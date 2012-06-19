/********************************************
 * Author: Guido Socher (TCP/IP stack), Andrey_B (http://www.ab-log.ru)
 * Copyright: GPL V2
 * See http://www.gnu.org/licenses/gpl.html
 *
 * Ethernet remote device and sensor
 * UDP and HTTP interface 
 *
 * Chip type: Atmega88 or Atmega168 or Atmega328 with ENC28J60
 * Current chip type: Atmega168
 *********************************************/
#include <avr/io.h>
#include <string.h>
#include <stdlib.h>
#include "websrv_help_functions.h"
#include "ip_arp_udp_tcp.h"
#include "enc28j60.h"
#include "timeout.h"

// For sprintf_P
#include <stdio.h>
// For EEPROM
#include <avr/eeprom.h> 
// For Debouncing
#include <avr/interrupt.h>


// Default MAC address
//static uint8_t mymac[6] = {0x54,0x55,0x58,0x10,0x00,0x29};
uint8_t mymac[6] = {0x54,0x55,0xc1,0xa8,0x00,0x0e};
// Default IP address
uint8_t myip[4] = {192,168,1,44};
// Default HTTP port
#define HTTPPORT 80
// the password string (only the first 5 char checked), (only a-z,0-9,_ characters):
static char password[]="sec"; // must not be longer than 9 char

// EEPROM 
// EEMEM IP address
uint8_t EEMEM ee_ip_addr[4];
// IP address
uint8_t _ip_addr[4];
// EEMEM server IP address
uint8_t EEMEM ee_sip_addr[4];
// server IP address
uint8_t _sip_addr[4];
// EEMEM Input port cmd
uint8_t EEMEM ee_cmd[13][11];
// EEMEM Input port cmd
uint8_t EEMEM ee_eth_cmd[13][25];

// Available IO
#define IO_SIZE 13
char *aio[IO_SIZE] = {"D0", "D1", "D3", "D4", "D5", "D6", "D7", "C0", "C1", "C2", "C3", "C4", "C5"};

// Initializing buffer for HTTP
#define BUFFER_SIZE 520
static uint8_t buf[BUFFER_SIZE+1];
// Buffer for URL parameters
static char gStrbuf[25];

// EEPROM
//Port type
uint8_t EEMEM ee_port_type[IO_SIZE];
static uint8_t _port_type[IO_SIZE];

//Port default state
uint8_t EEMEM ee_port_d[IO_SIZE];
static uint8_t _port_d[IO_SIZE];

// Service
char temp[25];
uint8_t i;
// Reset flag
uint8_t reset_flag = 0;
static uint8_t cur_input;
// Управление таймаутами ответа сервера по каждому порту
static uint16_t srv_timeout[IO_SIZE];
static uint8_t srv_timeout_act[IO_SIZE];
// If is_set gateway IP
static uint8_t gw_set = 0;
// Невозможно открыть две TCP-сессии. Флаги для управления очередностью сессий
// В этом флаге сохраняется номер сработавшего входа
static int8_t send_eth_flag = -1;
// Этот флаг устанавливается, когда завершена TCP-сессия с основным сервером
static int8_t send_eth_flag2 = -1;

// Debouncing
char input_state;      //Debounced and inverted key state:
char input_press;      //Key Press Detected  
char input_state2;      //Debounced and inverted key state:
char input_press2;      //Key Press Detected  

// function for software reset of AVR
#define RESET() (((void(*)(void))(char *)0x0000)()) 

// set output to VCC, red LED off
#define LEDOFF PORTB|=(1<<PORTB1)
// set output to GND, red LED on
#define LEDON PORTB&=~(1<<PORTB1)
// to test the state of the LED
#define LEDISOFF PORTB&(1<<PORTB1)

uint16_t http200ok(void)
{
	return(fill_tcp_data_p(buf,0,PSTR("HTTP/1.0 200 OK\r\nContent-Type: text/html\r\nPragma: no-cache\r\n\r\n")));
}

uint8_t verify_password(char *str)
{
	// the first characters of the received string are
	// a simple password/cookie:
	if (strncmp(password,str,strlen(password))==0)
	return(1);
	return(0);
}

int8_t analyse_get_url(char *str)
{
	uint8_t loop=15;
	// the first slash:
	if ( *str == '/' )
	{ str++; }
	else
	{ return(-1); }

	if ( strncmp("favicon.ico", str, 11) == 0 )
	{ return(2); }
	// the password:
	if ( verify_password(str)==0)
	{ return(-1); }

        // move forward to the first space or '/'
	while(loop)
	{
		if(*str==' ')
		{
			// end of url and no slash after password:
			return(-2);
                }

		if(*str=='/')
		{
			// end of password
			loop=0;
			continue;
		}

		str++;
		loop--; // do not loop too long
	}

        return(-3);
}

static uint8_t decode_ip(char *in,uint8_t *out)
{
	//uint8_t i;
	//char tmp[20];
	strncpy(temp,in,sizeof(temp));
	char *dig;
	dig=strtok(temp,".");

	for(i=0 ; i<4 && dig ;i++,dig=strtok(NULL,"."))
	out[i]=(uint8_t)strtoul(dig,NULL,10);

	return i;
}

// Функция, которая осуществляет парсинг и выполнение команд
void port_execute(char *srv_cmd)
{
	char p_num[2] = "FF";
	uint8_t p_flag=0;
	char port_letter;
	int8_t port_num;

	for ( i = 0; i < strlen(srv_cmd); i++ )
	{
		if ( srv_cmd[i] == ':' )
		p_flag = 1;
		else if ( srv_cmd[i] == ';' )
		p_flag = 0;
		else
		{
			if ( p_flag == 0 )
			{
				if ( p_num[0] != 'F' )
				p_num[1] = srv_cmd[i];
				else
				p_num[0] = srv_cmd[i];
			}
			else if ( p_flag == 1 )
			{
				if ( p_num[1] == 'F' )
				p_num[1] = '\0';
				port_letter = aio[atoi(p_num)][0];
				port_num = atoi(&aio[atoi(p_num)][1]);

				if (_port_type[atoi(p_num)] == 1 )
				{
					// ON
					if ( srv_cmd[i] == '1' )
					{
						if ( port_letter == 'D' )
						PORTD|= (1<<port_num);
						else if ( port_letter == 'C' )
						PORTC|= (1<<port_num);
					}
					// OFF
					else if ( srv_cmd[i] == '0' )
					{
						if ( port_letter == 'D' )
						PORTD &= ~(1<<port_num);
						else if ( port_letter == 'C' )
						PORTC &= ~(1<<port_num);
					}
					// Toggle
					else if ( srv_cmd[i] == '2' )
					{
						if ( port_letter == 'D' )
						PORTD ^= (1<<port_num);
						else if ( port_letter == 'C' )
						PORTC ^= (1<<port_num);
					}
				}

				p_num[0] = 'F';
				p_num[1] = 'F';
			}
		}
	}

}

void browserresult_callback(uint8_t statuscode,uint16_t datapos, uint16_t len)
{
	uint16_t i=0;
	uint8_t j=0;
	uint8_t k=0;

	char * srv_rep;
	srv_rep = (char *)&(buf[datapos]);
	char srv_cmd[30];
	if (statuscode==0)
	{
		// Поскольку в этой функции у нас нет информации о том, какой именно вход сработал,
		// сбрасываем таймаут по всем входам, предполагая, что если сервер ответил по одному,
		// он ответит и по остальным.
		for ( i = 0; i < IO_SIZE; i++ )
		srv_timeout[i] = 0;

		for ( i = 0; i < len; i++ )
		{
			// Пропускаем все HTTP-заголовки
			if ( *srv_rep == '\r' || *srv_rep == '\n' )
			{
				srv_rep++;
				k++;
				continue;
			}

			if ( k == 4 )
			{
				srv_cmd[j] = *srv_rep;
				j++;
			}

			if ( k != 4 )
			k = 0;

			srv_rep++;
		}

		port_execute(srv_cmd);
	}
	// Если ответ сервера не 200, то выполняем команды по умолчанию
	else
	{
		eeprom_read_block (temp, &ee_cmd[cur_input], 11);
		if ( temp[0] != 'я' && strlen(temp) > 0 ) 
		port_execute(temp);

	}

	send_eth_flag2 = 1;
}

ISR(TIMER1_COMPA_vect)            //every 10ms
{
	static char ct0 = 0xFF, ct1 = 0xFF;  // 8 * 2bit counters
	char i;

	static char ct2 = 0xFF, ct3 = 0xFF;  // 8 * 2bit counters
	//char i;

	uint8_t j;

	// Проверка на установленный таймаут каждый порт
	for ( j = 0; j < IO_SIZE; j++ )
	{
		// Если есть таймаут, то используем счетчик
		if ( srv_timeout[j] > 0 )
		{
			srv_timeout[j]--;
			// Если счетчик дошел до конца, выставляем флаг - выполняем команду по умолчанию
			if ( srv_timeout[j] == 0 )
			srv_timeout_act[j] = 1;
		}
	}

	i = ~PIND;              // read keys (low active)
	i ^= input_state;            // key changed ?
	ct0 = ~(ct0 & i);            // reset or count ct0
	ct1 = ct0 ^ (ct1 & i);       // reset or count ct1
	i &= ct0 & ct1;              // count until roll over ?
	input_state ^= i;            // then toggle debounced state
	input_press |= input_state & i;   // 0->1: key press detect

	i = ~PINC;              // read keys (low active)
	i ^= input_state2;            // key changed ?
	ct2 = ~(ct2 & i);            // reset or count ct0
	ct3 = ct2 ^ (ct3 & i);       // reset or count ct1
	i &= ct2 & ct3;              // count until roll over ?
	input_state2 ^= i;            // then toggle debounced state
	input_press2 |= input_state2 & i;   // 0->1: key press detect


} 

char get_key_press( char input_mask )
{
	cli();
	input_mask &= input_press;                // read key(s)
	input_press ^= input_mask;                // clear key(s)
	sei();
	return input_mask;
}

char get_key_press2( char input_mask )
{
	cli();
	input_mask &= input_press2;                // read key(s)
	input_press2 ^= input_mask;                // clear key(s)
	sei();
	return input_mask;
}


int main(void)
{
	//char urlpar[10];

        uint16_t plen;
	uint16_t dat_p;
	int8_t cmd;

	uint8_t k;
	uint8_t _eth_addr[4];

	int8_t avr_port;
	int8_t avr_port_port;
	int8_t avr_port_pin;

	//char temp[25];

	char port_letter;
	int8_t port_num;

	//CLKPR=(1<<CLKPCE); // change enable
	//CLKPR=0; // "no pre-scaler"
	_delay_loop_1(0); // 60us

	// Reading EEPROM IP address
	eeprom_read_block ((void *)_ip_addr, (const void *)&ee_ip_addr,4);
	if ( _ip_addr[0] != 255 )
	{
		for ( i = 0; i < 4; i++ )
		{
			myip[i] = _ip_addr[i];
			mymac[i+2] = _ip_addr[i];
		}
	}

	/*initialize enc28j60*/
	enc28j60Init(mymac);
	enc28j60clkout(2); // change clkout from 6.25MHz to 12.5MHz
	_delay_loop_1(0); // 60us

	/* Magjack leds configuration, see enc28j60 datasheet, page 11 */
	// LEDB=yellow LEDA=green
	// 0x476 is PHLCON LEDA=links status, LEDB=receive/transmit
	enc28j60PhyWrite(PHLCON,0x476);

	eeprom_read_block (_port_type, &ee_port_type, IO_SIZE);
	eeprom_read_block (_port_d, &ee_port_d, IO_SIZE);

	DDRB|= (1<<DDB1); // enable PB1, LED as output 

	// Enable ADC
	// Set ADC prescalar
	ADCSRA |= (1 << ADPS2) | (1 << ADPS1);
	// Set ADC reference to AVCC 
	ADMUX |= (1 << REFS0);
	// Left adjust ADC result to allow easy 8 bit reading 
	//ADMUX |= (1 << ADLAR); 
	// Enable ADC 
	ADCSRA |= (1<<ADEN);
	// Start A2D Conversions 
	//ADCSRA |= (1<<ADSC);

	for ( i = 0; i < IO_SIZE; i++ )
	{
		port_letter = aio[i][0];
		port_num = atoi(&aio[i][1]);
		srv_timeout[i] = 0;
		srv_timeout_act[i] = 0;

		if (_port_type[i] == 1 )
		{
			if ( port_letter == 'D' )
			{
				DDRD |= (1<<port_num);
				if (_port_d[i] == 1 )
				PORTD|= (1<<port_num);
				else
				PORTD &= ~(1<<port_num);

			}
			if ( port_letter == 'C' )
			{
				DDRC |= (1<<port_num);
				if (_port_d[i] == 1 )
				PORTC|= (1<<port_num);
				else
				PORTD &= ~(1<<port_num);
			}

		}
		else
		{
			if ( port_letter == 'D' )
			DDRD &= ~(1<<port_num);
			if ( port_letter == 'C' )
			DDRC &= ~(1<<port_num);
		}

	}

	// Debouncing init
	TCCR1B |=   (1 << WGM12);         //Timer1 Mode 2: CTC
	TCCR1B |=   (1 << CS12);          //Divide by 256
	OCR1A    =   F_CPU / 512 * 10e-3; //Set CTC compare value to 10ms at 8MHz AVR clock, with a prescaler of 256
	TIMSK1 =   (1 << OCIE1A);         //Enable T1 interrupt
	input_state    = ~PIND;      //no action on keypress during reset
	sei();

	// Инициализируем сетевые настройки
	init_ip_arp_udp_tcp(mymac,myip,HTTPPORT);

	// Reading Server IP address
	eeprom_read_block ((void *)_sip_addr, (const void *)&ee_sip_addr,4);

	if ( _sip_addr[0] != 255 )
	{
	        client_set_gwip(_sip_addr);
		client_set_wwwip(_sip_addr);
		gw_set = 1;
		client_browse_url(PSTR("/test-http.php"),"","",0);
	}

	LEDOFF;

	while(1)
	{
		plen=enc28j60PacketReceive(BUFFER_SIZE, buf);
		buf[BUFFER_SIZE]='\0';
		dat_p=packetloop_icmp_tcp(buf,plen);

		// Отправка информации по доп. URL. Только в том случае, если завершена TCP-сессия с основным сервером. (ограничения tuxgraphics TCP/IP)
		// Проблема. Если в момент таймаута сработал еще один вход, то отработает последний сработавший. Массив и очередь?
		if ( send_eth_flag2 > -1 )
		{
			eeprom_read_block (temp, &ee_eth_cmd[send_eth_flag], 25);
			if ( temp[0] != 'я' && strlen(temp) > 0 ) 
			{
				char ip_b[3];
				char urlpar[10];
				uint8_t ip_flag = 0;
				uint8_t ip_cnt = 0;
				uint8_t url_cnt = 0;

				for ( k = 0; k < strlen(temp); k++ )
				{
					if ( ip_flag < 4 )
					{
						if ( temp[k] == '.' || temp[k] == '/' )
						{
							ip_cnt = 0;
							_eth_addr[ip_flag] = atoi(ip_b);
							ip_flag++;
							ip_b[0] = '\0';
							ip_b[1] = '\0';
							ip_b[2] = '\0';
						}
						else
						{
							ip_b[ip_cnt] = temp[k];
							ip_cnt++;
						}
					}
					else
					{
						urlpar[url_cnt] = temp[k];
						url_cnt++;
					}
				}

				urlpar[url_cnt] = '\0';

				if ( gw_set == 0 || send_eth_flag2 == 2 )
				{
				        client_set_gwip(_eth_addr);
					gw_set = 1;
				}

				client_set_wwwip(_eth_addr);
				client_browse_url(PSTR("/"),urlpar,"",0);

			}

			send_eth_flag = -1;
			send_eth_flag2 = -1;
		}


		// Проверка состояния входов
		for ( i = 0; i < IO_SIZE; i++ )
		{
			port_letter = aio[i][0];
			port_num = atoi(&aio[i][1]);
			cur_input = i;

			// Если это вход...
			if (_port_type[i] == 0 )
			{
				// Таймаут завершен, выполняем команды по умолчанию
				if ( srv_timeout_act[i] == 1 )
				{
					srv_timeout_act[i] = 0;
					eeprom_read_block (temp, &ee_cmd[i], 11);
					if ( temp[0] != 'я' && strlen(temp) > 0 ) 
					port_execute(temp);
					// Если с текущим входом связан доп. адрес, ставим флаг для проверки записанного в EEPROM URL
					// Значение 2 - нужно переопределить default gateway, поскольку основной сервер не отвечает
					send_eth_flag2 = 2;
				}

				// Обработка нажатия кнопки.
				char my_mask;
				if (port_letter == 'D')
				my_mask = get_key_press(1 << port_num);
				else
				my_mask = get_key_press2(1 << port_num);
				if(my_mask)
				{
					PORTB ^= (1 << PB1);
					// Если прописан основной сервер
					if ( _sip_addr[0] != 255 )
					{
						client_set_wwwip(_sip_addr);
						char pnum[3];
						itoa(i, pnum, 10);
						client_browse_url(PSTR("/test-http.php?pt="),pnum,"",&browserresult_callback);
						srv_timeout[cur_input] = 600;
					}
					// Если сервер не прописан
					else if ( _sip_addr[0] == 255 )
					{
						// Если с текущим входом связан доп. адрес, ставим флаг для проверки записанного в EEPROM URL
						send_eth_flag2 = 1;
						eeprom_read_block (temp, &ee_cmd[i], 11);
						// Выполняем команды, если в EEPROM есть реальная информация
						if ( temp[0] != 'я' && strlen(temp) > 0 ) 
						port_execute(temp);
					}

					send_eth_flag = cur_input;

				}
			}
		}


                if(dat_p==0)
		{
                        // check if udp otherwise continue
                        goto UDP;
		}

		if (strncmp("/ ",(char *)&(buf[dat_p+4]),2)==0){
			plen=http200ok();
			plen=fill_tcp_data_p(buf,plen,PSTR("<p>Usage: http://host_or_ip/password</p>\n"));
			goto SENDTCP;
		}

		cmd=analyse_get_url((char *)&(buf[dat_p+4]));

		if (cmd==-1)
		{
			plen=fill_tcp_data_p(buf,0,PSTR("HTTP/1.0 401 Unauthorized\r\nContent-Type: text/html\r\n\r\n<h1>401 Unauthorized</h1>"));
			goto SENDTCP;
		}

		// Режим работы
		uint8_t mode = 0;
		// Команда
		char srv_cmd[30];
		if (find_key_val((char *)&(buf[dat_p+4]),srv_cmd,30,"cmd"))
		{
			if ( strcmp(srv_cmd, "get") == 0 )
			mode = 1;
			if ( strlen(srv_cmd) > 0 )
			port_execute(srv_cmd);
		}

		//if (find_key_val((char *)&(buf[dat_p+4]),gStrbuf,3,"get"))
		//mode = 1;

		if (find_key_val((char *)&(buf[dat_p+4]),gStrbuf,25,"pt"))
		{
		        plen=http200ok();
			eeprom_read_block (_port_type, &ee_port_type, IO_SIZE);

			//char temp[2];
			//snprintf_P(temp,sizeof(temp),PSTR("%d"),_port_type[atoi(gStrbuf)]);
			//plen=fill_tcp_data(buf,plen, temp);

			port_letter = aio[atoi(gStrbuf)][0];
			port_num = atoi(&aio[atoi(gStrbuf)][1]);
		
			if ( port_letter == 'D' )
			{
				avr_port = DDRD;
				avr_port_port = PORTD;
				avr_port_pin = PIND;
			}
			else if ( port_letter == 'C' )
			{
				avr_port = DDRC;
				avr_port_port = PORTC;
				avr_port_pin = PINC;
			}

			//plen=fill_tcp_data_p(buf,plen,PSTR("<br>"));

			if ( mode == 0 )
			{
				plen=fill_tcp_data_p(buf,plen,PSTR("<a href=/"));
				plen=fill_tcp_data(buf,plen,password);
				plen=fill_tcp_data_p(buf,plen,PSTR(">Back</a><br>"));

				//plen=fill_tcp_data_p(buf,plen,PSTR("Port "));
				plen=fill_tcp_data(buf,plen,aio[atoi(gStrbuf)]);
			}

			// Если порт уже сконфигурирован
			if ( _port_type[atoi(gStrbuf)] != 255 )
			{
				if ( mode == 0 )
				plen=fill_tcp_data_p(buf,plen,PSTR("/"));
				//plen=fill_tcp_data_p(buf,plen,PSTR("<br>State "));

				// Если порт является АЦП
				if ( _port_type[atoi(gStrbuf)] == 2 )
				{
					ADMUX = (1 << REFS0) + port_num; 
					//ADMUX |= (1 << ADLAR); 
					ADCSRA|=(1<<ADSC);
					while (bit_is_set(ADCSRA, ADSC))
					;
					//_delay_loop_1(0); // 60us
					//_delay_loop_1(0); // 60us
					uint16_t my_val;
					uint8_t my_val_low;
					my_val_low = ADCL;
					my_val = (ADCH<<8)|my_val_low;
					//snprintf_P(temp,sizeof(temp),PSTR("%d"),my_val);
					itoa (my_val, temp, 10);
					plen=fill_tcp_data(buf,plen, temp);
				}
				// Если порт является выходом
				else if ( bit_is_set(avr_port, port_num) )
				{
					//port_execute(srv_cmd);

					if ( bit_is_set(avr_port_port, port_num) )
					plen=fill_tcp_data_p(buf,plen,PSTR("ON"));
					else
					plen=fill_tcp_data_p(buf,plen,PSTR("OFF"));

					if ( mode == 0 )
					{
						plen=fill_tcp_data_p(buf,plen,PSTR("<br>"));

						plen=fill_tcp_data_p(buf,plen,PSTR("<a href=/"));
						plen=fill_tcp_data(buf,plen,password);
						plen=fill_tcp_data_p(buf,plen,PSTR("/?pt="));
						plen=fill_tcp_data(buf,plen,gStrbuf);
						plen=fill_tcp_data_p(buf,plen,PSTR("&cmd="));
						plen=fill_tcp_data(buf,plen,gStrbuf);
						plen=fill_tcp_data_p(buf,plen,PSTR(":1>ON</a> "));

						plen=fill_tcp_data_p(buf,plen,PSTR("<a href=/"));
						plen=fill_tcp_data(buf,plen,password);
						plen=fill_tcp_data_p(buf,plen,PSTR("/?pt="));
						plen=fill_tcp_data(buf,plen,gStrbuf);
						plen=fill_tcp_data_p(buf,plen,PSTR("&cmd="));
						plen=fill_tcp_data(buf,plen,gStrbuf);
						plen=fill_tcp_data_p(buf,plen,PSTR(":0>OFF</a>"));
					}
				}
				// Если порт является входом
				else
				{
					if ( bit_is_clear(avr_port_pin, port_num) )
					plen=fill_tcp_data_p(buf,plen,PSTR("ON"));
					else
					plen=fill_tcp_data_p(buf,plen,PSTR("OFF"));
				}
			}

			if ( mode == 0 )
			{
				plen=fill_tcp_data_p(buf,plen,PSTR("<br><form action=/"));
				plen=fill_tcp_data(buf,plen,password);
				plen=fill_tcp_data_p(buf,plen,PSTR("/>"));
				plen=fill_tcp_data_p(buf,plen,PSTR("<input type=hidden name=pn value="));
				plen=fill_tcp_data(buf,plen,gStrbuf);
				plen=fill_tcp_data_p(buf,plen,PSTR(">"));

				plen=fill_tcp_data_p(buf,plen,PSTR("<select name=pty>"));

				/*
				char *p_type[3] = {"In", "Out", "ADC"};

				if ( _port_type[atoi(gStrbuf)] == 255 )
				plen=fill_tcp_data_p(buf,plen,PSTR("<option selected>NC</option>"));
				else
				plen=fill_tcp_data_p(buf,plen,PSTR("<option>NC</option>"));

				for ( k = 0; k < 3; k++ )
				{
					if ( _port_type[atoi(gStrbuf)] == k )
					plen=fill_tcp_data(buf,plen,"<option selected>");
					else
					plen=fill_tcp_data(buf,plen,"<option>");
					plen=fill_tcp_data(buf,plen,p_type[k]);
					plen=fill_tcp_data(buf,plen,"</option>");
        			}
				*/
			
				if ( _port_type[atoi(gStrbuf)] == 255 )
				plen=fill_tcp_data_p(buf,plen,PSTR("<option selected value=255>NC</option><option value=0>In</option><option value=1>Out</option>"));
				else if ( bit_is_set(avr_port, port_num) && _port_type[atoi(gStrbuf)] == 1 )
				plen=fill_tcp_data_p(buf,plen,PSTR("<option value=255>NC</option><option value=0>In</option><option value=1 selected>Out</option>"));
				else if ( bit_is_clear(avr_port, port_num) && _port_type[atoi(gStrbuf)] == 0 )
				plen=fill_tcp_data_p(buf,plen,PSTR("<option value=255>NC</option><option value=0 selected>In</option><option value=1>Out</option>"));
				else
				plen=fill_tcp_data_p(buf,plen,PSTR("<option value=255>NC</option><option value=0>In</option><option value=1>Out</option>"));

				if ( port_letter == 'C' )
				{
					if ( _port_type[atoi(gStrbuf)] == 2 )
					plen=fill_tcp_data_p(buf,plen,PSTR("<option value=2 selected>ADC</option>"));
					else
					plen=fill_tcp_data_p(buf,plen,PSTR("<option value=2>ADC</option>"));
				}

				plen=fill_tcp_data_p(buf,plen,PSTR("</select>"));

				if ( bit_is_clear(avr_port, port_num) && _port_type[atoi(gStrbuf)] == 0 )
				{
					plen=fill_tcp_data_p(buf,plen,PSTR("<br>Cmd <input type=text name=ecmd value=\""));
					eeprom_read_block (temp, &ee_cmd[atoi(gStrbuf)], 11);
					if ( temp[0] != 'я' && strlen(temp) > 0 ) 
					plen=fill_tcp_data(buf,plen, temp);
					plen=fill_tcp_data_p(buf,plen,PSTR("\"><br>"));

					plen=fill_tcp_data_p(buf,plen,PSTR("Eth <input type=text name=eth value=\""));
					eeprom_read_block (temp, &ee_eth_cmd[atoi(gStrbuf)], 25);
					if ( temp[0] != 'я' && strlen(temp) > 0 ) 
					plen=fill_tcp_data(buf,plen, temp);
					plen=fill_tcp_data_p(buf,plen,PSTR("\">"));

				}
				else if ( bit_is_set(avr_port, port_num) && _port_type[atoi(gStrbuf)] == 1 )
				{
					plen=fill_tcp_data_p(buf,plen,PSTR("<select name=d>"));
					if (_port_d[atoi(gStrbuf)] == 1 )
					plen=fill_tcp_data_p(buf,plen,PSTR("<option value=0>0</option><option selected value=1>1</option>"));
					else
					plen=fill_tcp_data_p(buf,plen,PSTR("<option selected value=0>0</option><option value=1>1</option>"));
					plen=fill_tcp_data_p(buf,plen,PSTR("</select>"));
				}
	
				plen=fill_tcp_data_p(buf,plen,PSTR("<br><input type=submit value=ok></form>"));
			}

		}
		else if (find_key_val((char *)&(buf[dat_p+4]),gStrbuf,25,"pn"))
		{
			if (find_key_val((char *)&(buf[dat_p+4]),temp,25,"pty"))
			{
				if ( strcmp(temp,"NC") )
				{
					_port_type[atoi(gStrbuf)] = atoi(temp);
					eeprom_write_block (&_port_type[atoi(gStrbuf)], &ee_port_type[atoi(gStrbuf)], 1);
					reset_flag = 1;
				}
			}

			if (find_key_val((char *)&(buf[dat_p+4]),temp,25,"ecmd"))
			{
				if ( strlen(temp) > 0 )
				{
					urldecode(temp);
					eeprom_write_block (&temp, &ee_cmd[atoi(gStrbuf)], 11);
					reset_flag = 1;
				}
			}

			if (find_key_val((char *)&(buf[dat_p+4]),temp,25,"eth"))
			{
				if ( strlen(temp) > 0 )
				{
					urldecode(temp);
					eeprom_write_block (&temp, &ee_eth_cmd[atoi(gStrbuf)], 25);
					reset_flag = 1;
				}
			}

			if (find_key_val((char *)&(buf[dat_p+4]),temp,25,"d"))
			{
				_port_d[atoi(gStrbuf)] = atoi(temp);
				eeprom_write_block (&_port_d[atoi(gStrbuf)], &ee_port_d[atoi(gStrbuf)], 1);
			}

			if ( reset_flag == 1 )
			{
			        plen=http200ok();
				//plen=fill_tcp_data_p(buf,plen,PSTR("OK"));
				plen=fill_tcp_data_p(buf,plen,PSTR("<a href=/"));
				plen=fill_tcp_data(buf,plen,password);
				plen=fill_tcp_data_p(buf,plen,PSTR("/>Back</a>"));

			}

		}
		else if (find_key_val((char *)&(buf[dat_p+4]),gStrbuf,25,"cf"))
		{
			if ( gStrbuf[0] == '1' )
			{
				if (find_key_val((char *)&(buf[dat_p+4]),gStrbuf,25,"eip"))
				{
					decode_ip(gStrbuf, _ip_addr);
					eeprom_write_block (_ip_addr, &ee_ip_addr, 4);
					reset_flag = 1;
				}

				if (find_key_val((char *)&(buf[dat_p+4]),gStrbuf,25,"sip"))
				{
					decode_ip(gStrbuf, _sip_addr);
					eeprom_write_block (_sip_addr, &ee_sip_addr, 4);
					reset_flag = 1;
				}

			        plen=http200ok();

				eeprom_read_block ((void *)_ip_addr, (const void *)&ee_ip_addr,4);
				eeprom_read_block ((void *)_sip_addr, (const void *)&ee_sip_addr,4);

				if ( _ip_addr[0] == 255 )
				{
					for ( i = 0; i < 4; i++ )
					_ip_addr[i] = myip[i];
				}

				plen=fill_tcp_data_p(buf,plen,PSTR("<a href=/"));
				plen=fill_tcp_data(buf,plen,password);
				plen=fill_tcp_data_p(buf,plen,PSTR(">Back</a><br>"));

				plen=fill_tcp_data_p(buf,plen,PSTR("<form action=/"));
				plen=fill_tcp_data(buf,plen,password);
				plen=fill_tcp_data_p(buf,plen,PSTR("/>"));
				plen=fill_tcp_data_p(buf,plen,PSTR("<input type=hidden name=cf value=1>"));

				plen=fill_tcp_data_p(buf,plen,PSTR("IP: <input type=text name=eip value="));
				snprintf_P(temp,sizeof(temp),PSTR("%d.%d.%d.%d"),(int)_ip_addr[0],(int)_ip_addr[1],(int)_ip_addr[2],(int)_ip_addr[3]);
				plen=fill_tcp_data(buf,plen, temp);
				plen=fill_tcp_data_p(buf,plen,PSTR("><br>"));

				plen=fill_tcp_data_p(buf,plen,PSTR("Server: <input type=text name=sip value="));
				snprintf_P(temp,sizeof(temp),PSTR("%d.%d.%d.%d"),(int)_sip_addr[0],(int)_sip_addr[1],(int)_sip_addr[2],(int)_sip_addr[3]);
				plen=fill_tcp_data(buf,plen, temp);
				plen=fill_tcp_data_p(buf,plen,PSTR(">"));

				plen=fill_tcp_data_p(buf,plen,PSTR("<br><input type=submit value=Save></form>"));

				// ======================================================
				//client_browse_url(PSTR("/test-http.php"),"","",&browserresult_callback);


			}

		}
		else
		{
		        plen=http200ok();

			plen=fill_tcp_data_p(buf,plen,PSTR("<a href=/"));
			plen=fill_tcp_data(buf,plen,password);
			plen=fill_tcp_data_p(buf,plen,PSTR("/?cf=1>Conf</a><br>"));

			for ( i = 0; i < IO_SIZE; i++ )
			{
				plen=fill_tcp_data_p(buf,plen,PSTR("<a href=/"));
				plen=fill_tcp_data(buf,plen,password);
				plen=fill_tcp_data_p(buf,plen,PSTR("/?pt="));

				//char temp[2];

				snprintf_P(temp,sizeof(temp),PSTR("%d"),i);
				plen=fill_tcp_data(buf,plen, temp);

				plen=fill_tcp_data_p(buf,plen,PSTR(">"));
				plen=fill_tcp_data(buf,plen,aio[i]);
				plen=fill_tcp_data_p(buf,plen,PSTR("</a> "));
			}

			// ! ! !
			//plen=fill_tcp_data_p(buf,plen,PSTR("<br>"));
			//itoa(srv_fd, temp, 10);
			// plen=fill_tcp_data(buf,plen,urlpar);

		}
		
		SENDTCP:
                www_server_reply(buf,plen); // send data

		if ( reset_flag == 1 )
		RESET();

                continue;

		UDP:
                continue;
	}

        return (0);
}
