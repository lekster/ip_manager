# makefile, written by guido socher
#
# Please select according to the type of board you are using:
#MCU=atmega88
#DUDECPUTYPE=m88
MCU=atmega168
DUDECPUTYPE=m168
#MCU=atmega328p
#DUDECPUTYPE=m328p
#MCU=atmega644
#DUDECPUTYPE=m644
#
# === Edit this and enter the correct device/com-port:
# linux (plug in the avrusb500 and type dmesg to see which device it is):
#LOADCMD=avrdude -P /dev/ttyUSB0

# mac (plug in the programer and use ls /dev/tty.usbserial* to get the name):
#LOADCMD=avrdude -P /dev/tty.usbserial-A9006MOb

# windows (check which com-port you get when you plugin the avrusb500):
#LOADCMD=avrdude -P COM4

# All operating systems: if you have set the default_serial paramter 
# in your avrdude.conf file correctly then you can just use this
# and you don't need the above -P option:
#LOADCMD=avrdude
# === end edit this
#
#LOADARG=-p $(DUDECPUTYPE) -c stk500v2 -e -U flash:w:

# If you have a tuxgraphics microcontroller mail account 
# then you can uncommet the following line to compile the
# email client. You will also need to edit test_emailnotify.c
# and add your account ID there.
#EMAIL=haveaccount
# 
#
CC=avr-gcc
OBJCOPY=avr-objcopy
# optimize for size:
CFLAGS=-g -mmcu=$(MCU) -Wall -W -Os -mcall-prologues
#-------------------
.PHONY: all main
#
all: eth_rem_dev_tcp.hex
#
eth_rem_dev_tcp: eth_rem_dev_tcp.hex
	@echo "done"
#
main: eth_rem_dev_tcp.hex
	@echo "done"
#
#-------------------
eth_rem_dev_tcp.hex: eth_rem_dev_tcp.elf 
	$(OBJCOPY) -R .eeprom -O ihex eth_rem_dev_tcp.elf eth_rem_dev_tcp.hex 
	avr-size eth_rem_dev_tcp.elf
	@echo " "
	@echo "Expl.: data=initialized data, bss=uninitialized data, text=code"
	@echo " "

eth_rem_dev_tcp.elf: main.o ip_arp_udp_tcp.o enc28j60.o websrv_help_functions.o
	$(CC) $(CFLAGS) -o eth_rem_dev_tcp.elf -Wl,-Map,eth_rem_dev_tcp.map main.o ip_arp_udp_tcp.o enc28j60.o websrv_help_functions.o
websrv_help_functions.o: websrv_help_functions.c websrv_help_functions.h ip_config.h 
	$(CC) $(CFLAGS) -Os -c websrv_help_functions.c
enc28j60.o: enc28j60.c timeout.h enc28j60.h
	$(CC) $(CFLAGS) -Os -c enc28j60.c
ip_arp_udp_tcp.o: ip_arp_udp_tcp.c net.h enc28j60.h ip_config.h
	$(CC) $(CFLAGS) -Os -c ip_arp_udp_tcp.c
main.o: main.c ip_arp_udp_tcp.h enc28j60.h timeout.h net.h websrv_help_functions.h ip_config.h
	$(CC) $(CFLAGS) -Os -c main.c

#-------------------
clean:
	rm -f *.o *.map *.elf test*.hex eth_rem_dev_tcp.hex basic_web_server_example.hex
#-------------------
