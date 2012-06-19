# makefile, written by guido socher
MCU=atmega168
CC=avr-gcc
OBJCOPY=avr-objcopy
# optimize for size:
CFLAGS=-g -mmcu=$(MCU) -Wall -Wstrict-prototypes -Os -mcall-prologues
#-------------------
all: eth_rem_dev.hex test0.hex test1.hex test2.hex
#-------------------
help: 
	@echo "Usage: make all|test0|test1|test2|load|load_test0|load_test1|load_test2|rdfuses"
	@echo "or"
	@echo "Usage: make clean"
#-------------------
eth_rem_dev.hex : eth_rem_dev.out 
	$(OBJCOPY) -R .eeprom -O ihex eth_rem_dev.out eth_rem_dev.hex 
	avr-size eth_rem_dev.out
	@echo " "
	@echo "Expl.: data=initialized data, bss=uninitialized data, text=code"
	@echo " "

eth_rem_dev.out : main.o ip_arp_udp.o enc28j60.o timeout.o
	$(CC) $(CFLAGS) -o eth_rem_dev.out -Wl,-Map,eth_rem_dev.map main.o ip_arp_udp.o enc28j60.o timeout.o
enc28j60.o : enc28j60.c avr_compat.h timeout.h enc28j60.h
	$(CC) $(CFLAGS) -Os -c enc28j60.c
ip_arp_udp.o : ip_arp_udp.c net.h avr_compat.h enc28j60.h
	$(CC) $(CFLAGS) -Os -c ip_arp_udp.c
main.o : main.c ip_arp_udp.h avr_compat.h enc28j60.h timeout.h net.h
	$(CC) $(CFLAGS) -Os -c main.c
timeout.o : timeout.c timeout.h 
	$(CC) $(CFLAGS) -Os -c timeout.c
#------------------
test0.hex : test0.out 
	$(OBJCOPY) -R .eeprom -O ihex test0.out test0.hex 
	avr-size test0.out
	@echo " "
	@echo "Expl.: data=initialized data, bss=uninitialized data, text=code"
	@echo " "
test0.out : test0.o 
	$(CC) $(CFLAGS) -o test0.out -Wl,-Map,test0.map test0.o 
test0.o : test0.c 
	$(CC) $(CFLAGS) -Os -c test0.c
#------------------
test2.hex : test2.out 
	$(OBJCOPY) -R .eeprom -O ihex test2.out test2.hex 
	avr-size test2.out
	@echo " "
	@echo "Expl.: data=initialized data, bss=uninitialized data, text=code"
	@echo " "
test2.out : test2.o enc28j60.o timeout.o ip_arp_udp.o
	$(CC) $(CFLAGS) -o test2.out -Wl,-Map,test2.map test2.o enc28j60.o timeout.o ip_arp_udp.o
test2.o : test2.c ip_arp_udp.h avr_compat.h enc28j60.h timeout.h net.h
	$(CC) $(CFLAGS) -Os -c test2.c
#------------------
test1.hex : test1.out 
	$(OBJCOPY) -R .eeprom -O ihex test1.out test1.hex 
	avr-size test1.out
	@echo " "
	@echo "Expl.: data=initialized data, bss=uninitialized data, text=code"
	@echo " "
test1.out : test1.o enc28j60.o timeout.o ip_arp_udp.o
	$(CC) $(CFLAGS) -o test1.out -Wl,-Map,test1.map test1.o enc28j60.o timeout.o ip_arp_udp.o
test1.o : test1.c ip_arp_udp.h avr_compat.h enc28j60.h timeout.h net.h
	$(CC) $(CFLAGS) -Os -c test1.c
#------------------
load_test2: test2.hex
	./prg_load_uc_88 test2.hex
load_test1: test1.hex
	./prg_load_uc_88 test1.hex
load_test0: test0.hex
	./prg_load_uc_88 test0.hex
#------------------
load: eth_rem_dev.hex
	./prg_load_uc_88 eth_rem_dev.hex
#
loaduisp: eth_rem_dev.hex
	./prg_load_uc_88 -u eth_rem.hex
#-------------------
# Check this with make rdfuses
rdfuses:
	./prg_fusebit_uc_88 -r
#-------------------
clean:
	rm -f *.o *.map *.out test*.hex eth_rem_dev.hex
#-------------------
