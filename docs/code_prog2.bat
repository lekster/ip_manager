avrdude.exe -c usbasp -p m168 -U lfuse:w:0x62:m -U hfuse:w:0xDF:m
avrdude.exe -c usbasp -p m168 -U flash:w:C:\Docs\Micro\projects\ip_manager\default\ip_manager.hex:i  -v -v
avrdude.exe -c usbasp -p m168 -U lfuse:w:0xE2:m -U hfuse:w:0xDF:m
pause