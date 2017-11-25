CC=g++
CFLAGS=-g -Wall
INC= types.h Virus.h Disinfect.h
OBJ=disinfect_tester.o Virus.o Disinfect.o
TAR=disinfect_driver

disinfect_driver: $(OBJ) Virus.h Disinfect.h types.h
	$(CC) $(CFLAGS) $(OBJ) -o $(TAR)

disinfect_tester.o: disinfect_tester.cpp Virus.h Disinfect.h
	$(CC) $(CFLAGS) -c disinfect_tester.cpp

Virus.o: Virus.cpp Virus.h types.h
	$(CC) $(CFLAGS) -c Virus.cpp

Disinfect.o: Disinfect.cpp Disinfect.h Virus.h types.h
	$(CC) $(CFLAGS) -c Disinfect.cpp

clean:
	$(RM) $(TAR) *.o