CC = g++
CFLAGS  = -g -Wall

VDB: main.o VirusDB.o 
	$(CC) $(CFLAGS) -o virusDB main.o VirusDB.o

main.o:  main.cpp
	$(CC) $(CFLAGS) -c main.cpp

VirusDB.o: VirusDB.cpp VirusDB.h
	$(CC) $(CFLAGS) -c VirusDB.cpp

clean:
	$(RM) virusDB *.o *~
