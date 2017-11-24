CC = g++
CFLAGS  = -g -Wall
INC = includes.h

VDB: main.o VirusDB.o WuManber.o includes.h
	$(CC) $(CFLAGS) -o virusDB main.o VirusDB.o WuManber.o

main.o:  main.cpp $(INC)
	$(CC) $(CFLAGS) -c main.cpp

VirusDB.o: VirusDB.cpp VirusDB.h $(INC)
	$(CC) $(CFLAGS) -c VirusDB.cpp

WuManber.o: WuManber.cpp WuManber.h $(INC)
	$(CC) $(CFLAGS) -c WuManber.cpp

clean:
	$(RM) virusDB *.o *~
