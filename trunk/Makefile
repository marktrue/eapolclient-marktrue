CC = gcc
LIBS = /usr/local/lib/libpcap.a
CFLAGS = -Wall -g 
BIN = ../bin
OBJ = ../obj

.PHONY: all
all: exp802

exp802	: md5.o main.o
	$(CC) $(CFLAGS) -o $(BIN)/exp802 $(OBJ)/md5.o $(OBJ)/main.o $(LIBS)

md5.o	: md5.c md5.h
	$(CC) $(CFLAGS) -o $(OBJ)/$@ -c $< 

main.o	: main.c exp802.h
	$(CC) $(CFLAGS) -o $(OBJ)/$@ -c $<
	
clean :
	rm -v $(OBJ)/*.o $(BIN)/exp802 
