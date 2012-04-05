CC = g++
CFLAG = -Wall
OPENSSL = -lssl -lm -lcrypto
SERVER = ./src/server.cpp
OUT_SERVER = ./bin/server
CLIENT = ./src/client.cpp
OUT_CLIENT = ./bin/client

all: server client

server : $(SERVER)
	$(CC) $(CFLAG) -I ./src $(SERVER) -o $(OUT_SERVER) $(OPENSSL)

client : $(CLIENT)
	$(CC) $(CFLAG) -I ./src $(CLIENT) -o $(OUT_CLIENT) $(OPENSSL)

clean : 
	rm -rf $(OUT_SERVER)
	rm -rf $(OUT_CLIENT)
	rm -f *.o core
	rm -f ./bin/*.o core	
	rm -f ./log/*
