#include <iostream>
#include <fstream>
#include <cstring> 
#include <stdlib.h> 
#include <sys/socket.h>
#include <netinet/in.h> 
#include <arpa/inet.h> 
#include <strings.h> 
#include <pthread.h>
#include <math.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/blowfish.h>

/* Path della chiave privata associata alla chiave pubblica */
#define PRI_KEY "../certification/pri_key.pem"

/* Numero massimo di richieste di connessione che si possono accodare */
#define BACKLOG 5 

using namespace std;

/* Indirizzo IP del server */
char *SERVER_IP_ADD;
	
/* Porta associata all'indirizzo IP del server */
int SERVER_PORT;

/* Password condivisa con il client */
char *SERVER_PWD;

/* Identificatore del server */
char SERVER;

/* Identificatore del client */
char CLIENT;

/* Nounce utilizzato nei messaggi */
int NOUNCE; 

/* Struttura memoria server - informazioni client associato*/
struct cl_info {
	char id;
	char *password;
};

/* Strutture dei messaggi in chiaro */
struct msg1 {
	char client;
	char server;
};

struct msg2 {
	char client;
	char server;
	int nounce;
};


