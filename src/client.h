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

/* Path della chiave pubblica */
#define PUB_KEY "../certification/pub_key.pem"

/* Path del file di testo */
#define TEST "../test/text.txt"

/* Lunghezza massima di ogni riga del file di test */
#define MAX_LINE_LEN 1024 

/* Grandezza massima del file di test */
#define MAX_FILE_LEN 1024 

/* Numero massimo di richieste di connessione che si possono accodare */
#define BACKLOG 5 

using namespace std;

/* Indirizzo IP del server */
char *SERVER_IP_ADD;
	
/* Porta associata all'indirizzo IP del server */
int SERVER_PORT;

/* Password condivisa con il server */
char *CLIENT_PWD;

/* Identificatore del server */
char SERVER;

/* Identificatore del client */
char CLIENT;

/* Nounce utilizzato nei messaggi */
int NOUNCE;

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



