#include "server.h"

int main(int argc, char *argv[])
{
	/* Variabili e strutture standard per la gestione della connessione */
	int ret;
	int sv_sk;
	int sv_sk_act;
	int sv_ret;
	socklen_t addrlen;
	struct sockaddr_in my_addr;
	struct sockaddr_in cl_addr;
	
	/* Passare oltre a indirizzo IP e porta (del server) anche la password condivisa con il client */
	if(argc != 4) {
		cerr << "Errore: sintassi del comando errata" << endl;
		cout << "Digitare: ./server <indirizzo_IP> <porta> <password_condivisa>" << endl;
		exit(1);
	}	
	
	SERVER_IP_ADD = argv[1];
	SERVER_PORT = atoi(argv[2]);
	SERVER_PWD = argv[3];

	cout << endl;
	cout << "********* INIZIO FASE DI CONNESSIONE ********" << endl;

	/* Setto l'identificatore del server */
	SERVER = 'S';

	int np = strlen(SERVER_PWD); //Numero di caratteri che compongono la password

	if(np < 8) {
		cerr << "Errore: inserire una password di almeno 8 caratteri alfanumerici e/o caratteri speciali" << endl;	
		exit(1);
	}	

	if(SERVER_PORT <= 1023) {
		cerr << "Porta <" << SERVER_PORT << "> non utilizzabile :: Well Known Port" << endl;
		return -1;
	}

	if(SERVER_PORT <= 65535 && SERVER_PORT >= 49152)
		cout << "Fare attenzione nella scelta della porta <" << SERVER_PORT << "> :: Dynamic and/or Private Port" << endl;

	/* Creazione del socket lato server */	
	sv_sk = socket(AF_INET, SOCK_STREAM, 0);
	if(sv_sk == -1) {
    		cerr << "Errore: funzione <socket> non eseguita correttamente sul server" << endl;
    		exit(0);
	}

	/* Valore standard usato nella <setsockopt> */
	const int on = 1; 

	/* 
	Opzione <SO_REUSEADDR>: fa il restart del server se si effettua una bind su una certa porta
	quando sono presenti delle connnessioni established che usano la suddetta porta 
	*/
	sv_ret = setsockopt(sv_sk, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	if(sv_ret == -1) {
    		cerr << "Errore: impossibile settare l'opzione <SO_REUSEADDR> sul server" << endl;
    		exit(0);
  	}

	/* Inizializzazione struttura dati */
	bzero(&my_addr, sizeof(struct sockaddr_in)); /* Azzera il contenuto della struttura */
	my_addr.sin_family = AF_INET;
	my_addr.sin_port = htons(SERVER_PORT);
	inet_pton(AF_INET, SERVER_IP_ADD, &my_addr.sin_addr.s_addr); /* Converte l'indirizzo da stringa a valore numerico */

	sv_ret = bind(sv_sk, (struct sockaddr *)(&my_addr), sizeof(my_addr));
	if(sv_ret == -1) {
    		cerr << "Errore: funzione <bind> non eseguita correttamente sul server" << endl;
    		exit(0);
	}

	sv_ret = listen(sv_sk, BACKLOG);
	if(sv_ret == -1) {
    		cerr << "Errore: funzione <listen> non eseguita correttamente sul server" << endl;
    		exit(0);
	}

	cout << endl;
	cout << "\033[32mSERVER IN ASCOLTO\033[0m" << endl;
	cout << "\033[32mIndirizzo IP server: " << SERVER_IP_ADD <<  "\033[0m" << endl;
	cout << "\033[32mPorta server: " << SERVER_PORT <<  "\033[0m" << endl;
	cout << "\033[32mDescrittore del soket lato server in ascolto: " << sv_sk <<  "\033[0m" << endl;
	cout << endl;
	cout << "********** FINE FASE DI CONNESSIONE *********" << endl;
	cout << endl;
	cout << "---------------------------------------------" << endl;
	cout << endl; 
	cout << "****** INIZIO FASE DI SCAMBIO MESSAGGI ******" << endl;
	cout << endl;

	while(1) {

		addrlen = sizeof(cl_addr);
		sv_sk_act = accept(sv_sk, (struct sockaddr *)(&cl_addr), &addrlen);
		if(sv_sk_act == -1) {
    			cerr << "Errore: funzione <accept> non eseguita correttamente sul server" << endl;
    			exit(0);
		} 
		
		/* Setto le informazioni relative al client associato  */
		cl_info cli;
		cli.id = 'C';
		cli.password = SERVER_PWD;		

		/* Ricevo dal client il messaggio M1 */
		msg1 m1;
		int dim1 = sizeof(msg1);	
		ret = recv(sv_sk_act, &m1, dim1, MSG_WAITALL);
		if(ret == -1) {
			cerr << "Errore: messaggio M1 non ricevuto correttamente" << endl;
			return -1;
		}

		cout << "\033[32m:: C -> S\033[0m" << endl;
		cout << "\033[34m:: Messaggio in chiaro M1 ricevuto correttamente \033[0m" << endl;
	
		if(m1.client != cli.id) {
			cout << "L'identificativo del Client non coincide con quello atteso" << endl;
			exit(0);		
		}
		else {
			cout << "\t\033[31m:: Controllo Identificativo Client -> OK\033[0m" << endl;		
		}

		cout << endl;

		/* Setto l'identificator del client */
                CLIENT = m1.client;

		/* Setto il nounce */
		msg2 m2;
		int n = rand();
		m2.nounce = n;
		NOUNCE = n;

		/* Converto il nounce in una stringa per poterlo utilizzare nel confronto del messaggio */
		char tmp[50];
		int m; //Numero di caratteri che compongono il nounce
		m = sprintf(tmp, "%i", NOUNCE); //Converto il nounce in una stringa
		char nounce[m];
		strcpy(nounce, tmp);

		/* Costruzione del messaggio M2  */
		m2.server = SERVER;
		m2.client = CLIENT;
				
		/* Invio al client il messaggio M2 */
		int dim2 = sizeof(msg2);
		ret = send(sv_sk_act, &m2, dim2, 0);	
		if(ret == -1) {
			cerr << "Errore: messaggio M2 non inviato correttamente" << endl;
			return -1;
		}
		
		cout << "\033[32m:: S -> C\033[0m" << endl; 
		cout << "\033[34m:: Messaggio in chiaro M2 inviato al client\033[0m" << endl;
		cout << endl;

		/* Setto la chiave privata con cui decriptare M3 */
		FILE *pri = fopen(PRI_KEY, "r");
		RSA *pri_key = RSA_new();
		PEM_read_RSAPrivateKey(pri, &pri_key, NULL, NULL);

		/* Ricevo la dimensione del messaggio cifrato M3 */
		int dim3c;
		ret = recv(sv_sk_act, &dim3c, 4, MSG_WAITALL);
		if(ret == -1) {
			cerr << "Errore: dimensione del messaggio cifrato M3 non ricevuta correttamente" << endl;
			return -1;
		}

		/* Ricevo il messaggio criptato M3 */
		unsigned char *m3c = (unsigned char*) malloc(dim3c);
		bzero(m3c, dim3c);
		ret = recv(sv_sk_act, m3c, dim3c, MSG_WAITALL);
		if(ret == -1) {
			cerr << "Errore: messaggio cifrato M3 non ricevuto correttamente" << endl;
			return -1;
		}

		cout << "\033[32m:: C -> S\033[0m" << endl;
		cout << "\033[34m:: Messaggio cifrato M3 ricevuto correttamente\033[0m" << endl;

		/* Decripto il messaggio cifrato M3 */
		unsigned char *m3 = (unsigned char*) malloc(RSA_size(pri_key));
		bzero(m3, RSA_size(pri_key));
		int nd; //Numero di byte restituiti dalla decifratura
		nd = RSA_private_decrypt(dim3c, m3c, m3, pri_key, RSA_PKCS1_OAEP_PADDING);
		if(nd == -1) {
			cerr << "Errore: funzione <RSA_private_decrypt> sul messaggio M3 non effettuata con successo" << endl;
			exit(1);
		}
		if(nd == 0) {
			cerr << "Errore: messaggio M3 non decriptato correttamente" << endl;
			exit(1);	
		}

		cout << "\t\033[31m:: Messaggio cifrato M3 decriptato correttamente\033[0m" << endl;
	
		/* Analizzo il messaggio decriptato M3 */
		char *c3 = strtok((char*)m3, " "); //Memorizzo l'id del client
		char *s3 = strtok(NULL, " "); //Memorizzo l'id del server
		char *n3 = strtok(NULL, " "); //Memorizzo il nounce
		char *p3 = strtok(NULL, " "); //Memorizzo la password
		char *k3 = strtok(NULL, " "); //Memorizzo la chiave di sessione

		/* Controllo che la password sia quella attesa */
		if(strcmp(p3, SERVER_PWD) != 0) {
			cout << "La password non coincide con quella attesa" << endl;
			exit(0);		
		}
		else {
			cout << "\t\033[31m:: Controllo Password -> OK\033[0m" << endl;		
		}

		/* Controllo che il nounce sia quello atteso */
		if(strcmp(n3, nounce) != 0) {
			cout << "Il nonce non coincide con quella atteso" << endl;
			exit(0);		
		}
		else {
			cout << "\t\033[31m:: Controllo Nonce -> OK\033[0m" << endl;
		}

		cout << endl;

		/* Setto la chiave di sessione */
		int len = strlen(k3);
		unsigned char *key = (unsigned char*) malloc(len + 1);
		bzero(key, len);
		memcpy(key, k3, len + 1);
		BF_KEY kcs;
		BF_set_key(&kcs, len, (const unsigned char*) k3);

		/* Costruisco il messaggio M4 da criptare e mandare al client */
		int sep4 = 2; //Numero di separatori da inserire nel messaggio M4
		int ids4 = 2; //Numero di identificatori da inserire nel messaggio M4
		int dim4 =  sep4 + ids4 + np;
		unsigned char *m4 = (unsigned char*) malloc(dim4 + 1);
		bzero(m4, dim4 + 1);
		strcpy((char*)m4, s3);
		strcat((char*)m4, " ");
		strcat((char*)m4, c3);
		strcat((char*)m4, " ");
		strcat((char*)m4, SERVER_PWD);	
		
		/* Cripto il messaggio con la chiave di sessione 8 byte alla volta */
		int dim4c = dim4 + 1;
		unsigned char *m4c = (unsigned char*) malloc(dim4c);
		bzero(m4c, dim4c);
				
		double b = 8.0; //Numero di byte -> dimensione del blocco cifrato
		int off = 0; //Offset
		for(int i = 0; i < (int)ceil(dim4c / b); i++) {
			BF_ecb_encrypt(m4 + off, &m4c[off], &kcs, BF_ENCRYPT);
			off+=b;
		}	

		/* Invio al client la dimensione del messaggio cifrato M4 */
		ret = send(sv_sk_act, &dim4c, 4, 0);	
		if(ret == -1) {
			cerr << "Errore: dimensione del messaggio cifrato M4 non inviata correttamente" << endl;
			return -1;
		}

		/* Invio al client il messaggio cifrato M4 */
		ret = send(sv_sk_act, m4c, strlen((char*)m4c), 0);	
		if(ret == -1) {
			cerr << "Errore: messaggio M4 non inviato correttamente" << endl;
			return -1;
		} 		
		
		cout << "\033[32m:: S -> C\033[0m" << endl;
		cout << "\033[34m:: Messaggio cifrato M4 inviato al client\033[0m" << endl;
		cout << endl;


		cout << "******* FINE FASE DI SCAMBIO MESSAGGI *******" << endl;
		cout << endl;
		cout << "---------------------------------------------" << endl;
		cout << endl; 
		cout << "************ INIZIO FASE DI TEST ************" << endl;
		cout << endl;

		/* Ricevo la dimensione del messaggio di test in chiaro */
		int dimtest;
		ret = recv(sv_sk_act, &dimtest, 4, MSG_WAITALL);
		if(ret == -1) {
			cerr << "Errore: dimensione del messaggio di test in chiaro non ricevuto correttamente" << endl;
			return -1;
		}

		/* Ricevo la dimensione del messaggio di test criptato */
		int dimtestc;
		ret = recv(sv_sk_act, &dimtestc, 4, MSG_WAITALL);
		if(ret == -1) {
			cerr << "Errore: dimensione del messaggio di test criptato non ricevuto correttamente" << endl;
			return -1;
		}

		/* Ricevo il messaggio di test cifrato */
		unsigned char *testc = (unsigned char*) malloc(dimtestc);
		bzero(testc, dimtestc);
		ret = recv(sv_sk_act, testc, dimtestc, MSG_WAITALL);
		if(ret == -1) {
			cerr << "Errore: messaggio di test criptato non ricevuto correttamente" << endl;
			return -1;
		}

		cout << "\033[32m:: C -> S\033[0m" << endl;
		cout << "\033[34m:: Messaggio di test cifrato ricevuto correttamente\033[0m" << endl;
		cout << endl; 

		/* Decifro il messaggio di test */
		unsigned char *test = (unsigned char*) malloc(dimtest + 1);
		bzero(test, dimtest + 1);	
		int offtest = 0;
		for(int j = 0; j < (int)ceil(dimtest / b); j++) {
			BF_ecb_encrypt((const unsigned char*)testc + offtest, &test[offtest], &kcs, BF_DECRYPT);
			offtest += b;
		}

		cout << "\033[33mMESSAGGIO DECIFRATO:\033[0m" << endl;
		cout << endl;
		cout << test << endl;
		
		cout << endl;
		cout << "************* FINE FASE DI TEST *************" << endl;
		cout << endl;
		
		/* Libero la memoria */
		free(m3c);
		free(m3);
		free(key);
		free(m4c);
		free(m4);
		free(testc);
		free(test);
	}

	close(sv_sk);

	return 0;

}
