#include "client.h"

int main(int argc, char *argv[])
{
	/* Variabili e strutture standard per la gestione della connessione */
	int ret;
	int cl_sk;
	int cl_ret;
	struct sockaddr_in sv_addr;

	/* Passare, oltre a indirizzo IP e porta (del server), anche la password condivisa con il server */
	if(argc != 4) {
		cerr << "Errore: sintassi del comando errata" << endl;
		cout << "Digitare: ./client <indirizzo_IP> <porta> <password_condivisa>" << endl;
		exit(1);
	}

	SERVER_IP_ADD = argv[1];
	SERVER_PORT = atoi(argv[2]);
	CLIENT_PWD = argv[3];

	cout << endl;
	cout << "********* INIZIO FASE DI CONNESSIONE ********" << endl;

	int np = strlen(CLIENT_PWD); //Numero di caratteri che compongono la password

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

	/* Creazione del socket lato client */	
	cl_sk = socket(AF_INET, SOCK_STREAM, 0);
	if(cl_sk == -1) {
    		cerr << "Errore: funzione <socket> non eseguita correttamente sul client" << endl;
    		exit(0);
	}

	/* Inizializzazione struttura dati */
	bzero(&sv_addr, sizeof(struct sockaddr_in)); /* Azzera il contenuto della struttura */
	sv_addr.sin_family = AF_INET;
	sv_addr.sin_port = htons(SERVER_PORT);
	inet_pton(AF_INET, SERVER_IP_ADD, &sv_addr.sin_addr.s_addr); /* Converte l'indirizzo da stringa a valore numerico */
	
	cl_ret = connect(cl_sk, (struct sockaddr *)(&sv_addr), sizeof(struct sockaddr_in));
	if(cl_ret == -1) {
		cerr << "Errore: funzione <connect> non eseguita correttamente sul client" << endl;
    		exit(0);
	}
	
	cout << endl;
	cout << "\033[32mCONNESSIONE CLIENT-SERVER EFFETTUATA\033[0m" << endl;
	cout << "\033[32mIndirizzo IP server: " << SERVER_IP_ADD << "\033[0m" << endl;
	cout << "\033[32mPorta server: " << SERVER_PORT << "\033[0m" << endl;
	cout << "\033[32mDescrittore del soket lato client in ascolto: " << cl_sk << "\033[0m" << endl;	
	cout << endl;
	cout << "********** FINE FASE DI CONNESSIONE *********" << endl;
	cout << endl;
	cout << "---------------------------------------------" << endl;
	cout << endl; 
	cout << "****** INIZIO FASE DI SCAMBIO MESSAGGI ******" << endl;
	cout << endl;
	
	/* Setto l'identificatore del client e del server */
	CLIENT = 'C';		
	SERVER = 'S';

	/* Costrutisco il messaggio M1 */
	msg1 m1;		
	m1.client = CLIENT;
	m1.server = SERVER;

	/* Invio al server il messaggio M1 */
	int dim1 = sizeof(msg1);
	ret = send(cl_sk, &m1, dim1, 0);
	if(ret == -1) {
		cerr << "Errore: messaggio M1 non inviato correttamente" << endl;
		return -1;
	}

	cout << "\033[32m:: C -> S\033[0m" << endl;
	cout << "\033[34m:: Messaggio in chiaro M1 inviato al server\033[0m" << endl;
	cout << endl;

	/* Ricevo dal server il messaggio M2 */
	msg2 m2;
	int dim2 = sizeof(msg2);
	ret = recv(cl_sk, &m2, dim2, MSG_WAITALL);
	if(ret == -1) {
		cerr << "Errore: messaggio M2 non ricevuto correttamente" << endl;
		return -1;
	}

	/* Memorizzo il nounce ricevuto dal server */
	NOUNCE = m2.nounce;

	cout << "\033[32m:: S -> C\033[0m" << endl;
	cout << "\033[34m:: Messaggio in chiaro M2 ricevuto correttamente\033[0m" << endl;
	cout << endl;

	/* Setto la chiave pubblica con cui criptare M3 */
	FILE *pub = fopen(PUB_KEY, "r");
	RSA *pub_key = RSA_new();
	PEM_read_RSA_PUBKEY(pub, &pub_key, NULL, NULL);

	/* Converto il nounce in una stringa per poterlo inserire nel messaggio da cifrare */
	char tmp[50];
	int n; //Numero di caratteri che compongono il nounce
	n = sprintf(tmp, "%i", NOUNCE); //Converto il nounce in una stringa
	char nounce[n];
	strcpy(nounce, tmp);
	
	/* Genero le componenti della chiave di sessione in maniera random */
	int part1 = rand();
	char tmp1[50];
	int t1 = sprintf(tmp1, "%i", part1);
	char p1[t1];
	strcpy(p1, tmp1);

	int part2 = rand();
	char tmp2[50];
	int t2 = sprintf(tmp2, "%i", part2);
	char p2[t2];
	strcpy(p2, tmp2);

	int part3 = rand();
	char tmp3[50];
	int t3 = sprintf(tmp3, "%i", part3);
	char p3[t3];
	strcpy(p3, tmp3);
	
	/* Costruisco la chiave di sessione */
	int dim_ses = t1 + t2 + t3; //Numero di caratteri della chiave di sessione
	char *ses_key = (char*) malloc (dim_ses);
	bzero(ses_key, dim_ses);
	strcpy(ses_key, p1);
	strcat(ses_key, p2);
	strcat(ses_key, p3);

	/* Setto la chiave di sessione */
	BF_KEY kcs;
	BF_set_key(&kcs, dim_ses, (const unsigned char*)ses_key);	

	/* Costruisco il messaggio M3 da criptare e inviare al client */
	int sep3 = 4; //Numero di separatori da inserire nel messaggio M3
	int ids3 = 2; //Numero di identificatori da inserire nel messaggio M3
	int dim3 = ids3 + n + np + dim_ses + sep3;
	char *m3 = (char*) malloc(dim3 + 1);
	bzero(m3, dim3 + 1);
	strcpy(m3, "C");
	strcat(m3, " ");
	strcat(m3, "S");
	strcat(m3, " ");
	strcat(m3, nounce);
	strcat(m3, " ");
	strcat(m3, CLIENT_PWD);
	strcat(m3, " ");
	strcat(m3, ses_key);
	
	/* Cripto il messaggio M3 con la chiave pubblica */
	unsigned char *m3c = (unsigned char*) malloc(RSA_size(pub_key));
	bzero(m3c, RSA_size(pub_key));
	int nc; //Numero di byte restituiti dalla cifratura
	nc = RSA_public_encrypt(dim3, (unsigned char*)m3, m3c, pub_key, RSA_PKCS1_OAEP_PADDING);
	if(nc == -1) {
		cerr << "Errore: funzione <RSA_public_encrypt> sul messaggio M3 non effettuata con successo" << endl;
		exit(1);
	}
	if(nc == 0) {
		cerr << "Errore: messaggio M3 non criptato correttamente" << endl;
		exit(1);	
	}

	/* Invio al server la dimensione del messaggio cifrato */
	int dim3c = RSA_size(pub_key);
	ret = send(cl_sk, &dim3c, 4, 0);
	if(ret == -1) {
		cerr << "Errore: dimensione del messaggio cifrato M3 non inviata correttamente" << endl;
		return -1;
	}

	/* Invio al server il messaggio cifrato M3 */
	ret = send(cl_sk, m3c, dim3c, 0);
	if(ret == -1) {
		cerr << "Errore: messaggio cifrato M3 non inviato correttamente" << endl;
		return -1;
	}

	cout << "\033[32m:: C -> S\033[0m" << endl;
	cout << "\033[34m:: Messaggio cifrato M3 inviato al server\033[0m" << endl;
		cout << endl;	

	/* Ricevo dal server la dimensione il messaggio criptato M4 */
	int dim4c;	
	ret = recv(cl_sk, &dim4c, 4, MSG_WAITALL);
	if(ret == -1) {
		cerr << "Errore: dimensione del messaggio cifrato M4 non ricevuta correttamente" << endl;
		return -1;
	}

	/* Imposto la dimensione del messaggio criptato M4 */
	double b = 8.0; //Numero di byte -> dimensione del blocco cifrato
	int dim4cb = (int)ceil(dim4c / b) * 8;
	dim4cb++;
	
	/* Ricevo dal server il messaggio criptato M4 */
	unsigned char *m4c = (unsigned char*) malloc(dim4cb);
	bzero(m4c, dim4cb);
	ret = recv(cl_sk, m4c, dim4cb, MSG_WAITALL);
	if(ret == -1) {
		cerr << "Errore: dimensione del messaggio cifrato M4 non ricevuta correttamente" << endl;
		return -1;
	}

	cout << "\033[32m:: S -> C\033[0m" << endl;
	cout << "\033[34m:: Messaggio cifrato M4 ricevuto correttamente\033[0m" << endl;

	/* Decifro il messaggio criptato M4 */
	unsigned char *m4 = (unsigned char*) malloc(dim4c);
	bzero(m4, dim4c);
	int off = 0; //Offeset		
	for(int i = 0; i < (int)ceil(dim4c / b); i++) {
		BF_ecb_encrypt(m4c + off, &m4[off], &kcs, BF_DECRYPT);
		off+=b;
	}

	cout << "\t\033[31m:: Messaggio cifrato M4 decriptato correttamente\033[0m" << endl;

	/* Analizzo il messaggio decriptato M4 */
	char *s4 = strtok((char*)m4, " "); //Memorizzo l'id del server
	char *c4 = strtok(NULL, " "); //Memorizzo l'id del client
	char *p4 = strtok(NULL, " "); //Memorizzo la password

	/* Controllo che la password sia quella attesa */
	if(strcmp(p4, CLIENT_PWD) != 0) {
		cout << "La password non coincide con quella attesa" << endl;
		exit(0);		
	}
	else {
		cout << "\033[31m\t:: Controllo Password -> OK\033[0m" << endl;
	}

	cout << endl;
	cout << "******* FINE FASE DI SCAMBIO MESSAGGI *******" << endl;
	cout << endl;
	cout << "---------------------------------------------" << endl;
	cout << endl;

	/* Pulizia delle variabili inutilizzate per evitare warning */	
	strcpy(c4, "");
	strcpy(s4, "");
 
	cout << "************ INIZIO FASE DI TEST ************" << endl;
	cout << endl;

	/* Apertura del file per effettuare il test */
	fstream ft;
	ft.open(TEST, ios::in);
	if(!ft) {
		cerr << "Errore nell'apertura del file di test" << endl;
    		exit(0);
  	}
	 
	/* Memorizzo il file di test in una stringa */	
	char *test_tmp = (char*) malloc(MAX_FILE_LEN);
	bzero(test_tmp, MAX_FILE_LEN);
	char line[MAX_LINE_LEN];
	while(ft.getline(line, MAX_LINE_LEN)) {
		strcat(test_tmp, line);		
	}

	/* Alloco lo spazio effettivamente utilizzato dal file di test */
	int dimtest = strlen(test_tmp) + 1;
	char *test = (char*) malloc(dimtest+1);
	bzero(test, dimtest);
	strcpy(test,test_tmp);

	/* Invio al server la dimensione del messaggio in chiaro */
	ret = send(cl_sk, &dimtest, 4, 0);
	if(ret == -1) {
		cerr << "Errore: dimensione del messaggio di test in chiaro non inviata correttamente" << endl;
		return -1;
	}

	/* Imposto la dimensione del messaggio di test criptato */
	int dimtestc = (int)ceil(dimtest / b) * 8;
	dimtestc++;

	/* Cripto la stringa del file di test */
	unsigned char *testc = (unsigned char*) malloc(dimtestc);
	bzero(testc, dimtestc);	
	int offtest = 0;
	for(int j = 0; j < (int)ceil(dimtest / b); j++) {
		BF_ecb_encrypt((const unsigned char*)test + offtest, &testc[offtest], &kcs, BF_ENCRYPT);
		offtest += b;	
	}

	/* Invio al server la dimensione della stringa di test cifrata */
	ret = send(cl_sk, &dimtestc, 4, 0);
	if(ret == -1) {
		cerr << "Errore: dimensione del messaggio di test cifrato non inviata correttamente" << endl;
		return -1;
	}

	/* Invio al server la stringa di test cifrata */
	ret = send(cl_sk, testc, dimtestc, 0);
	if(ret == -1) {
		cerr << "Errore: messaggio di test cifrato non inviato correttamente" << endl;
		return -1;
	}

	cout << "\033[32m:: C -> S\033[0m" << endl;
	cout << "\033[34m:: Messaggio di test cifrato e inviato al server\033[0m" << endl;

	cout << endl;
	cout << "************* FINE FASE DI TEST *************" << endl;
	cout << endl;

	/* Libero la memoria */
	RSA_free(pub_key);
	fclose(pub);
	free(m3);
	free(m3c);
	free(ses_key);
	free(m4c);
	free(m4);
	free(test_tmp);
	free(test);
	free(testc);
	
	return 0;
}


