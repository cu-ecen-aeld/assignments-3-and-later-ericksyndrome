#include <sys/stat.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/wait.h>
#include <signal.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdbool.h>
#include <pthread.h>
#include <sys/queue.h>




#define SERVER_PORT     ("9000")
#define MAXDATASIZE     (1024)
#define TMP_FILE        ("/var/tmp/aesdsocketdata")
#define NUM_THREADS      (10) //not sure yet

volatile sig_atomic_t cleanup_trigger = 0;
int server_run = 0; //initially 1
int socketfd = 0;
FILE *file_ptr = NULL; //file going to /var/tmp/ 
pthread_t timer_thread; //global var for timer_thread
pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

typedef struct ThreadNode { //this struct is used to manage node
	pthread_t thread;
	int newfd;  //peer data
	//int run;    //used for controlled termination
	pthread_mutex_t *mutex;
	FILE *log;
	int flag;  //contains params
	SLIST_ENTRY(ThreadNode) entries;
	//int *run;    //used for controlled termination
} ThreadNode;

//needs headname and type
SLIST_HEAD(ThreadList, ThreadNode) threadList = SLIST_HEAD_INITIALIZER(threadList);

//inserts new entry into a list and returns ptr to inserted node
struct ThreadNode *insert_node(struct ThreadList *head)
{
	struct ThreadNode *new_node = malloc(sizeof(struct ThreadNode));
	memset(new_node, 0, sizeof(struct ThreadNode));
	SLIST_INSERT_HEAD(head, new_node, entries);
	return new_node;
}


//zero out memory for initiliaztion 
int init(struct ThreadList *head) 
{
	SLIST_INIT(head);
	
	//initiliaze vars
	struct ThreadNode node;
	memset(&node, 0, sizeof(struct ThreadNode)); //zero out memory for node
	
	//set run or control variable
	server_run = 1;
	syslog(LOG_CRIT, "zery memory\n");
	
	return 0;
}

/*** adding thread to handle clients ***/
void *handle_client_thread(void *threadp) {
	//threadParams_t *threadParams = (threadParams_t *)threadp;
	struct ThreadNode* node = (struct ThreadNode*) threadp;
	int newfd = node->newfd; //created an instance threadParams 
	char buff[MAXDATASIZE];
	memset(buff, 0, MAXDATASIZE); //zero mem
	int bytes = 0;
	
	//below is handling the recv
	while (server_run == 1 && (bytes=recv(newfd, buff, MAXDATASIZE-1, 0) > 0))
	{
		//acquirirng mutex
		pthread_mutex_lock(node->mutex);
		
		//writing to output log
		if (node->log != NULL) {
			fprintf(node->log, "%s", buff);
		}
		
		//releasing mutex
		pthread_mutex_unlock(node->mutex);
		
		//break when a newline is found
		if (strpbrk(buff, "\n") != NULL)
		{
			break;
		}
		memset(buff, 0, MAXDATASIZE);
	}
	
	//below is handdling the bytes to send
	if (server_run == 1) {
		//acquring mutex
		pthread_mutex_lock(node->mutex);
		//seeking to beggining of file
		if (fseek(node->log, 0, SEEK_SET) != 0) {
		perror("Failed to seek to the bof\n"); }
		
		//defining bytes rx to echo back
		ssize_t bytes_rx = 0;
		while(server_run == 1 && (bytes_rx = fread(buff, sizeof(char), MAXDATASIZE, node->log)) != 0)
		{
			if (send(newfd, buff, bytes_rx, 0) != 0) {
				perror("cannot send fam");
			}
			memset(buff, 0, MAXDATASIZE);
		}
		//now release mutex
		pthread_mutex_unlock(node->mutex);
	}
	//set complete flag
	node->flag = 1;
	//exit thread
	return NULL;
}

void join_threads(struct ThreadList *head, int force_exit) //pass this in for reference
{
	struct ThreadNode *current, *tmp;
	current = SLIST_FIRST(head);
	while (current != NULL)
	{
		tmp = SLIST_NEXT(current, entries);
		if (current->flag == 1 || force_exit == 1) {
			//join thread
			pthread_join(current->thread, NULL);
			//removal of node from list
			SLIST_REMOVE(head, current, ThreadNode, entries);
			//free allocated mem
			free(current); 
	}
	current=tmp;
}
} 

//timer thread
void *timer_thread_func(void *arg) {
	pthread_mutex_t *mutex = (pthread_mutex_t *)arg;
	while (server_run) {
		sleep(10); //waits 10 seconds
		
		//get current time
		time_t now = time(NULL);
		char time_buffer[100];
		strftime(time_buffer, sizeof(time_buffer), "timestamp: %a, %d %b %Y %H:%M:%S", localtime(&now));
		
		//writitng timestamp to file
		pthread_mutex_lock(mutex);
		FILE *file = fopen(TMP_FILE, "a"); //append mode
		if (file) {
			fprintf(file, "%s\n", time_buffer);
			fclose(file);
		}
		pthread_mutex_unlock(mutex);
	}
	return NULL;
} 

void cleanup() {
	//stop server
	server_run = 0;
	
	//join timer thread
	pthread_join(timer_thread, NULL);
	
	if (socketfd > 0) {
		shutdown(socketfd, SHUT_RDWR); //graceful shut down
		close(socketfd);
		socketfd = -1;   //prevents reuse of old socket fd
	}
	
	//close log file
	if (file_ptr != NULL) {
		fclose(file_ptr);
		file_ptr = NULL;
	}
	
	join_threads(&threadList, 1); //cleans list as well
	syslog(LOG_CRIT, "cleanup complete");
}

void handle_sig(int sig)
{
	if (sig == SIGINT || sig == SIGTERM) {
	/*	syslog(LOG_CRIT, "caught signal, exiting now");
		//shut server
		cleanup();
		exit(EXIT_SUCCESS);
	}*/
	cleanup_trigger = 1; //this is for thread safety
}
} 

void add_sigActions() {
syslog(LOG_DEBUG, "adding sig actions success");
	
struct sigaction act = {
	 .sa_handler = handle_sig,
 };
/* act.sa_handler = handle_sig;
 sigemptyset(&act.sa_mask); */ 
 sigaction(SIGINT, &act, NULL);
 sigaction(SIGTERM, &act, NULL);	
}

int main(int argc, char *argv[])
{
	
	
	
//verify proper usage
    if (argc >= 2 && !strcmp(argv[1], "-d"))
    {
		if (daemon(0, 0) == -1)
		{
			perror("Daemon time failed");
			exit(-1);
		}
	}
	syslog(LOG_INFO,"usage is proper. \n");	
    
    //set up signal handler      
    add_sigActions();
    
    //initialize
    if (init(&threadList) == -1)
    {
		exit(-1);
	}
	
	//getting socket fd
	int socketfd = socket(AF_INET, SOCK_STREAM, 0);
	if (socketfd == -1) {
		perror("socket failed");
		exit(-1);
	}
	
	//set socket options
	if (setsockopt(socketfd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) == -1)
	{
		perror("sockopt failed");
		exit(-1);
	}
	
	//binding socket to address and port
	struct sockaddr_in server_address;
	server_address.sin_family = AF_INET;
	server_address.sin_port = htons(9000);
	server_address.sin_addr.s_addr = INADDR_ANY;
	
	//bind
	if (bind(socketfd, (struct sockaddr *)&server_address, sizeof(server_address)) == -1)
	{
		perror("Bind failed");
		exit(-1);
	}
	
	//listening for connections
	if (listen(socketfd, 10) == -1)
	{
		perror("listen failed");
		exit(-1);
	}
	
	//opening output file
	file_ptr = fopen(TMP_FILE, "w+");
	if (file_ptr == NULL)
	{
		perror("failed to open output file");
		exit(-1);
	}
	
	pthread_create(&timer_thread, NULL, timer_thread_func, &log_mutex);
	
	//while loop as long as run is enabled
	while (server_run)
	{
		if (cleanup_trigger) {
			server_run = 0;  //server loop is exited
			cleanup();
			break;
		}
		//accept incoming conections
		struct sockaddr_in peer_addr;
		socklen_t peer_len = sizeof(peer_addr);
		int peer = accept(socketfd, (struct sockaddr *)&peer_addr, &peer_len);
		if (peer == -1)
		{
			perror("accept failed");
		}
		char peer_ip[INET_ADDRSTRLEN];
		if (inet_ntop(AF_INET, &(peer_addr.sin_addr), peer_ip, INET_ADDRSTRLEN) == NULL)
		{
			perror("call to inet_ntop failed");
		}
		if (server_run)
		{
			syslog(LOG_INFO, "Accepted connection from: %s", peer_ip);
			struct ThreadNode *node = insert_node(&threadList); //check this
			node->log = file_ptr;
			node->mutex = &log_mutex;
			node->newfd = peer;
			node->flag = 0;
			//node->run = 1; //check
			pthread_create(&node->thread, NULL, handle_client_thread, (void *)node);
		}
		join_threads(&threadList, 0); //joins threads and doesn't force exit
	}
	if (!cleanup_trigger) { //if not triggered by signal call here
		cleanup();
	}
	//pthread_join(timer_thread, NULL);
	//cleanup();
	syslog(LOG_INFO, "Server exiting");
	exit(EXIT_SUCCESS);
}
			
	
	

			
		
	
		
	
	
