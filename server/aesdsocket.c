#include <sys/stat.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
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

//#ifndef USE_AESD_CHAR_DEVICE
//#define USE_AESD_CHAR_DEVICE 1
//#endif

#ifdef USE_AESD_CHAR_DEVICE
	#define DATA_FILE ("/dev/aesdchar")
#else
	#define DATA_FILE ("/var/tmp/aesdsocketdata")
#endif

#define SERVER_PORT     ("9000")
#define MAXDATASIZE     (1024)
#define NUM_THREADS     (10) 

volatile sig_atomic_t cleanup_trigger = 0;
int server_run = 0; //initially 1
int socketfd = -1; //was 0
//FILE *file_ptr = NULL; //file going to /var/tmp/ or /dev/aesdchar
#ifndef USE_AESD_CHAR_DEVICE 
pthread_t timer_thread; //global var for timer_thread
#endif
pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t thread_list_mutex = PTHREAD_MUTEX_INITIALIZER;

typedef struct ThreadNode { //this struct is used to manage node
	pthread_t thread;
	int newfd;  //peer data
	//pthread_mutex_t *mutex;
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
	SLIST_INIT(head);  //check
	
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
	
	struct ThreadNode* node = (struct ThreadNode*) threadp;
	int newfd = node->newfd; 
	char buff[MAXDATASIZE];
	memset(buff, 0, MAXDATASIZE); //zero mem
	FILE * file_ptr;
	int openfd = 0;
	ssize_t bytes_rx;
	
	//below is handling the recv
	while (server_run==1) {
		int bytes = recv(newfd, buff, MAXDATASIZE - 1, 0);
		if (bytes <= 0) {
			break; // exit loop if no data or error
		}
		
		// locking file mutex for writing data
		pthread_mutex_lock(&log_mutex);
		//making mods for a8 below
#ifdef USE_AESD_CHAR_DEVICE
			openfd = open(DATA_FILE, O_RDWR | O_CREAT | O_APPEND, S_IWUSR | S_IRUSR | S_IWGRP | S_IRGRP | S_IROTH);
			if (!openfd || openfd == -1) {
				syslog(LOG_ERR, "Could not open file");
				break;
			}
			if (write(openfd, buff, bytes) == -1) {
				syslog(LOG_ERR, "cannot write damn");
				pthread_mutex_unlock(&log_mutex);
				perror("write error");
			}
		/*	else {
				printf("%c", buff);
			} */
			close(openfd);
			
			
#else
		file_ptr = fopen(DATA_FILE, "a"); //open in append mode
		if (file_ptr != NULL) {
			fwrite(buff, sizeof(char), bytes, file_ptr);
			fflush(file_ptr); //questionable, flushing stream
			fclose(file_ptr); //closing file to ensure data is written and fd is freed
			//file_ptr = NULL; //questionable
		}
		else {
			syslog(LOG_CRIT, "failed to open deevice file");
		}
#endif
		pthread_mutex_unlock(&log_mutex);
		
		//check for newline to break the loop
		if (strpbrk(buff, "\n") != NULL) {
			break;
		}
		memset(buff, 0, MAXDATASIZE);
	}
	
	
	//below is handling the bytes to send back
	pthread_mutex_lock(&log_mutex);
#ifdef USE_AESD_CHAR_DEVICE
	openfd = open(DATA_FILE, O_RDWR | O_CREAT | O_APPEND, S_IWUSR | S_IRUSR | S_IWGRP | S_IRGRP | S_IROTH);
	if (openfd == -1) {
        syslog(LOG_ERR, "Could not open device file for reading");
    } else {
        while (server_run ==1 && (bytes_rx = read(openfd, buff, MAXDATASIZE)) > 0) {
            send(newfd, buff, bytes_rx, 0); //send data to client
            memset(buff, 0, MAXDATASIZE);
        }
        close(openfd);
    }
#else
	file_ptr = fopen(DATA_FILE, "r"); //open in read mode
	if (file_ptr != NULL) {
		fseek(file_ptr, 0, SEEK_SET);
		while (server_run ==1 && (bytes_rx = fread(buff, sizeof(char), MAXDATASIZE, file_ptr)) > 0) {
			send(newfd, buff, bytes_rx, 0); //send data to client
			memset(buff, 0, MAXDATASIZE);
		}
		fclose(file_ptr);
	} else {
	syslog(LOG_CRIT, "failed to open for reading");
	}
#endif
	pthread_mutex_unlock(&log_mutex);
	
	node->flag = 1; //set thread complete flaf
	return NULL;
} 

#ifndef USE_AESD_CHAR_DEVICE

//timer thread
void *timer_thread_func(void *arg) {
	//pthread_mutex_t *mutex = (pthread_mutex_t *)arg;
	FILE * file = (FILE *)arg; //use passed file ptr
	while (server_run) {
		sleep(10); //waits 10 seconds
		
		//get current time
		time_t now = time(NULL);
		char time_buffer[100];
		strftime(time_buffer, sizeof(time_buffer), "timestamp: %a, %d %b %Y %H:%M:%S", localtime(&now));
		
		//writitng timestamp to file
		pthread_mutex_lock(&log_mutex);
		if (file != NULL) {
			fprintf(file, "%s\n", time_buffer);
			fflush(file);
		}
		pthread_mutex_unlock(&log_mutex);
	}
	return NULL;
}
#endif

void cleanup() {
	
	//stop server
	server_run = 0;
	
	//join timer thread
	//pthread_join(timer_thread, NULL); //inspect
#ifndef USE_AESD_CHAR_DEVICE
    remove(DATA_FILE);
#endif	
	if (socketfd > 0) {
		shutdown(socketfd, SHUT_RDWR); //graceful shut down
		close(socketfd);
		socketfd = -1;   //prevents reuse of old socket fd
	}
	
	/*
	//close log file if any open
	FILE * file_ptr;
	if (file_ptr != NULL) {
		fclose(file_ptr);
		file_ptr = NULL;
	} */
	
	//clean up threads
	struct ThreadNode *current, *tmp;
	pthread_mutex_lock(&thread_list_mutex);
	current = SLIST_FIRST(&threadList);
	while (current != NULL) {
		tmp = SLIST_NEXT(current, entries);
		if (current->flag ==1) {
			pthread_join(current->thread, NULL); //join current threads?
			SLIST_REMOVE(&threadList, current, ThreadNode, entries);
			free(current);
		}
		current = tmp;
	}
	pthread_mutex_unlock(&thread_list_mutex);
		
	//destroy mutexes
	pthread_mutex_destroy(&log_mutex);
	pthread_mutex_destroy(&thread_list_mutex);
	syslog(LOG_CRIT, "cleanup complete");
		
}

void handle_sig(int sig)
{
	if (sig == SIGINT || sig == SIGTERM) {
	
	cleanup_trigger = 1; //this is for thread safety
}
} 

void add_sigActions() {
syslog(LOG_DEBUG, "adding sig actions success");
	
struct sigaction act = {
	 .sa_handler = handle_sig,
 };

 sigemptyset(&act.sa_mask);  
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
    
#ifndef USE_AESD_CHAR_DEVICE
	if (remove(DATA_FILE) != 0) {
        // Handle error if the file removal failed, unless it's just because the file didn't exist
        if (errno != ENOENT) {
            perror("Failed to remove data file");
            exit(EXIT_FAILURE);
        }
    }
#endif
    /*FILE * fp = fopen(DATA_FILE, "w");
    if (fp != NULL) {
		fclose(fp);
	} else {
		perror("failed to trunc data file");
		exit(EXIT_FAILURE);
	}*/
    
    //initialize
    if (init(&threadList) == -1)
    {
		exit(EXIT_FAILURE);
	}
	
	//getting socket fd
	socketfd = socket(AF_INET, SOCK_STREAM, 0);
	if (socketfd == -1) {
		perror("socket failed");
		exit(EXIT_FAILURE);
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
	
	
	//pthread_create(&timer_thread, NULL, timer_thread_func, file_ptr); //check last arg
	
	//while loop as long as run is enabled
	while (server_run)
	{
		if (cleanup_trigger) {
		//	server_run = 0;  //server loop is exited might not need?
			//cleanup();
			break;
		}
		//accept incoming conections
		struct sockaddr_in peer_addr;
		socklen_t peer_len = sizeof(peer_addr);
		int peer = accept(socketfd, (struct sockaddr *)&peer_addr, &peer_len);
		if (peer == -1)
		{
			perror("accept failed");
			continue; //skip to next iteration if accept fails, this is questionable
		}
		
		//handle accpeted connection
		char peer_ip[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &(peer_addr.sin_addr), peer_ip, INET_ADDRSTRLEN);
		syslog(LOG_INFO, "Accepted connection from: %s", peer_ip);
		
		struct ThreadNode *node = insert_node(&threadList);
		//node->log = file_ptr; //come back here to check
		node->newfd = peer;
		node->flag = 0;
		
		pthread_create(&node->thread, NULL, handle_client_thread, (void *)node);
	}
	//now time to cleanup if not triggered by signal
	if (!cleanup_trigger) {
		cleanup();
	}
	syslog(LOG_INFO, "server exiting");
	exit(EXIT_SUCCESS);
}
