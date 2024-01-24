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

static bool daemon_time = false;
static bool kill_system = false;
static pthread_mutex_t data_mutex = PTHREAD_MUTEX_INITIALIZER;

/**** declaring functions beforehand ****/
void handle_clients(int socketfd);
char *buf_to_file(char *buf, int buf_len);
void read_stream(int newfd);
int get_socketfd();
int bind_func(int socketfd);
int socketfd = 0;
void add_sigActions();
void *get_in_addr(struct sockaddr *sa);

/**** thread and linked list stuff ****/

// struct to hold thread params
typedef struct {
	int newfd;  //data
	SLIST_ENTRY(ThreadNode) entries; //ThreadNode is a type
} threadParams_t;  //thread parameters type
	
//SLIST_HEAD(ThreadList, ThreadNode); //needs headname and type
SLIST_HEAD(ThreadList, ThreadNode) threadList = SLIST_HEAD_INITIALIZER(threadList);

struct ThreadNode {
	threadParams_t params;
	SLIST_ENTRY(ThreadNode) entries;
};


/*** adding thread to handle clients ***/
void *handle_client_thread(void *threadp) {
	threadParams_t *threadParams = (threadParams_t *)threadp;
	int newfd = threadParams->newfd;
	pthread_mutex_lock(&data_mutex);
	/*** below is from prev handle func ***/
	//some info for the peer struct before accept()
struct sockaddr_storage peer;
//socklen_t peer_addr_size;
//peer_addr_size = sizeof(peer);
  //int newfd = accept(socketfd, (void *)&peer, &peer_addr_size);

  if (newfd < 0) {
	  if (kill_system)
		  return NULL;
	  exit(1);
  } else {
	  char client[INET_ADDRSTRLEN];
	  char *buf = NULL;
	  int buf_size, buf_len;
	  ssize_t bytes_rx;

//function to convert ip to something printable
memset(client, 0, sizeof(client));
inet_ntop(peer.ss_family, get_in_addr((struct sockaddr *)&peer), client, sizeof(client));
//printf("server got connection from: %s \n", client);
syslog(LOG_INFO, "Accepted connection from: %s \n", client);



  while(!kill_system) {
	if (buf == NULL) {
		buf_len = 0;
		buf_size = 0;
	}
        if (buf_len == buf_size) {
	       if (buf_size == 0) {
	       buf_size = 100;
	       } else {
	         buf_size *= 2;
	       }
       buf = realloc(buf, buf_size);
	}
 bytes_rx = recv(newfd, buf + buf_len, 1, 0);
 if (bytes_rx == -1 || bytes_rx == 0) {
	break;
 } else if (bytes_rx == 1) {
    buf_len++;
 if (buf[buf_len-1] == '\n') {
     write(1, buf, buf_len);
    
     buf = buf_to_file(buf, buf_len);
     read_stream(newfd);
 }
 }
}  //close while loop 
  if (buf) {
	  free(buf);
	  buf = NULL;
	  
  }
  close(newfd);
 }
   free(threadParams);
   return NULL;  
}

/*** accept clients thread ***/
void *accept_connections(void *socketfd_ptr) {
	//int socketfd = *((int *)socketfd_ptr); //wtf
	
	while(!kill_system) {
	/*	struct sockaddr_storage peer;
		socklen_t peer_addr_size = sizeof(peer);
		
		int newfd = accept(socketfd, (void *)&peer, &peer_addr_size);
		
		if (newfd < 0) {
			if (kill_system)
				return NULL;
			exit(1); 
		}
		else { */
			threadParams_t *params = malloc(sizeof(threadParams_t));
			//params->newfd = newfd;
			//params->socketfd = socketfd;
			
			//creating new thread node for each connection
			struct ThreadNode *node = malloc(sizeof(struct ThreadNode));
			memcpy(&node->params, params, sizeof(threadParams_t));
			SLIST_INSERT_HEAD(&threadList, node, entries);
			
			//create new thread for each connection
			pthread_t thread;
			pthread_create(&thread, NULL, handle_client_thread, (void*)params);
		//}
		}
		return NULL;
}	

// maybe change up later to match example				
void cleanup_threads() {
	struct ThreadNode *node;
	
	SLIST_FOREACH(node, &threadList, entries) {
		SLIST_REMOVE_HEAD(&threadList, entries);
		//free(node->params);
		free(node);
	}
}
			

void handle_sig(int sig)
{
	if (sig == SIGINT || sig == SIGTERM) {
		kill_system = true;
		cleanup_threads();
	}
} 

/* beej uses this function to get sockaddr ipv4/ipv6, so I will too */
void *get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}
	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int main(int argc, char *argv[])
{
	
//verify proper usage
if (argc >= 2 && !strcmp(argv[1], "-d")) {
               //printf("usage is proper. \n");
               syslog(LOG_INFO,"usage is proper. \n");
	       daemon_time = true;

               }
          /*     else {
       printf("usage invalid");
       exit(1);
       } */

  add_sigActions();

  int socketfd = get_socketfd();
  
  bind_func(socketfd);
 
  if (fork() != 0) {
	  exit(0);
  }

  //listen
  listen(socketfd, 10);
  
  //launch accepted connection thread
  pthread_t accept_thread;
  pthread_create(&accept_thread, NULL, accept_connections, &socketfd);

  while(!kill_system) {
	  //handle_clients(socketfd);
	  //handle_client_thread();
	  struct sockaddr_storage peer;
		socklen_t peer_addr_size = sizeof(peer);
		
		int newfd = accept(socketfd, (void *)&peer, &peer_addr_size);
		
		if (newfd < 0) {
			if (kill_system)
				//return NULL;
			exit(1);
		}
  }

  close(socketfd);
  remove(TMP_FILE);	       
}

/* get socket fd and socket function */
int get_socketfd()
{
	int yes = 1;
	syslog(LOG_DEBUG, "starting socket func \n");
	int socketfd;
	if ((socketfd = socket(AF_INET, SOCK_STREAM, 0)) == -1 ) {
          // perror("not good for your socket");
           exit(1);     
        }
	setsockopt(socketfd, IPPROTO_TCP, SO_REUSEADDR, &yes, sizeof(yes));
	syslog(LOG_DEBUG, "socket func complete \n");
	return socketfd;
}

/* bind function -- complete */
int bind_func(int socketfd)
{

struct addrinfo hints;
struct addrinfo *res;
memset(&hints, 0, sizeof(hints));   //make sure struct is empty
hints.ai_family = AF_INET;        // dont care ipv4 or ipv6
hints.ai_socktype = SOCK_STREAM;    // TCP
hints.ai_flags = AI_PASSIVE;        // fill IP for me, might not need
int status;
//int ret;

if ((status = getaddrinfo(NULL, "9000", &hints, &res)) != 0) {
                perror("damn, socket failed");
                exit(EXIT_FAILURE);
        }

if (bind(socketfd, res->ai_addr, res->ai_addrlen) == -1) {
                close(socketfd);
                perror("server bind issues smh");
		exit(1);
}       //return to here in case

freeaddrinfo(res);
syslog(LOG_DEBUG, "binding and getting adress complete \n");
//printf("binding and getaddrinfo complete. \n");
return 0;  //return back to null
}


/* sock stream to send and write */ 
void read_stream(int newfd)
{
FILE *tmpfile;
   tmpfile = fopen(TMP_FILE, "r"); //add b for binary?
   if (tmpfile == NULL) {
   perror("could no create and open to append");
   exit(1);
   }
   

   while(1) {
	   char char_val;
	   int c = fgetc(tmpfile);
	   if (c==EOF)
		   break;
	   char_val = (char)c;
	   send(newfd, &char_val, 1, 0);
	  
   }
  fclose(tmpfile);
 
} 
/* opening file to buffer and write */
char *buf_to_file(char *buf, int buf_len)
{
	FILE *tmpfile;
        tmpfile	= fopen(TMP_FILE, "a+");
	if (tmpfile == NULL) {
		perror("cannot open buf to file");
		exit(EXIT_FAILURE);
	}
	fwrite(buf, 1, buf_len, tmpfile);
	fclose(tmpfile);
	free(buf);
	return NULL;
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

