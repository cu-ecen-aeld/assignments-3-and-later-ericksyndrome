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

#define _BSD_SOURCE
#define SERVER_PORT     ("9000")
#define MAXDATASIZE     (1024)
#define TMP_FILE        ("/var/tmp/aesdsocketdata")

static bool daemon_time = false;
static bool kill_system = false;

/**** declaring functions beforehand ****/
void handle_clients(int socketfd);
char *buf_to_file(char *buf, int buf_len);
void read_stream(int newfd);
int get_socketfd();
int bind_func(int socketfd);

void handle_sig(int sig)
{
        switch(sig) {
                case SIGINT:
                        syslog(LOG_INFO, "signal caught");
                        printf("caught signal sigint\n");
                        exit(0);
                case SIGTERM:
                        syslog(LOG_INFO, "sig caught");
                        printf("caught signal sigterm\n");
                        exit(0);
                default:
                       syslog(LOG_DEBUG, "unknown signal");
                       exit(1);
        }
       // close(socketfd);
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
if ((argc == 2) && (strcmp(argv[1], "-d")) == 0) {
               printf("usage is proper. \n");
	       daemon_time = true;

               }
               else {
       printf("usage invalid");
       exit(1);
       }
  //signal handler
  signal(SIGTERM, handle_sig);
  signal(SIGINT, handle_sig);


  int socketfd = get_socketfd();

  bind_func(socketfd);

  if (fork() != 0) {
	  exit(0);
  }

  //listen
  listen(socketfd, 10);

  while(!kill_system) {
	  handle_clients(socketfd);
  }

  close(socketfd);
  remove(TMP_FILE);	       
}

/* accept clients and buffer */
void handle_clients(int socketfd)
{

//some info for the peer struct before accept()
struct sockaddr_storage peer;
socklen_t peer_addr_size;
peer_addr_size = sizeof(peer);
int newfd;
char client[INET6_ADDRSTRLEN];  //string for clients IP
//accepting
   if ((newfd = accept(socketfd, (void *)&peer, &peer_addr_size) <0)) {
                perror("did not accept");
                syslog(LOG_DEBUG, "could not accept. \n");
		exit(1);
                } //replaced struct sockaddr
//function to convert ip to something printable
memset(client, 0, sizeof(client));
inet_ntop(peer.ss_family, get_in_addr((struct sockaddr *)&peer), client, sizeof(client));
printf("server got connection from: %s \n", client);
syslog(LOG_INFO, "Accepted connection from: %s \n", client);

char *buf = NULL;
int buf_size;
int buf_len;
ssize_t bytes_rx;

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


int get_socketfd()
{
	int yes = 1;
	syslog(LOG_DEBUG, "starting socket func \n");
	int socketfd;
	if ((socketfd = socket(AF_INET, SOCK_STREAM, 0))<0) {
           perror("not good for your socket");
           exit(1);     
        }
	if (setsockopt(socketfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes))<0){
                perror("sockopt man");
                exit(EXIT_FAILURE);
        }
	syslog(LOG_DEBUG, "socket func complete \n");
	return socketfd;
}

/* bind function */
int bind_func(int socketfd)
{
int status;
struct addrinfo hints;
struct addrinfo *res;
memset(&hints, 0, sizeof(hints));   //make sure struct is empty
hints.ai_family = AF_UNSPEC;        // dont care ipv4 or ipv6
hints.ai_socktype = SOCK_STREAM;    // TCP
hints.ai_flags = AI_PASSIVE;        // fill IP for me, might not need

if ((status = getaddrinfo(NULL, "9000", &hints, &res)) != 0) {
                perror("damn, socket failed");
                exit(EXIT_FAILURE);
        }

if (bind(socketfd, res->ai_addr, res->ai_addrlen) == -1) {
                close(socketfd);
                perror("server bind issues smh");
		exit(1);
}
freeaddrinfo(res);
syslog(LOG_DEBUG, "binding and getting adress complete \n");
printf("binding and getaddrinfo complete. \n");
return 0;
}

/* sock stream to send and write */ 
void read_stream(int newfd)
{
FILE *tmpfile;
   tmpfile = fopen(TMP_FILE, "rb"); //add b for binary?
   if (tmpfile == NULL) {
   perror("could no create and open to append");
   exit(EXIT_FAILURE);
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

char *buf_to_file(char *buf, int buf_len)
{
	FILE *tmpfile;
        tmpfile	= fopen(TMP_FILE, "ab");
	if (tmpfile == NULL) {
		perror("cannot open buf to file");
		exit(EXIT_FAILURE);
	}
	fwrite(buf, 1, buf_len, tmpfile);
	fclose(tmpfile);
	free(buf);
	return 0;
}



