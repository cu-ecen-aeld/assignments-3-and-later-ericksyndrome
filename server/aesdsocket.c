#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <signal.h>
#include <stdbool.h>
#include <getopt.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <malloc.h>
#include <pthread.h>
#include <sys/queue.h>
#include <time.h>
#include <unistd.h> 


#include "../aesd-char-driver/aesd_ioctl.h" 

#define USE_AESD_CHAR_DEVICE 1


#define BUFFER_SIZE 1000000
#define PORT 9000

#ifdef USE_AESD_CHAR_DEVICE
#define DATA_FILE "/dev/aesdchar"
#else
#define DATA_FILE "/var/tmp/aesdsocketdata"
#endif


int sockfd = 0;
FILE *file_ptr = NULL;

// strcuts for threads and info
struct ThreadInfo {
    pthread_t thread_id;
    int client_socket;
    int thread_complete_flag;
    //struct sockaddr_storage client_thread_addr;
    struct sockaddr_in client_thread_addr;
    socklen_t sin_thread_size;
    SLIST_ENTRY(ThreadInfo) entries;
};

SLIST_HEAD(ThreadList, ThreadInfo) thread_list = SLIST_HEAD_INITIALIZER(thread_list);

pthread_mutex_t thread_list_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

// Calculate available heap size
size_t get_available_heap_size() {
    struct mallinfo mi = mallinfo();
    size_t available_heap = mi.fordblks;

    return available_heap;
}

// daemon functionality
void daemonize() {
    pid_t pid, sid;

    pid = fork();
    if (pid < 0) {
        exit(EXIT_FAILURE);
    }

    if (pid > 0) {
        exit(EXIT_SUCCESS); // Parent process exits
    }

    umask(0); // Set file permissions

    sid = setsid(); // Create a new session
    if (sid < 0) {
        exit(EXIT_FAILURE);
    }

    // Close standard file descriptors
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
}

// cleanup function
void cleanup_threads(pthread_t timer_thread_id) {
    struct ThreadInfo *info, *tmp;
    pthread_mutex_lock(&thread_list_mutex);
    
    info = SLIST_FIRST(&thread_list);
    while (info != NULL) {
        tmp = SLIST_NEXT(info, entries);
        if (info->thread_complete_flag) {
            //printf("Removing thread %lu\n", info->thread_id);
            close(info->client_socket);
            pthread_join(info->thread_id, NULL);
            SLIST_REMOVE(&thread_list, info, ThreadInfo, entries);
            free(info);
            info = NULL;
        }
        info = tmp;
    }

    pthread_mutex_unlock(&thread_list_mutex);

}

void add_timestamp_to_file(FILE *file) {
    time_t current_time;
    struct tm *time_info;
    char timestamp[128];

    time(&current_time);
    time_info = localtime(&current_time);

    strftime(timestamp, sizeof(timestamp), "timestamp:%a, %d %b %Y %H:%M:%S %z", time_info);

    pthread_mutex_lock(&log_mutex);
    fprintf(file, "%s\n", timestamp);
    pthread_mutex_unlock(&log_mutex);
    //printf("%s\n", timestamp);

  
}

// Thread that writes timestamp to file every 10 seconds
//void *timer_thread_function(void *arg) {
void *timer_thread_function(void *arg) {
    FILE* file = (FILE *)arg;
    //printf("Timer thread is starting ... \n");

    while(1) {
        add_timestamp_to_file(file);
        sleep(10);
    }
    return NULL;

}

void *handle_client_connection(void *arg) {
    struct ThreadInfo *info = (struct ThreadInfo *)arg;
    //ioctl tracker
    bool ioctrl_tracker = false;
    int client_sock = info->client_socket;
    struct sockaddr_in client_addr= info->client_thread_addr;
    //socklen_t sin_thread_size_local = info->sin_thread_size;
    char client_ip[INET_ADDRSTRLEN];
     struct aesd_seekto seek_data_from_server;
    // Receive data and append to file
    file_ptr = fopen(DATA_FILE, "w+");
    if (file_ptr == NULL) {
        perror("fopen");
        close(client_sock);
    }
    
    
    pthread_mutex_lock(&log_mutex);
    char *buffer = (char*)malloc(BUFFER_SIZE * sizeof(char));
    memset(buffer, 0, BUFFER_SIZE*sizeof(char));
    size_t available_heap = get_available_heap_size();
    pthread_mutex_unlock(&log_mutex);
    
    // Log the accepted connection to syslog with client IP address
    inet_ntop(AF_INET, &(client_addr.sin_addr), client_ip, INET_ADDRSTRLEN);
    syslog(LOG_INFO, "Accepted connection from %s", client_ip);

    ssize_t total_received = 0;
    ssize_t bytes_received;
    char *ptr = NULL;
    unsigned int X = 0;
    unsigned int Y = 0;
    int eon = 0;
    pthread_mutex_lock(&log_mutex);
    
    while ((bytes_received = recv(client_sock, buffer, BUFFER_SIZE - 1, 0)) > 0) {
        if ((total_received > available_heap)) {
            syslog(LOG_INFO, "Too large for available heap, have to closie connection");
            fclose(file_ptr);
            close(client_sock);
            free(buffer);
            buffer = NULL;
            return NULL;
        }

        ptr = strchr(buffer, '\n');
        if (ptr != NULL) {
            break;
        }
        total_received += bytes_received;
    }
    
    char* start = strstr(buffer, "AESDCHAR_IOCSEEKTO:");
    if (start != NULL) {
		ioctrl_tracker = true;
		sscanf(start, "AESDCHAR_IOCSEEKTO:%u,%u", &seek_data_from_server.write_cmd, &seek_data_from_server.write_cmd_offset);
		char* end = strchr(start, '\n');
		if (end != NULL) {
			end++; //moving past the newline here
		} else {
			end = start + strlen("AESDCHAR_IOCSEEKTO:");  // just move past the command if no newline is found
		}
	size_t bytes_move = buffer + total_received - end;
    	char* dest = start;
    	char* src = end;
    	while (*src) {
    		*dest = *src;
    		dest++;
    		src++;
    	}
    	*dest = '\0';  // Null-terminate the string
    	total_received -= (end - start);  // adjust the total_received count
    	*start = '\0';
    	*end = '\0';
    	*src = '\0';
    }
    	
    fprintf(file_ptr, "%s", buffer);
    fseek(file_ptr, 0, SEEK_END);
    long file_size = ftell(file_ptr);
    fseek(file_ptr, 0, SEEK_SET);
    // Allocate memory for the file contents (+1 for null-terminator)
    char* file_contents = (char*)malloc(file_size + 1);
    if (!file_contents) {
    		perror("malloc");
    		pthread_mutex_unlock(&log_mutex);
    		free(buffer);
    		buffer = NULL;
    		return NULL;
    	}
    	else{
    		memset(file_contents, 0, sizeof(file_contents));
    	}

    
        if (ioctrl_tracker == true){
        syslog(LOG_INFO, "Encoded seek data: write_cmd = %u, write_cmd_offset = %u", seek_data_from_server.write_cmd, seek_data_from_server.write_cmd_offset);
    	int file_descriptor = fileno(file_ptr);
	if (file_descriptor == -1) {
    		// Handle the error, e.g., print to syslog and exit
    		syslog(LOG_ERR, "Error getting file descriptor: %m");
    		fclose(file_ptr); // Close the file if it's open
    		exit(EXIT_FAILURE);
	}
	// Get the ioctl command number
    	unsigned int ioctlCommand = _IOC_NR(AESDCHAR_IOCSEEKTO);
    	// Get the ioctl command type
    	unsigned int ioctlType = _IOC_TYPE(AESDCHAR_IOCSEEKTO);
    	// Log the ioctl command type to syslog
    	syslog(LOG_INFO, "IOCTL Command Type: %u", ioctlType);
    	// Log the ioctl command number to syslog
    	syslog(LOG_INFO, "IOCTL Command Number: %u", ioctlCommand);
	syslog(LOG_INFO, "ioctl command: %ld", AESDCHAR_IOCSEEKTO);
	syslog(LOG_INFO, "launching ioctl call..");
	ioctlCommand = 0;
	ioctlType = 0;
    	if(ioctl(file_descriptor, AESDCHAR_IOCSEEKTO, &seek_data_from_server) == -1) {
    	  //if(ioctl(file_descriptor, AESDCHAR_IOCSEEKTO, &seek_data_from_server) == -1) {
    		syslog(LOG_ERR, "ioctl exploded");
    		//syslog(LOG_ERR, "ioctl failed: %s", strerror(errno));
    		syslog(LOG_ERR, "ioctl failed: %s (errno=%d)", strerror(errno), errno);
    	}
	else{
		long position = ftell(file_ptr);
		syslog(LOG_INFO, "Current file position after ioctl: %ld", position);
		syslog(LOG_INFO, "ioctrl_tracker true, write_cmd: %u, write_cmd_offset: %u", seek_data_from_server.write_cmd, seek_data_from_server.write_cmd_offset);
	}
	file_descriptor = 0;
	ioctrl_tracker == false;
    }
    else
    {
    	syslog(LOG_INFO, "ioctrl_tracker false, write_cmd: %u, write_cmd_offset: %u", seek_data_from_server.write_cmd, seek_data_from_server.write_cmd_offset);
    }

    size_t bytes_read;
    
    while ((bytes_read = fread(file_contents, 1, file_size, file_ptr)) > 0) {
        ssize_t bytes_sent = send(client_sock, file_contents, bytes_read, 0);
        //printf("Sent %zu bytes to client.\n", bytes_sent);
        if (bytes_sent == -1) {
            perror("send");
            pthread_mutex_unlock(&log_mutex);
            free(buffer);
            buffer = NULL;
            free(file_contents);
            file_contents = NULL;
            break;
        }
    }
 
    pthread_mutex_unlock(&log_mutex);


    // Log closed connection to syslog
    syslog(LOG_INFO, "Closed connection from %s", client_ip);
    close(client_sock);
    free(buffer);
    buffer = NULL;
    free(file_contents);
    file_contents = NULL;
    info->thread_complete_flag = 1;
    pthread_exit(NULL);
}

void sigint_handler(int signum) {
    syslog(LOG_INFO, "Caught signal, exiting");
    fclose(file_ptr);
    close(sockfd);
    unlink(DATA_FILE); // Delete the file
    closelog();
    exit(EXIT_SUCCESS);
}

int main(int argc, char *argv[]) {
    int client_sock;
    struct sockaddr_in server_addr, client_addr;


    openlog("aesdsocket_server", LOG_CONS | LOG_PID, LOG_USER);

    bool daemon_mode = false;

    char *ptr = NULL;
    
    // Parse command-line arguments
    int opt;
    while ((opt = getopt(argc, argv, "d")) != -1) {
        switch (opt) {
            case 'd':
                daemon_mode = true;
                break;
            default:
                fprintf(stderr, "Usage: %s [-d]\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    // Daemonize if in daemon mode
    if (daemon_mode) {
        daemonize();
    }


    // Create a socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

	int enable = 1;
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
    		perror("setsockopt(SO_REUSEADDR) failed");
	}


    // Set up the server address structure
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    // Bind the socket to the specified PORT
    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        perror("bind");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // Listen for incoming connections
    if (listen(sockfd, 5) == -1) {
        perror("listen");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    //printf("Listening for incoming connections...\n");

    socklen_t client_addr_len = sizeof(client_addr);
    char client_ip[INET_ADDRSTRLEN];

    // Set up the signal handler for SIGINT (Ctrl+C) and SIGTERM
    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);
    
      
    /*
    pthread_t timer_thread;
    if(pthread_create(&timer_thread, NULL, timer_thread_function, file_ptr)) {
        perror("Timer thread create");
    }
    */
    while (1) {
        // Accept a connection
        int client_sock = accept(sockfd, (struct sockaddr *)&client_addr, &client_addr_len);
        if (client_sock == -1) {
            perror("accept");
            continue;
        }
        
	struct ThreadInfo *info = (struct ThreadInfo *)malloc(sizeof(struct ThreadInfo));
        if (info == NULL) {
            perror("Thread memory allocation error");
            close(client_sock);
            continue;
        }
        info->client_socket = client_sock;
        info->sin_thread_size = sizeof(client_addr);
        info->client_thread_addr = client_addr;
        info->thread_complete_flag = 0;
	
	pthread_create(&info->thread_id, NULL, handle_client_connection, info);

        // Insert the thread's info into the linked list
        pthread_mutex_lock(&thread_list_mutex);
        SLIST_INSERT_HEAD(&thread_list, info, entries);
        pthread_mutex_unlock(&thread_list_mutex);
        
	//cleanup_threads(timer_thread);
    }

    return 0;
}
