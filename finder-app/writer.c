#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <stdarg.h>
#include <stdlib.h>
#include <fcntl.h>

int main(int argc, char *argv[])
{
        FILE* fd;        	//FILE is stdlib variable
	
	char *writefile = argv[1];    // first arg passed in aka writefile
        char *writestr = argv[2];     // next arg will be a string

 

	if ( argc < 3 ) {
	
	printf("not enough arguements\n");
	
	openlog(NULL, 0, LOG_USER);
        syslog(LOG_DEBUG, "Writing %s to %s \n",writestr,writefile);
        closelog();
	return 1;
	}
    

        fd = fopen(writefile, "w+");        //creates writefile and gives perm to w   
	fputs(writestr, fd);        //writes writestr into fd
        fclose(fd);                 //closes writefile

	return 0;
}	



