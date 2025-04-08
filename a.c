#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>  
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include "ring.h"

int main() {
    const char *filename = "/proc/simple_int";
    int fd;
    ring_t *ring = NULL;
    ring_fd_t ring_fd;

    memset(&ring_fd, 0, sizeof(ring_fd));

    fd = open(filename, O_RDONLY);
    if (fd == -1) {
        perror("open failed"); 
        return 1;
    }


	read(fd, &ring_fd, sizeof(ring_fd));

	printf("abc: %d\n", ring_fd.fd);

    close(fd); 


	ring = (ring_t *)mmap(NULL, sizeof(ring_t), PROT_READ | PROT_WRITE, MAP_SHARED, ring_fd.fd, 0);
	if (ring == NULL){
		printf("error:%s\n", strerror(errno));
	}else{
		printf("ring.mask(%0x)\n", ring->mask);
	}


    return 0;
}

