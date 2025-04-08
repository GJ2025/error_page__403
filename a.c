#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>  
#include <unistd.h>
#include <string.h>
#include "ring.h"

int main() {
    const char *filename = "/proc/simple_int";
    int fd;
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
    return 0;
}

