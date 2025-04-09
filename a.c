#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>  
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <stdint.h>
#include <arpa/inet.h>
#define  u32 uint32_t
#include "ring.h"

void print_ip(unsigned int ip) {
    unsigned int net_ip = htonl(ip);

    unsigned char bytes[4];
    bytes[0] = (net_ip >> 24) & 0xFF;  // 第一个字节
    bytes[1] = (net_ip >> 16) & 0xFF;  // 第二个字节
    bytes[2] = (net_ip >> 8)  & 0xFF;  // 第三个字节
    bytes[3] = net_ip & 0xFF;           // 第四个字节

    printf("%u.%u.%u.%u\n", bytes[0], bytes[1], bytes[2], bytes[3]);
}

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
		printf("ring.head(%ld), ring.tail(%ld), ring.mask(%0x)\n", ring->head, ring->tail, ring->mask);
		if (ring->head != ring->tail){
			print_ip(ring->ips[ring->head & ring->mask].saddr);	
			print_ip(ring->ips[ring->head & ring->mask].daddr);

			ring->head++;	
		}
	}


    return 0;
}

