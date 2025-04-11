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

#include <sys/epoll.h>

void print_ip(unsigned int ip) {
    unsigned int net_ip = htonl(ip);

    unsigned char bytes[4];
    bytes[0] = (net_ip >> 24) & 0xFF;  // 第一个字节
    bytes[1] = (net_ip >> 16) & 0xFF;  // 第二个字节
    bytes[2] = (net_ip >> 8)  & 0xFF;  // 第三个字节
    bytes[3] = net_ip & 0xFF;           // 第四个字节

    printf("%u.%u.%u.%u", bytes[0], bytes[1], bytes[2], bytes[3]);
}


int check_ring(int fd, ring_t *ring) {
    int epoll_fd;
    long id = 0;
    struct epoll_event ev, evs[1];

    epoll_fd = epoll_create1(0);
    if (epoll_fd == -1) {
        perror("epoll_create1");
        close(fd);
        return 1;
    }

    ev.events = EPOLLIN;
    ev.data.fd = fd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev) == -1) {
        perror("epoll_ctl");
        close(fd);
        close(epoll_fd);
        return 1;
    }

    while (1) {
        int n = epoll_wait(epoll_fd, evs, 1, 3);
        if (n == -1) {
            perror("epoll_wait");
            break;
        }

        if (n==1 && evs[0].events & EPOLLIN) {
                printf("%ld: <head:tail --%ld,%ld>, ring.mask(%0x)\n", id++, ring->head, ring->tail, ring->mask);
                if (ring->head != ring->tail){
			printf("from:");
                        print_ip(ring->ips[ring->head & ring->mask].saddr);
			printf("  to:");
                        print_ip(ring->ips[ring->head & ring->mask].daddr);
			printf("\n");

                        ring->head++;
                }
	}
    }

    close(fd);
    close(epoll_fd);
    return 0;
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
	
		check_ring(ring_fd.fd, ring);
	
	}


    return 0;
}

