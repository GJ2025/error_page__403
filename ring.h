
typedef struct ring{
	long head;
	long tail;
	long mask;
	long ips[512];
}ring_t;

typedef struct ring_fd{
	int fd;
	int ret;
}ring_fd_t;


void ring_init(void);
void ring_exit(void);
