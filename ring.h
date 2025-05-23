
typedef struct ips{
	u32 saddr;
	u32 daddr;
}ips_t;

typedef struct ring{
	long head;
	long tail;
	long mask;
	ips_t ips[512];
}ring_t;

typedef struct ring_fd{
	int fd;
	int ret;
}ring_fd_t;


void ring_init(void);
void ring_exit(void);
void ring_push(u32 saddr, u32 daddr);
