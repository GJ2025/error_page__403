ccflags-y := -I$(src)
obj-m := all.o
all-objs := hello.o ring.o
KERNELDIR ?= /lib/modules/$(shell uname -r)/build  
PWD := $(shell pwd)  

default:  
	$(MAKE)  -C $(KERNELDIR) M=$(PWD) modules  

clean:  
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean  
