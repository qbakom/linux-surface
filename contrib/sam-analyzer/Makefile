# Makefile for SAM Packet Analyzer Kernel Module

obj-m += sam_analyzer.o

KVERSION := $(shell uname -r)
KDIR := /lib/modules/$(KVERSION)/build
PWD := $(shell pwd)

# Compiler flags for additional checks
ccflags-y := -Wall -Wextra -Werror
ccflags-y += -std=gnu99 -Wno-declaration-after-statement

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f modules.order Module.symvers

install:
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install
	depmod -a

uninstall:
	rm -f /lib/modules/$(KVERSION)/extra/sam_analyzer.ko
	depmod -a

# Development targets
check:
	@echo "Running sparse static analysis..."
	$(MAKE) -C $(KDIR) M=$(PWD) C=2 CF="-D__CHECK_ENDIAN__" modules

debug:
	$(MAKE) -C $(KDIR) M=$(PWD) ccflags-y+="-DDEBUG -g" modules

load:
	sudo insmod sam_analyzer.ko

unload:
	sudo rmmod sam_analyzer

reload: unload load

test:
	@echo "Testing module functionality..."
	@sudo dmesg | tail -n 20
	@echo "Checking debugfs entries..."
	@ls -la /sys/kernel/debug/sam_analyzer/

.PHONY: all clean install uninstall check debug load unload reload test
