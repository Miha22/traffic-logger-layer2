MODULE_NAME := traffic_logger
BUILD_DIR := build

KERNEL_DIR := /lib/modules/$(shell uname -r)/build
EXTRA_CFLAGS := -I$(PWD)/include

obj-m += src/$(MODULE_NAME).o

all: build_dir kernel_module

build_dir:
	mkdir -p $(BUILD_DIR)

kernel_module:
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) EXTRA_CFLAGS="$(EXTRA_CFLAGS)" modules
	mv src/$(MODULE_NAME).ko $(BUILD_DIR)/

clean:
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) clean
	rm -rf $(BUILD_DIR)