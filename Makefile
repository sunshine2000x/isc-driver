# SPDX-License-Identifier: GPL-2.0-only
ifeq ($(KERNELRELEASE),)
KDIR := /lib/modules/$(shell uname -r)/build
OUT := $(PWD)/out

default: prepare
	$(MAKE) -C $(KDIR) src=$(PWD) M=$(OUT)
clean:
	@rm -rf $(OUT)
	@echo "$(MAKE) $@ done."
prepare:
	@mkdir -p $(OUT)/src $(OUT)/sample
	@ln -sf $(PWD)/Makefile $(OUT)
install:
	sudo insmod $(OUT)/src/isc.ko
	sudo insmod $(OUT)/sample/sample.ko
remove:
	sudo rmmod sample
	sudo rmmod isc
else
	ccflags-y := -I$(PWD)/include -Wall -Werror
	obj-m := src/isc.o
	obj-m += sample/sample.o
endif
