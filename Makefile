KDIR ?= /root/trees/final/
KPATCH_GENERATED ?= kpatch-generated.o
KMOD_DIR ?= /root/powerpc-kpatch/kmod
OBJ_ORIG = /root/trees/final/fs/proc/ocmdline.o
OBJ_PATCHED = /root/trees/final/fs/proc/cmdline.o
VMLINUX_ORIG = /root/trees/final/vmlinux

.PHONY: clean

all:
	$(MAKE) -C elf-diff-copy
	elf-diff-copy/elf-diff-copy $(OBJ_ORIG) $(OBJ_PATCHED) -v $(VMLINUX_ORIG) -o $(KMOD_DIR)/$(KPATCH_GENERATED)

clean:
	$(MAKE) -C elf-diff-copy clean
