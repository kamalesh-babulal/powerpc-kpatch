KDIR ?= /root/trees/final/
KPATCH_GENERATED ?= kpatch-generated.o
KMOD_DIR ?= /root/powerpc-kpatch/kmod
OBJ_ORIG = /root/trees/final/fs/proc/ocmdline.o
OBJ_PATCHED = /root/trees/final/fs/proc/cmdline.o
VMLINUX_ORIG = /root/trees/final/vmlinux
SRC_PATH=/root/powerpc-kpatch

all:
	$(MAKE) -C elf-diff-copy
	elf-diff-copy/elf-diff-copy $(OBJ_ORIG) $(OBJ_PATCHED) -v $(VMLINUX_ORIG) -o $(KMOD_DIR)/$(KPATCH_GENERATED)

.PHONY: clean
clean:
	$(MAKE) -C elf-diff-copy clean
	rm -f TAGS cscope.*

.PHONY: TAGS
TAGS:
	rm -f $@
	find "$(SRC_PATH)" -name '*.[hc]' -exec etags --append {} +

cscope:
	rm -f "$(SRC_PATH)"/cscope.*
	find "$(SRC_PATH)/" -name "*.[chsS]" -print | sed 's,^\./,,' > "$(SRC_PATH)/cscope.files"
	cscope -b -i"$(SRC_PATH)/cscope.files"
