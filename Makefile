.PHONY: clean

all:
	$(MAKE) -C elf-diff-copy

clean:
	$(MAKE) -C elf-diff-copy clean
