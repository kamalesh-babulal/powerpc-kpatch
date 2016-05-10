#include <argp.h>
#include <gelf.h>
#include <error.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <elfutils/elf-knowledge.h>

#ifdef DEBUG
#define log_d(format, ...) \
        printf("" format, ##__VA_ARGS__);
#else
#define log_d(format, ...) { };
#endif

struct arguments {
	char *args[2];
	char *vmlinux;
	char *outfile;
};

struct arguments args;
Elf *elf1, *elf2;

error_t parse_opt(int key, char *arg, struct argp_state *state)
{
	struct arguments *arguments = state->input;

	switch (key) {
		case 'v':
			arguments->vmlinux = arg;
			break;
		case 'o':
			arguments->outfile = arg;
			break;
		case ARGP_KEY_ARG:
			if (state->arg_num > 1)
				argp_usage(state);
			arguments->args[state->arg_num] = arg;
			break;
		case ARGP_KEY_END:
			if (!arguments->args[0] || !arguments->args[1] ||
			    !arguments->vmlinux || !arguments->outfile)
				argp_usage(state);
			break;
		default:
			return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

static const struct argp_option options[] = {
	{NULL, 'v', "file", 0, "original vmlinux"},
	{NULL, 'o', "file", 0, "output file"},
	{},
};

static struct argp argp = {
	.options	= options,
	.parser		= parse_opt,
	.args_doc	= "FILE1.o FILE2.o",
	.doc		= "Compare two kernel .o files and generate an object containing the changed and/or new functions.",
};

static Elf *elf_open(const char *name, int *fd)
{
	Elf *elf;

	*fd = open(name, O_RDONLY);
	if (*fd == -1)
		error(1, errno, "open of '%s' failed", name);

	elf = elf_begin(*fd, ELF_C_READ_MMAP, NULL);
	if (!elf)
		error(1, 0, "elf_begin failed for '%s': %s", name,
		      elf_errmsg(-1));

	log_d("%s %s\t\t[PASSED]\n", __FUNCTION__, name);
	return elf;
}

int main(int argc, char *argv[])
{
	int fd1, fd2;

	argp_parse(&argp, argc, argv, 0, NULL, &args);

	/*
	 * Open ELF object files.
	 */
	elf_version(EV_CURRENT);
	elf1 = elf_open(args.args[0], &fd1);
	elf2 = elf_open(args.args[1], &fd2);

	return (0);
}
