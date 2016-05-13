#include <argp.h>
#include <gelf.h>
#include <error.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <elfutils/elf-knowledge.h>

/*
 * Macros
 */
#define log_d(format, ...)	\
({				\
    \
	if (args.debug)		\
		printf("%s:%d " format, __FUNCTION__, __LINE__, ##__VA_ARGS__);				\
	else			\
	  do { }  while(0);	\
})

#define log_ok(format, ...) \
        printf("" format, ##__VA_ARGS__);
#define ERROR(format, ...) \
	error(1, 0, "%s: %d: " format, __FUNCTION__, __LINE__, ##__VA_ARGS__)


#define elfname(elf) \
({									\
	const char *name = NULL;					\
	if (elf == elf1)						\
		name = args.args[0];					\
	else if (elf == elf2)						\
		name = args.args[1];					\
	else if (elf == elfv)						\
		name = args.vmlinux;					\
	else if (elf == elfo)						\
		name = args.outfile;					\
	name;								\
})

#define ELF_ERROR(elf, str) \
	error(1, 0, "%s:%d: " str " failed for '%s': %s", __FUNCTION__, __LINE__, elfname(elf), elf_errmsg(-1))

#define DIFF_FATAL(format, ...) \
({ \
	printf("%s:%d: " format "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__); \
	error(2, 0, "unreconcilable difference"); \
})

/*
 * List manipulation macros.
 */
#define list_add(head, new) \
({ \
	typeof(new) p = head; \
	if (!head) \
		head = new; \
	else { \
		while (p->next) \
			p = p->next; \
		p->next = new; \
	} \
})

/*
 * Structure definitions.
 */
struct arguments {
	char *args[2];
	char *vmlinux;
	char *outfile;
	bool debug;
};

struct section {
	struct section *next;
	Elf_Scn *sec;
	GElf_Shdr sh;
	Elf_Data *data;
	char *name;
	struct section *twin, *twino;
	size_t index;
	int diff;
};

/*
 * Global declarations.
 */
struct arguments args;
Elf *elf1, *elf2, *elfv, *elfo;
struct section *secs1, *secs2;

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
		case 'd':
			arguments->debug = true;
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
	{NULL, 'd',      0, 0, "debug"},
	{},
};

static struct argp argp = {
	.options	= options,
	.parser		= parse_opt,
	.args_doc	= "FILE1.o FILE2.o",
	.doc		= "Compare two kernel .o files and generate an object containing the changed and/or new functions.",
};

/*
 * Helper functions
 */
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

void check_elf_header(GElf_Ehdr *eh1, GElf_Ehdr *eh2)
{
	if (memcmp(eh1->e_ident, eh2->e_ident, EI_NIDENT)	||
	    eh1->e_type		!= eh2->e_type			||
	    eh1->e_machine	!= eh2->e_machine		||
	    eh1->e_version	!= eh2->e_version		||
	    eh1->e_entry	!= eh2->e_entry			||
	    eh1->e_phoff	!= eh2->e_phoff			||
	    eh1->e_flags	!= eh2->e_flags			||
	    eh1->e_ehsize	!= eh2->e_ehsize		||
	    eh1->e_phentsize	!= eh2->e_phentsize		||
	    eh1->e_shentsize	!= eh2->e_shentsize)
		DIFF_FATAL("ELF headers differ");
	log_ok("%s\t[PASSED]\n", "Elf Header compare");
}

void check_for_program_header()
{
	size_t phnum1, phnum2;

	if (elf_getphdrnum(elf1, &phnum1))
		ELF_ERROR(elf1, "elf_getphdrnum");
	log_ok("%s %s\t[PASSED]\n", "Get Program Header for ", args.args[0]);

	if (elf_getphdrnum(elf2, &phnum2))
		ELF_ERROR(elf2, "elf_getphdrnum");
	log_ok("%s %s\t[PASSED]\n", "Get Program Header for ", args.args[1]);

	if (phnum1 || phnum2)
		DIFF_FATAL("program header counts are nonzero");
	log_d("%s\t[PASSED]\n", "no program headers");
}

void about_elf(GElf_Ehdr *elf)
{
	if (elf->e_ident[EI_CLASS] == 2)
		log_d ("Is a 64 bit object\n");
	if (elf->e_ident[EI_DATA] == 1)
		log_d ("Is a Little Endian\n");
		log_d ("Is ABI version %d\n", elf->e_ident[EI_ABIVERSION]);
}

void init_section_list(Elf *elf, struct section **secs)
{
	Elf_Scn *scn;
	struct section *sec;
	size_t shstrndx;

	if (elf_getshdrstrndx(elf, &shstrndx))
		ELF_ERROR(elf, "elf_getshdrstrndx");

	scn = NULL;

	log_d("Sections found \n");
	while ((scn = elf_nextscn(elf, scn))) {

		sec = malloc(sizeof(*sec));
		memset(sec, 0, sizeof(*sec));
		sec->sec = scn;

		if (!gelf_getshdr(scn, &sec->sh))
			ELF_ERROR(elf, "gelf_getshdr");

		sec->name = elf_strptr(elf, shstrndx, sec->sh.sh_name);
		if (!sec->name)
			ELF_ERROR(elf, "elf_strptr");

		log_d("section %s\n", sec->name);
		sec->data = NULL;
		sec->data = elf_getdata(sec->sec, sec->data);
		if (!sec->data)
			ELF_ERROR(elf, "elf_getdata");
		/* TODO: check for any remaining data? */

		sec->index = elf_ndxscn(sec->sec);

		list_add(*secs, sec);
	}
}

int main(int argc, char *argv[])
{
	int fd1, fd2;
	GElf_Ehdr eh1, eh2;

	argp_parse(&argp, argc, argv, 0, NULL, &args);

	/*
	 * Open ELF object files.
	 */
	elf_version(EV_CURRENT);
	elf1 = elf_open(args.args[0], &fd1);
	elf2 = elf_open(args.args[1], &fd2);

	/*
	 * Read the ELF header of object files.
	 */
	if (!gelf_getehdr(elf1, &eh1))
		ELF_ERROR(elf1, "gelf_getehdr");
	log_ok("%s %s\t[PASSED]\n", "Get Elf Header for ", args.args[0]);

	if (!gelf_getehdr(elf2, &eh2))
		ELF_ERROR(elf2, "gelf_getehdr");
	log_ok("%s %s\t[PASSED]\n", "Get Elf Header for ", args.args[1]);

	/*
	 * Compare the ELF headers of object files.
	 */
	check_elf_header(&eh1, &eh2);

	/*
	 * Check if any of the object file has program headers,
	 * object files should not be having one.
	 */
	check_for_program_header();

	/*
	 * Print information about elf.
	 */
	about_elf(&eh1);
	about_elf(&eh2);

	/*
	 * Read all the sections and add them
         * into linked list.
	 */
	init_section_list(elf1, &secs1);
	log_ok("%s %s\t[PASSED]\n", "Section list created for ", args.args[0]);
	return (0);
}
