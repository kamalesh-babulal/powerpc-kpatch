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

struct symbol {
	struct symbol *next;
	GElf_Sym sym;
	char *name;
	struct symbol *twin, *twinv, *twino;
	struct section *sec;
	size_t index;
	int type;
	int bind;
	int diff;
};

struct rela {
	struct rela *next;
	GElf_Rela rela;
	struct rela *twin;
	struct section *rela_sec, *dest_sec;
	struct symbol *src_sym, *dest_sym;
	/* TODO: get right signed and # of bits for all these vars */
	long dest_off, src_off;
	const char *src_str;
	unsigned int type;
	struct kpatch_rela *kpatch_rela;
};

/*
 * Global declarations.
 */
struct arguments args;
Elf *elf1, *elf2, *elfv, *elfo;
struct section *secs1, *secs2;
struct symbol *syms1, *syms2;
struct rela *relas1, *relas2;

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
 * Character array's to print more human readable
 * ELF information.
 */
char *symbol_type_char[] = {
		"None",	"Object", "Function", "Section",  "File",
		"Common", " ", " ", " ", " ", " ", " ", " ", " ",
		" "};

char *symbol_bind_char[] = {
/* 0  */	"STB_LOCAL", "STB_GLOBAL", "STB_WEAK", "STB_NUM",
/* 4  */	" ", " ", " ", " ", " ", " ",
/* 10 */	"STB_LOOS || STB_GNU_UNIQUE", " ", "STB_HIOS",
/* 13 */	"STB_LOPROC", " ", "STB_HIPROC"};

/*
 * Helper functions
 */
struct section *find_section_by_index(struct section *secs, unsigned int index)
{
	struct section *sec;

	for (sec = secs; sec && sec->index != index; sec = sec->next)
		;

	return sec;
}

struct section *find_section_by_name(struct section *secs, const char *name)
{
	struct section *sec;

	for (sec = secs; sec && strcmp(sec->name, name); sec = sec->next)
		;

	return sec;
}

struct symbol *find_symbol_by_offset(struct symbol *syms, struct section *sec,
				     int off, long *sym_off)
{
	struct symbol *sym;

	for (sym = syms; sym; sym = sym->next)
		if (sym->sec == sec && off >= sym->sym.st_value &&
		    off < sym->sym.st_value + sym->sym.st_size) {
			*sym_off = off - sym->sym.st_value;
			return sym;
		}

	return NULL;
}

struct symbol *find_symbol_by_index(struct symbol *syms, size_t index)
{
	struct symbol *sym;

	for (sym = syms; sym && sym->index != index; sym = sym->next)
		;

	return sym;
}

struct symbol *find_symbol_by_name(struct symbol *syms, const char *name)
{
	struct symbol *sym;

	for (sym = syms; sym && strcmp(sym->name, name); sym = sym->next)
		;

	return sym;
}

/*
 * Core Functions.
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

void
init_symbol_list(Elf *elf, struct section *secs, struct symbol **syms)
{
	struct section *sec;
	struct symbol *sym = NULL, *last_sym = NULL;
	int count, i;

	sec = find_section_by_name(secs, ".symtab");
	if (!sec)
		ERROR("missing symbol table");

	/*  Section size in bytes / Entry size if section holds table */
	count = sec->sh.sh_size / sec->sh.sh_entsize;

	for (i = 1; i < count; i++) { /* skip symbol 0 */

		last_sym = sym;
		sym = malloc(sizeof(*sym));
		memset(sym, 0, sizeof(*sym));

		sym->index = i;

		if (!gelf_getsym(sec->data, i, &sym->sym))
			ELF_ERROR(elf, "gelf_getsym");

		/* The strings will be stores in .strtab section */
		sym->name = elf_strptr(elf, sec->sh.sh_link,
				       sym->sym.st_name);
		if (!sym->name)
			ELF_ERROR(elf, "elf_strptr");

		sym->type = GELF_ST_TYPE(sym->sym.st_info);
		sym->bind = GELF_ST_BIND(sym->sym.st_info);

		switch (sym->type) {
			case STT_NOTYPE: /* TODO: compare ABS symbols */
			case STT_OBJECT:
			case STT_FUNC:
			case STT_SECTION:
			case STT_FILE: /* TODO: FILE getting compared properly? */
				break;
			default:
				ERROR("%s: unknown symbol type %d", sym->name,
				      sym->type);
		}

		/*
		 * ELF Extended Sections are employed to allow an ELF file to
		 * contain more than 0xff00 (SHN_LORESERVE) section.
		 */
		if (sym->sym.st_shndx >= SHN_LORESERVE &&
		    sym->sym.st_shndx <= SHN_HIRESERVE &&
		    sym->sym.st_shndx != SHN_ABS)
			ERROR("%s: I don't know how to handle reserved section "
			      "index %d for symbol %s", elfname(elf),
			      sym->sym.st_shndx, sym->name);

		if (sym->sym.st_shndx != SHN_UNDEF)
			sym->sec = find_section_by_index(secs,
							 sym->sym.st_shndx);
		else
			sym->sec = NULL;

		if (sym->type == STT_SECTION)
			sym->name = sym->sec->name;

		log_d("Symbol [%s] type [%s] bind [%s]\n",
			sym->name, symbol_type_char[sym->type],
			symbol_bind_char[sym->type]);

		/* optimized list_add */
		if (!*syms)
			*syms = sym;
		else
			last_sym->next = sym;

	}
}

void init_rela_list(Elf *elf, struct section *secs, struct symbol *syms,
		    struct rela **relas)
{
	struct section *rela_sec, *dest_sec;
	int count, i;
	unsigned int off, index;
	struct rela *rela;

	log_d("Relocation list :\n");

	for (rela_sec = secs; rela_sec; rela_sec = rela_sec->next) {

		if (rela_sec->sh.sh_type != SHT_RELA ||
		    strstr(rela_sec->name, ".debug"))
			continue;

		/* Base or counter part of this relocation section */
		dest_sec = find_section_by_name(secs, rela_sec->name + 5);
		if (!dest_sec)
			ERROR("can't find text section for rela %s",
			      rela_sec->name);

		/* Matching the number of entries */
		count = rela_sec->sh.sh_size / rela_sec->sh.sh_entsize;
		log_d("relocation [%s] entries [%d] it's mirror [%s]\n",
				rela_sec->name, count,
				dest_sec->name);
/*
Offset       Info         Type             Sym. Value       Sym. Name + Addend
000000000000 045c000000fc R_PPC64_REL16_HA 0000000000000000 .TOC. + 0
000000000004 045c000000fa R_PPC64_REL16_LO 0000000000000000 .TOC. + 4
*/
		for (i = 0; i < count; i++) {

			rela = malloc(sizeof(*rela));
			memset(rela, 0, sizeof(*rela));

			if (!gelf_getrela(rela_sec->data, i, &rela->rela))
				ELF_ERROR(elf, "gelf_getrela");

			rela->rela_sec = rela_sec;
			rela->dest_sec = dest_sec;

			/*
			 * This member (r_offset) gives the location at which to apply the
			 * relocation action. For a relocatable file, the value is the byte
			 * offset from the beginning of the section to the storage unit
			 * affected by the relocation.
			 * Find the symbol in the dest_sec() a.k.a base section.
			 */
			off = rela->rela.r_offset;
			rela->dest_sym = find_symbol_by_offset(syms, dest_sec,
							       off,
							       &rela->dest_off);

			if (!rela->dest_sym) {
				/*
				 * This means there is no symbol associated
				 * with the address in the destination section.
				 *
				 * We ignore mcount relocations for now.
				 * They'll need to be automatically regenerated
				 * anyway...
				 */
				if (!strcmp(dest_sec->name, "__mcount_loc") ||
				    !strcmp(dest_sec->name, ".toc")         ||
				    !strcmp(dest_sec->name, "__jump_table")         ||
				    !strcmp(dest_sec->name, "__bug_table")) {
					free(rela);
					continue;
				} else
					ERROR("%s:%d: missing symbol at offset %d",
					      rela_sec->name, i, off);
			}

			/*
			 * This member gives both the symbol table index with respect to
			 * which the relocation must be made, and the type of relocation to
			 * apply. For example, a call instruction's relocation entry would
			 * hold the symbol table index of the function being called. If the
			 * index is STN_UNDEF, the undefined symbol index, the relocation
			 * uses 0 as the ``symbol value''. Relocation types are
			 * processor-specific; descriptions of their behavior appear in
			 * the processor supplement. When the text below refers to a
			 * relocation entry's relocation type or symbol table index, it means
			 * the result of applying ELF32_R_TYPE (or ELF64_R_TYPE) or
			 * ELF32_R_SYM (or ELF64_R_SYM), respectively, to the entry's r_info
			 * member.
			 */
			rela->type = GELF_R_TYPE(rela->rela.r_info);
			index = GELF_R_SYM(rela->rela.r_info);

			rela->src_sym = find_symbol_by_index(syms, index);
			if (!rela->src_sym)
				ERROR("%s:%d: missing symbol at index %d",
				      rela_sec->name, i, index);

			/*
			 * This member specifies a constant addend used to compute the
			 * value to be stored into the relocatable field.
			 */
			rela->src_off = rela->rela.r_addend;

			/*
			 * If the source symbol is actually a section, we need
			 * to figure out the underlying function/object.
			 */
			if (rela->src_sym->type == STT_SECTION) {

				const char *name = rela->src_sym->name;

				if (!strcmp(name, ".text") ||
				    !strcmp(name, ".init.text") ||
				    !strncmp(name, ".data", 5) ||
				    !strcmp(name, ".bss") ||
				    !strcmp(name, ".toc")||
				    !strcmp(name, ".rodata")) {

					/* Source is a function/object */

					/* TODO: too much indenting... */

					/* TODO: In the case of R_X86_64_PC32,
					 * for find_symbol_by_offset to be
					 * accurate for finding the source
					 * symbol, we will have to disassemble
					 * the target function, find which
					 * instruction includes the target
					 * address, and then modify addend
					 * appropriately.  e.g. .bss - 5.  and
					 * _then_ call find_symbol_by_offset
					 * with the correct offset.
					 *
					 * But for now, it should be ok because
					 * we don't allow any changes (or
					 * additions...) to global data anyway
					 * and this only seems to affect .bss?
					 *
					 * but....we may need this for the
					 * generation phase.  because when
					 * translating relocations we need to
					 * know what the source object is so we
					 * can look up its address in the
					 * vmlinux.
					 * 
					 * yeah.  so if the type is
					 * R_X86_64_PC32 we need to do this.
					 * examine the target location somehow,
					 * and convert the addend
					 * accordingly before calling
					 * find_symbol_by_offset.
					 *
					 */
#if 0
					int addend_off = addend_offset(rela);


					rela->src_sym = find_symbol_by_offset(
							 syms,
							 rela->src_sym->sec,
							 rela->rela.r_addend + addend_off,
							 &rela->src_off);

					rela->src_off -= addend_off;
					

					if (!rela->src_sym)
						ERROR("unknown reloc src "
						      "symbol %s+%lx", name,
						      rela->rela.r_addend);

					/*
					printf("reloc: %s+%lx -> %s+%x\n",
					       name, rela->rela.r_addend,
					       rela->src_sym->name,
					       rela->src_off);
					*/
#endif

				} else if (!strncmp(name, ".rodata.str", 11) ||
					   !strcmp(name, "__ksymtab_strings")) {
					/* Source is a string */
					Elf_Data *str_data = rela->src_sym->sec->data;

					rela->src_str = str_data->d_buf +
							rela->rela.r_addend;

					rela->src_off = 0;

					/*
					printf("reloc: %s+%lx -> %s\n",
					       name, rela->rela.r_addend,
					       rela->src_str);
					*/

				} else
					printf("\t\tdon't know how to handle "
					       "relocation source %s %d\n",
						name, count);
			}


/*			printf("rela: %s+0x%lx to %s+0x%x\n",
			       rela->src_sym->name, rela->rela.r_addend,
			       rela->dest_sym->name, rela->dest_off);*/

			list_add(*relas, rela);
		}
		//break; //debugging purpose.
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

	/*
	 * Read all the symbols from symbol table and
	 * also identify their type, binding and section
         * holding them. Add them to global link list.
	 */
	init_symbol_list(elf1, secs1, &syms1);
	log_ok("%s %s\t[PASSED]\n", "Symbol list created for ", args.args[0]);

	/*
	 * Read the section link list and find all of the relocation section.
	 * For every relocation entry in the relocation section, find its
	 * corresponding destination/base entry. To which the relocation should
	 * be applied.
	 */
	init_rela_list(elf1, secs1, syms1, &relas1);
	log_ok("%s %s\t[PASSED]\n", "Relocation list created for ", args.args[0]);

	return (0);
}
