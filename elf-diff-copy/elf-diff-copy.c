#include <stdlib.h>
#include <argp.h>

struct arguments {
	char *args[2];
	char *vmlinux;
	char *outfile;
};

struct arguments args;

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

int main(int argc, char *argv[])
{
	argp_parse(&argp, argc, argv, 0, NULL, &args);

	return (0);
}
