/* shc.c */

/**
 * This software contains the 'Alleged RC4' source code.
 * The original source code was published on the Net by a group of cypherpunks.
 * I picked up a modified version from the news.
 * The copyright notice does not apply to that code.
 */
static const char my_name[] = "shc";
static const char version[] = "Version 3.7";
static const char subject[] = "Generic Script Compiler";
static const char cpright[] = "Copyright (c) 1994-2003";
static const struct { const char * f, * s, * e; }
	author = { "Francisco", "Rosales", "<frosal@fi.upm.es>" };

static const char * copying[] = {
"Copying:",
"",
"    This program is free software; you can redistribute it and/or modify",
"    it under the terms of the GNU General Public License as published by",
"    the Free Software Foundation; either version 2 of the License, or",
"    (at your option) any later version.",
"",
"    This program is distributed in the hope that it will be useful,",
"    but WITHOUT ANY WARRANTY; without even the implied warranty of",
"    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the",
"    GNU General Public License for more details.",
"",
"    You should have received a copy of the GNU General Public License",
"    along with this program; if not, write to the Free Software",
"    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.",
"",
"    Report problems and questions to:",
"",
0};

static const char * abstract[] = {
"Abstract:",
"",
"    This tool generates a stripped binary executable version",
"    of the script specified at command line.",
"",
"    Binary version will be saved with a .x extension.",
"",
"    You can specify expiration date [-e] too, after which binary will",
"    refuse to be executed, displaying \"[-m]\" instead.",
"",
"    You can compile whatever interpreted script, but valid [-i], [-x]",
"    and [-l] options must be given.",
"",
0};

static const char usage[] = 
"Usage: shc [-e date] [-m addr] [-i iopt] [-x cmnd] [-l lopt] [-rvDTCAh] -f script";

static const char * help[] = {
"",
"    -e %s  Expiration date in dd/mm/yyyy format [none]",
"    -m %s  Message to display upon expiration [\"Please contact your provider\"]",
"    -f %s  File name of the script to compile",
"    -i %s  Inline option for the shell interpreter i.e: -e",
"    -x %s  eXec command, as a printf format i.e: exec('%s',@ARGV);",
"    -l %s  Last shell option i.e: --",
"    -r     Relax security. Make a redistributable binary",
"    -v     Verbose compilation",
"    -D     Switch ON debug exec calls [OFF]",
"    -T     Allow binary to be traceable [no]",
"    -C     Display license and exit",
"    -A     Display abstract and exit",
"    -h     Display help and exit",
"",
"    Environment variables used:",
"    Name    Default  Usage",
"    CC      cc       C compiler command",
"    CFLAGS  <none>   C compiler flags",
"",
"    Please consult the shc(1) man page.",
"",
0};

#include <sys/types.h>
#include <sys/stat.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define SIZE 4096

static char * file;
static long date;
static char * mail = "Please contact your provider";
static int relax;
static char * shll;
static char * inlo;
static char * xecc;
static char * lsto;
static char * opts;
static char * text;
static int verbose;
static const char DEBUGEXEC_line[] =
"#define DEBUGEXEC	%d	/* Define as 1 to debug execvp calls */\n";
static int DEBUGEXEC_flag;
static const char TRACEABLE_line[] =
"#define TRACEABLE	%d	/* Define as 1 to enable ptrace the executable */\n";
static int TRACEABLE_flag;
static const char * RTC[] = {
"",
"/* rtc.c */",
"",
"#include <sys/stat.h>",
"#include <sys/types.h>",
"",
"#include <errno.h>",
"#include <stdio.h>",
"#include <stdlib.h>",
"#include <string.h>",
"#include <time.h>",
"#include <unistd.h>",
"",
"/**",
" * 'Alleged RC4' Source Code picked up from the news.",
" * From: allen@gateway.grumman.com (John L. Allen)",
" * Newsgroups: comp.lang.c",
" * Subject: Shrink this C code for fame and fun",
" * Date: 21 May 1996 10:49:37 -0400",
" */",
"",
"static unsigned char state[256], indx, jndx;",
"",
"/*",
" * Reset rc4 state. ",
" */",
"void state_0(void)",
"{",
"	indx = jndx = 0;",
"	do {",
"		state[indx] = indx;",
"	} while (++indx);",
"}",
"",
"/*",
" * Set key. Can be used more than once. ",
" */",
"void key(char * str, int len)",
"{",
"	unsigned char tmp, * ptr = (unsigned char *)str;",
"	while (len > 0) {",
"		do {",
"			tmp = state[indx];",
"			jndx += tmp;",
"			jndx += ptr[(int)indx % len];",
"			state[indx] = state[jndx];",
"			state[jndx] = tmp;",
"		} while (++indx);",
"		ptr += 256;",
"		len -= 256;",
"	}",
"}",
"",
"/*",
" * Crypt data. ",
" */",
"void rc4(char * str, int len)",
"{",
"	unsigned char tmp, * ptr = (unsigned char *)str;",
"	jndx = 0;",
"	while (len > 0) {",
"		indx++;",
"		tmp = state[indx];",
"		jndx += tmp;",
"		state[indx] = state[jndx];",
"		state[jndx] = tmp;",
"		tmp += state[indx];",
"		*ptr ^= state[tmp];",
"		ptr++;",
"		len--;",
"	}",
"}",
"",
"/*",
" * Key with file invariants. ",
" */",
"int key_with_file(char * file)",
"{",
"	struct stat statf[1];",
"	struct stat control[1];",
"",
"	if (stat(file, statf) < 0)",
"		return -1;",
"",
"	/* Turn on stable fields */",
"	memset(control, 0, sizeof(control));",
"	control->st_ino = statf->st_ino;",
"	control->st_dev = statf->st_dev;",
"	control->st_rdev = statf->st_rdev;",
"	control->st_uid = statf->st_uid;",
"	control->st_gid = statf->st_gid;",
"	control->st_size = statf->st_size;",
"	control->st_mtime = statf->st_mtime;",
"	control->st_ctime = statf->st_ctime;",
"	key((char *)control, sizeof(control));",
"	return 0;",
"}",
"",
"#if DEBUGEXEC",
"void debugexec(char * shll, int argc, char ** argv)",
"{",
"	int i;",
"	fprintf(stderr, \"shll=%s\\n\", shll ? shll : \"<null>\");",
"	fprintf(stderr, \"argc=%d\\n\", argc);",
"	if (!argv) {",
"		fprintf(stderr, \"argv=<null>\\n\");",
"	} else { ",
"		for (i = 0; i <= argc ; i++)",
"			fprintf(stderr, \"argv[%d]=%.60s\\n\", i, argv[i] ? argv[i] : \"<null>\");",
"	}",
"}",
"#endif /* DEBUGEXEC */",
"",
"void rmarg(char ** argv, char * arg)",
"{",
"	for (; argv && *argv && *argv != arg; argv++);",
"	for (; argv && *argv; argv++)",
"		*argv = argv[1];",
"}",
"",
"int chkenv(int argc)",
"{",
"	char buff[512];",
"	unsigned mask, m;",
"	int l, a, c;",
"	char * string;",
"	extern char ** environ;",
"",
"	mask  = (unsigned)chkenv;",
"	mask ^= (unsigned)getpid() * ~mask;",
"	sprintf(buff, \"x%x\", mask);",
"	string = getenv(buff);",
"#if DEBUGEXEC",
"	fprintf(stderr, \"getenv(%s)=%s\\n\", buff, string ? string : \"<null>\");",
"#endif",
"	l = strlen(buff);",
"	if (!string) {",
"		/* 1st */",
"		sprintf(&buff[l], \"=%u %d\", mask, argc);",
"		putenv(strdup(buff));",
"		return 0;",
"	}",
"	c = sscanf(string, \"%u %d%c\", &m, &a, buff);",
"	if (c == 2 && m == mask) {",
"		/* 3rd */",
"		rmarg(environ, &string[-l - 1]);",
"		return 1 + (argc - a);",
"	}",
"	return -1;",
"}",
"",
"#if !TRACEABLE",
"",
"#define _LINUX_SOURCE_COMPAT",
"#include <sys/ptrace.h>",
"#include <sys/types.h>",
"#include <sys/wait.h>",
"#include <fcntl.h>",
"#include <signal.h>",
"#include <stdio.h>",
"#include <unistd.h>",
"",
"void untraceable(char * argv0)",
"{",
"	char proc[80];",
"	int pid, mine;",
"",
"	switch(pid = vfork()) {",
"	case  0:",
"		pid = getppid();",
"		/* For problematic SunOS ptrace */",
"		sprintf(proc, \"/proc/%d/as\", (int)pid);",
"		close(0);",
"		mine = !open(proc, O_RDWR|O_EXCL);",
"		if (!mine && errno != EBUSY)",
"			mine = !ptrace(PTRACE_ATTACH, pid, 0, 0);",
"		if (mine) {",
"			kill(pid, SIGCONT);",
"		} else {",
"			fprintf(stderr, \"%s is being traced!\\n\", argv0);",
"			kill(pid, SIGKILL);",
"		}",
"		_exit(mine);",
"	case -1:",
"		break;",
"	default:",
"		if (pid == waitpid(pid, 0, 0))",
"			return;",
"	}",
"	perror(argv0);",
"	_exit(1);",
"}",
"#endif /* !TRACEABLE */",
"",
"char * xsh(int argc, char ** argv)",
"{",
"	char buff[512];",
"	char * scrpt;",
"	int ret, i, j;",
"	char ** varg;",
"",
"	state_0();",
"	key(pswd, sizeof(pswd_t));",
"	rc4(shll, sizeof(shll_t));",
"	rc4(inlo, sizeof(inlo_t));",
"	rc4(xecc, sizeof(xecc_t));",
"	rc4(lsto, sizeof(lsto_t));",
"	rc4(chk1, sizeof(chk1_t));",
"	if (strcmp(TEXT_chk1, chk1))",
"		return \"location has changed!\";",
"	ret = chkenv(argc);",
"	if (ret < 0)",
"		return \"abnormal behavior!\";",
"	varg = (char **)calloc(argc + 10, sizeof(char *));",
"	if (!varg)",
"		return 0;",
"	if (ret) {",
"		if (!relax && key_with_file(shll))",
"			return shll;",
"		rc4(opts, sizeof(opts_t));",
"		rc4(text, sizeof(text_t));",
"		rc4(chk2, sizeof(chk2_t));",
"		if (strcmp(TEXT_chk2, chk2))",
"			return \"shell has changed!\";",
"		if (sizeof(text_t) < sizeof(hide_t)) {",
"			/* Prepend spaces til a sizeof(hide_t) script size. */",
"			scrpt = malloc(sizeof(hide_t));",
"			if (!scrpt)",
"				return 0;",
"			memset(scrpt, (int) ' ', sizeof(hide_t));",
"			memcpy(&scrpt[sizeof(hide_t) - sizeof(text_t)], text, sizeof(text_t));",
"		} else {",
"			scrpt = text;	/* Script text */",
"		}",
"	} else {			/* Reexecute */",
"		if (*xecc) {",
"			sprintf(buff, xecc, argv[0]);",
"			scrpt = buff;",
"		} else {",
"			scrpt = argv[0];",
"		}",
"	}",
"	j = 0;",
"	varg[j++] = argv[0];		/* My own name at execution */",
"	if (ret && *opts)",
"		varg[j++] = opts;	/* Options on 1st line of code */",
"	if (*inlo)",
"		varg[j++] = inlo;	/* Option introducing inline code */",
"	varg[j++] = scrpt;		/* The script itself */",
"	if (*lsto)",
"		varg[j++] = lsto;	/* Option meaning last option */",
"	i = (ret > 1) ? ret : 0;	/* Args numbering correction */",
"	while (i < argc)",
"		varg[j++] = argv[i++];	/* Main run-time arguments */",
"	varg[j] = 0;			/* NULL terminated array */",
"#if DEBUGEXEC",
"	debugexec(shll, j, varg);",
"#endif",
"	execvp(shll, varg);",
"	return shll;",
"}",
"",
"int main(int argc, char ** argv)",
"{",
"#if DEBUGEXEC",
"	debugexec(\"main\", argc, argv);",
"#endif",
"#if !TRACEABLE",
"	untraceable(argv[0]);",
"#endif",
"	if (date && (date < (long)time(NULL))) {",
"		fprintf(stderr, \"%s has expired!\\n\", argv[0]);",
"		fprintf(stderr, \"%s\\n\", mail);",
"	} else {",
"		argv[1] = xsh(argc, argv);",
"		fprintf(stderr, \"%s%s%s: %s\\n\", argv[0],",
"			errno ? \": \" : \"\",",
"			errno ? strerror(errno) : \"\",",
"			argv[1] ? argv[1] : \"<null>\"",
"		);",
"	}",
"	return 1;",
"}",
0};

static int parse_an_arg(int argc, char * argv[])
{
	extern char * optarg;
	const char * opts = "e:m:f:i:x:l:rvDTCAh";
	struct tm tmp[1];
	int cnt, l;
	char ctrl;

	switch (getopt(argc, argv, opts)) {
	case 'e':
		memset(tmp, 0, sizeof(tmp));
		cnt = sscanf(optarg, "%2d/%2d/%4d%c",
			&tmp->tm_mday, &tmp->tm_mon, &tmp->tm_year, &ctrl);
		if (cnt == 3) {
			tmp->tm_mon--;
			tmp->tm_year -= 1900;
			date = (long)mktime(tmp);
		}
		if (cnt != 3 || date == -1) {
			fprintf(stderr, "%s parse(-e %s): Not a valid value\n",
				my_name,  optarg);
			return -1;
		}
		break;
	case 'm':
		mail = optarg;
		break;
	case 'f':
		if (file) {
			fprintf(stderr, "%s parse(-f): Specified more than once\n",
				my_name);
			return -1;
		}
		file = optarg;
		break;
	case 'i':
		inlo = optarg;
		break;
	case 'x':
		xecc = optarg;
		break;
	case 'l':
		lsto = optarg;
		break;
	case 'r':
		relax++;
		break;
	case 'v':
		verbose++;
		break;
	case 'D':
		DEBUGEXEC_flag = 1;
		break;
	case 'T':
		TRACEABLE_flag = 1;
		break;
	case 'C':
		fprintf(stderr, "%s %s, %s\n", my_name, version, subject);
		fprintf(stderr, "%s %s %s %s %s\n", my_name, cpright, author.f, author.s, author.e);
		fprintf(stderr, "%s ", my_name);
		for (l = 0; copying[l]; l++)
			fprintf(stderr, "%s\n", copying[l]);
		fprintf(stderr, "    %s %s %s\n\n", author.f, author.s, author.e);
		exit(0);
		break;
	case 'A':
		fprintf(stderr, "%s %s, %s\n", my_name, version, subject);
		fprintf(stderr, "%s %s %s %s %s\n", my_name, cpright, author.f, author.s, author.e);
		fprintf(stderr, "%s ", my_name);
		for (l = 0; abstract[l]; l++)
			fprintf(stderr, "%s\n", abstract[l]);
		exit(0);
		break;
	case 'h':
		fprintf(stderr, "%s %s, %s\n", my_name, version, subject);
		fprintf(stderr, "%s %s %s %s %s\n", my_name, cpright, author.f, author.s, author.e);
		fprintf(stderr, "%s %s\n", my_name, usage);
		for (l = 0; help[l]; l++)
			fprintf(stderr, "%s\n", help[l]);
		exit(0);
		break;
	case -1:
		if (!file) {
			fprintf(stderr, "%s parse(-f): No source file specified\n", my_name);
			file = "";
			return -1;
		}
		return 0;
	case ':':
		fprintf(stderr, "%s parse: Missing parameter\n", my_name);
		return -1;
	case '?':
		fprintf(stderr, "%s parse: Unknown option\n", my_name);
		return -1;
	default:
		fprintf(stderr, "%s parse: Unknown return\n", my_name);
		return -1;
	}
	return 1;
}

static void parse_args(int argc, char * argv[])
{
	int err = 0;
	int ret;

#if 0
	my_name = strrchr(argv[0], '/');
	if (my_name)
		my_name++;
	else
		my_name = argv[0];
#endif

	do {
		ret = parse_an_arg(argc, argv);
		if (ret == -1)
			err++;
	} while (ret);
	if (err) {
		fprintf(stderr, "\n%s %s\n\n", my_name, usage);
		exit(1);
	}
}

/**
 * 'Alleged RC4' Source Code picked up from the news.
 * From: allen@gateway.grumman.com (John L. Allen)
 * Newsgroups: comp.lang.c
 * Subject: Shrink this C code for fame and fun
 * Date: 21 May 1996 10:49:37 -0400
 */

static unsigned char state[256], indx, jndx;

/*
 * Reset rc4 state. 
 */
void state_0(void)
{
	indx = jndx = 0;
	do {
		state[indx] = indx;
	} while (++indx);
}

/*
 * Set key. Can be used more than once. 
 */
void key(char * str, int len)
{
	unsigned char tmp, * ptr = (unsigned char *)str;
	while (len > 0) {
		do {
			tmp = state[indx];
			jndx += tmp;
			jndx += ptr[(int)indx % len];
			state[indx] = state[jndx];
			state[jndx] = tmp;
		} while (++indx);
		ptr += 256;
		len -= 256;
	}
}

/*
 * Crypt data. 
 */
void rc4(char * str, int len)
{
	unsigned char tmp, * ptr = (unsigned char *)str;
	jndx = 0;
	while (len > 0) {
		indx++;
		tmp = state[indx];
		jndx += tmp;
		state[indx] = state[jndx];
		state[jndx] = tmp;
		tmp += state[indx];
		*ptr ^= state[tmp];
		ptr++;
		len--;
	}
}

/*
 * Key with file invariants.
 */
int key_with_file(char * file)
{
	struct stat statf[1];
	struct stat control[1];

	if (stat(file, statf) < 0)
		return -1;

	/* Turn on stable fields */
	memset(control, 0, sizeof(control));
	control->st_ino = statf->st_ino;
	control->st_dev = statf->st_dev;
	control->st_rdev = statf->st_rdev;
	control->st_uid = statf->st_uid;
	control->st_gid = statf->st_gid;
	control->st_size = statf->st_size;
	control->st_mtime = statf->st_mtime;
	control->st_ctime = statf->st_ctime;
	key((char *)control, sizeof(control));
	return 0;
}

/*
 * NVI stands for Shells that complaint "Not Valid Identifier" on
 * environment variables with characters as "=|#:*?$ ".
 */
struct {
	char * shll;
	char * inlo;
	char * lsto;
	char * xecc;
} shellsDB[] = {
	{ "perl", "-e", "--", "exec('%s',@ARGV);" },
	{ "rc",   "-c", "",   "builtin exec %s $*" },
	{ "sh",   "-c", "",   "exec '%s' \"$@\"" }, /* IRIX_nvi */
	{ "bash", "-c", "",   "exec '%s' \"$@\"" },
	{ "bsh",  "-c", "",   "exec '%s' \"$@\"" }, /* AIX_nvi */
	{ "Rsh",  "-c", "",   "exec '%s' \"$@\"" }, /* AIX_nvi */
	{ "ksh",  "-c", "",   "exec '%s' \"$@\"" }, /* OK on Solaris, AIX and Linux (THX <bryan.hogan@dstintl.com>) */
	{ "tsh",  "-c", "--", "exec '%s' \"$@\"" }, /* AIX */
	{ "ash",  "-c", "--", "exec '%s' \"$@\"" }, /* Linux */
	{ "csh",  "-c", "-b", "exec '%s' $argv" }, /* AIX: No file for $0 */
	{ "tcsh", "-c", "-b", "exec '%s' $argv" },
	{ NULL,   NULL, NULL, NULL },
};

int eval_shell(char * text)
{
	int i;
	char * ptr;

	ptr = strchr(text, (int)'\n');
	if (!ptr)
		i = strlen(text);
	else
		i = ptr - text;
	ptr  = malloc(i + 1);
	shll = malloc(i + 1);
	opts = malloc(i + 1);
	if (!ptr || !shll || !opts)
		return -1;
	strncpy(ptr, text, i);
	ptr[i] = '\0';

	*opts = '\0';
	i = sscanf(ptr, " #!%s%s %c", shll, opts, opts);
	if (i < 1 || i > 2) {
		fprintf(stderr, "%s: invalid first line in script: %s\n", my_name, ptr);
		return -1;
	}
	free(ptr);

	shll = realloc(shll, strlen(shll) + 1);
	ptr  = strrchr(shll, (int)'/');
	if (*ptr == '/')
		ptr++;
	if (verbose) fprintf(stderr, "%s shll=%s\n", my_name, ptr);

	for(i=0; shellsDB[i].shll; i++) {
		if(!strcmp(ptr, shellsDB[i].shll)) {
			if (!inlo)
				inlo = strdup(shellsDB[i].inlo);
			if (!xecc)
				xecc = strdup(shellsDB[i].xecc);
			if (!lsto)
				lsto = strdup(shellsDB[i].lsto);
		}
	}
	if (!inlo || !xecc || !lsto) {
		fprintf(stderr, "%s Unknown shell (%s): specify [-i][-x][-l]\n", my_name, ptr);
		return -1;
	}
	if (verbose) fprintf(stderr, "%s [-i]=%s\n", my_name, inlo);
	if (verbose) fprintf(stderr, "%s [-x]=%s\n", my_name, xecc);
	if (verbose) fprintf(stderr, "%s [-l]=%s\n", my_name, lsto);

	opts = realloc(opts, strlen(opts) + 1);
	if (*opts && !strcmp(opts, lsto)) {
		fprintf(stderr, "%s opts=%s : Is equal to [-l]. Removing opts\n", my_name, opts);
		*opts = '\0';
	} else if (!strcmp(opts, "-")) {
		fprintf(stderr, "%s opts=%s : No real one. Removing opts\n", my_name, opts);
		*opts = '\0';
	}
	if (verbose) fprintf(stderr, "%s opts=%s\n", my_name, opts);
	return 0;
}

char * read_script(char * file)
{
	FILE * i;
	char * text;
	int cnt, l;

	text = malloc(SIZE);
	if (!text)
		return NULL;
	i = fopen(file, "r");
	if (!i)
		return NULL;
	for (l = 0;;) {
		text = realloc(text, l + SIZE);
		if (!text)
			return NULL;
		cnt = fread(&text[l], 1, SIZE, i);
		if (!cnt)
			break;
		l += cnt;
	}
	fclose(i);
	text = realloc(text, l + 1);
	if (!text)
		return NULL;
	text[l] = '\0';

	/* Check current System ARG_MAX limit. */
	if (l > 0.80 * (cnt = sysconf(_SC_ARG_MAX))) {
		fprintf(stderr, "%s: WARNING!!\n"
"   Scripts of length near to (or higher than) the current System limit on\n"
"   \"maximum size of arguments to EXEC\", could comprise its binary execution.\n"
"   In the current System the call sysconf(_SC_ARG_MAX) returns %d bytes\n"
"   and your script \"%s\" is %d bytes length.\n",
		my_name, cnt, file, l);
	}
	return text;
}

int noise(char * ptr, unsigned min, unsigned xtra, int str)
{
	if (xtra) xtra = rand() % xtra;
	xtra += min;
	for (min = 0; min < xtra; min++, ptr++)
		do
			*ptr = (char) rand();
		while (str && !isalnum(*ptr));
	if (str) *ptr = '\0';
	return xtra;
}

void print_bytes(FILE * o, char * ptr, int l, int n)
{
	int i;

	for (i = 0; i < n; i++) {
		if ((i & 0xf) == 0)
			fprintf(o, "\n\t\"");
		fprintf(o, "\\%03o", (unsigned char)(i < l ? ptr[i] : rand()));
		if ((i & 0xf) == 0xf)
			fprintf(o, "\"");
	}
	if ((i & 0xf) != 0)
		fprintf(o, "\"");
}

void print_array(FILE * o, char * ptr, char * name, int l)
{
	fprintf(o, "typedef char %s_t[%d];\n", name, l);
	fprintf(o, "static  char %s[] = ", name);
	print_bytes(o, ptr, l, l + (rand() & 0xf));
	fprintf(o, ";\n");
}

void dump_array(FILE * o, char * ptr, char * name, int l)
{
	rc4(ptr, l);
	print_array(o, ptr, name, l);
}

int write_C(char * file, char * argv[])
{
	FILE * o;
	char buf[SIZE];
	int l;

	sprintf(buf, "%s.x.c", file);
	o = fopen(buf, "w");
	if (!o)
		return -1;
	srand((unsigned)time(NULL));
	fprintf(o, "#if 0\n");
	fprintf(o, "\t%s %s, %s\n", my_name, version, subject);
	fprintf(o, "\t%s %s %s %s\n\n\t", cpright, author.f, author.s, author.e);
	for (l = 0; argv[l]; l++)
		fprintf(o, "%s ", argv[l]);
	fprintf(o, "\n#endif\n\n");
	fprintf(o, "static  long date = %ld;\n", date);
	fprintf(o, "static  char mail[] = \"%s\";\n", mail);
	fprintf(o, "static  int  relax = %d;\n", relax);
	l = noise(buf, 256, 256, 0);
	dump_array(o, buf, "pswd", l);
	state_0();
	key(buf, l);
	dump_array(o, strdup(shll), "shll", strlen(shll) + 1);
	dump_array(o, inlo, "inlo", strlen(inlo) + 1);
	dump_array(o, xecc, "xecc", strlen(xecc) + 1);
	dump_array(o, lsto, "lsto", strlen(lsto) + 1);
	l = noise(buf, 8, 8, 1);
	fprintf(o, "#define TEXT_%s	\"%s\"\n", "chk1", buf);
	dump_array(o, buf, "chk1", l + 1);
	if (!relax && key_with_file(shll)) {
		fprintf(stderr, "%s: invalid file name: %s", my_name, shll);
		perror("");
		exit(1);
	}
	dump_array(o, opts, "opts", strlen(opts) + 1);
	dump_array(o, text, "text", strlen(text) + 1);
	l = noise(buf, 8, 8, 1);
	fprintf(o, "#define TEXT_%s	\"%s\"\n", "chk2", buf);
	dump_array(o, buf, "chk2", l + 1);
	fprintf(o, "typedef char %s_t[%d];\n\n", "hide", 1<<12);
	fprintf(o, DEBUGEXEC_line, DEBUGEXEC_flag);
	fprintf(o, TRACEABLE_line, TRACEABLE_flag);
	for (l = 0; RTC[l]; l++)
		fprintf(o, "%s\n", RTC[l]);
	fflush(o);
	fclose(o);
	return 0;
}

int make(void)
{
	char * cc, * cflags;
	char cmd[SIZE];

	cc = getenv("CC");
	if (!cc)
		cc = "cc";
	cflags = getenv("CFLAGS");
	if (!cflags)
		cflags = "";
	sprintf(cmd, "%s %s %s.x.c -o %s.x", cc, cflags, file, file);
	if (verbose) fprintf(stderr, "%s: %s\n", my_name, cmd);
	if (system(cmd))
		return -1;
	sprintf(cmd, "strip %s.x", file);
	if (verbose) fprintf(stderr, "%s: %s\n", my_name, cmd);
	if (system(cmd))
		fprintf(stderr, "%s: never mind\n", my_name);

	return 0;
}

void do_all(int argc, char * argv[])
{
	parse_args(argc, argv);
	text = read_script(file);
	if (!text)
		return;
	if (eval_shell(text))
		return;
	if (write_C(file, argv))
		return;
	if (make())
		return;
	exit(0);
}

int main(int argc, char * argv[])
{
	putenv("LANG=");
	do_all(argc, argv);
	/* Return on error */
	perror(argv[0]);
	exit(1);
	return 1;
}

