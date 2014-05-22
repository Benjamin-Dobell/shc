/* shc.c */

/**
 * This software contains the 'Alleged RC4' source code.
 * The original source code was published on the Net by a group of cypherpunks.
 * I picked up a modified version from the news.
 * The copyright notice does not apply to that code.
 */
static const char * my_name = "shc";
static const char * version = "Version 3.3";
static const char * subject = "Generic Script Compiler";
static const char * cpright = "Copyright (c) 1994..2002...";
static const char * authorm = "Francisco Rosales <frosal@fi.upm.es>";

static const char * copying =
"Copying:\n"
"\n"
"    This program is free software; you can redistribute it and/or modify\n"
"    it under the terms of the GNU General Public License as published by\n"
"    the Free Software Foundation; either version 2 of the License, or\n"
"    (at your option) any later version.\n"
"\n"
"    This program is distributed in the hope that it will be useful,\n"
"    but WITHOUT ANY WARRANTY; without even the implied warranty of\n"
"    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n"
"    GNU General Public License for more details.\n"
"\n"
"    You should have received a copy of the GNU General Public License\n"
"    along with this program; if not, write to the Free Software\n"
"    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.\n"
"\n"
"    Report problems and questions to:\n"
"\n"
"    frosal@fi.upm.es\n";

static const char * abstract =
"Abstract:\n"
"\n"
"    This tool generates a stripped binary executable version\n"
"    of the script specified at command line.\n"
"\n"
"    Binary version will be named with .x extension.\n"
"\n"
"    You can specify expiration date [-e] too, after which binary will\n"
"    refuse to be executed, displaying \"Contact with [-m]\" instead.\n"
"\n"
"    You can compile whatever interpreted script, but valid [-i], [-x]\n"
"    and [-l] options must be given.\n";

static const char * usage =
"Usage: -f script [-e date] [-m addr] [-i iopt] [-x cmnd] [-l lopt] [-rvCAh]";

static const char * help =
"\n"
"    -e %s  Expiration date in dd/mm/yyyy format [NO]\n"
"    -m %s  e-Mail address to contact with at expiration [your provider]\n"
"    -f %s  File name of the script to compile\n"
"    -i %s  Inline option for this interpreter i.e: -e\n"
"    -x %s  eXec command, as a printf format i.e: exec('%s',@ARGV);\n"
"    -l %s  Last option i.e: --\n"
"    -r     force Relaxed security. Make a redistributable binary.\n"
"    -v     Verbose\n"
"    -C     Copying\n"
"    -A     Abstract\n"
"    -h     Help\n"
"\n"
"       Environment variables used:\n"
"       Name    Default Usage\n"
"       CC      cc      C language compiler\n"
"       CFLAGS  <none>  Flags for C compiler\n";

#include <sys/types.h>
#include <sys/stat.h>
#include <assert.h>
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
static char * mail = "your provider";
static int relax;
static char * shll;
static char * inlo;
static char * xecc;
static char * lsto;
static char * opts;
static char * text;
static int verbose;
static int debuging;
static const char * RTC =
"\n"
"#include <sys/stat.h>\n"
"#include <sys/types.h>\n"
"\n"
"#include <stdio.h>\n"
"#include <stdlib.h>\n"
"#include <string.h>\n"
"#include <time.h>\n"
"#include <unistd.h>\n"
"\n"
"/**\n"
" * 'Alleged RC4' Source Code picked up from the news.\n"
" * From: allen@gateway.grumman.com (John L. Allen)\n"
" * Newsgroups: comp.lang.c\n"
" * Subject: Shrink this C code for fame and fun\n"
" * Date: 21 May 1996 10:49:37 -0400\n"
" */\n"
"\n"
"static unsigned char state[256], * ptr, indx, jndx, tmp;\n"
"\n"
"/*\n"
" * Reset rc4 state. \n"
" */\n"
"void state_0(void)\n"
"{\n"
"	indx = jndx = 0;\n"
"	do {\n"
"		state[indx] = indx;\n"
"	} while (++indx);\n"
"}\n"
"\n"
"/*\n"
" * Set key. Can be used more than once. \n"
" */\n"
"void key(char * str, int len)\n"
"{\n"
"	ptr = (unsigned char *)str;\n"
"	while (len > 0) {\n"
"		do {\n"
"			tmp = state[indx];\n"
"			jndx += tmp;\n"
"			jndx += ptr[(int)indx % len];\n"
"			state[indx] = state[jndx];\n"
"			state[jndx] = tmp;\n"
"		} while (++indx);\n"
"		ptr += 256;\n"
"		len -= 256;\n"
"	}\n"
"}\n"
"\n"
"/*\n"
" * Crypt data. \n"
" */\n"
"void rc4(char * str, int len)\n"
"{\n"
"	ptr = (unsigned char *)str;\n"
"	jndx = 0;\n"
"	while (len > 0) {\n"
"		indx++;\n"
"		tmp = state[indx];\n"
"		jndx += tmp;\n"
"		state[indx] = state[jndx];\n"
"		state[jndx] = tmp;\n"
"		tmp += state[indx];\n"
"		*ptr ^= state[tmp];\n"
"		ptr++;\n"
"		len--;\n"
"	}\n"
"}\n"
"\n"
"void key_with_file(char * file)\n"
"{\n"
"	struct stat statf[1];\n"
"	struct stat control[1];\n"
"\n"
"	if (!file)\n"
"		return;\n"
"\n"
"	if (stat(file, statf) < 0) {\n"
"		perror(file);\n"
"		exit(1);\n"
"	}\n"
"	/* Turn on stable fields */\n"
"	memset(control, 0, sizeof(control));\n"
"	control->st_ino = statf->st_ino;\n"
"	control->st_dev = statf->st_dev;\n"
"	control->st_rdev = statf->st_rdev;\n"
"	control->st_uid = statf->st_uid;\n"
"	control->st_gid = statf->st_gid;\n"
"	control->st_size = statf->st_size;\n"
"	control->st_mtime = statf->st_mtime;\n"
"	control->st_ctime = statf->st_ctime;\n"
"	key((char *)control, sizeof(control));\n"
"}\n"
"\n"
"void rmarg(char ** argv, char * arg)\n"
"{\n"
"	for (; argv && *argv && *argv != arg; argv++);\n"
"	for (; argv && *argv; argv++)\n"
"		*argv = argv[1];\n"
"}\n"
"\n"
"int chkenv(int argc, int rm)\n"
"{\n"
"	char buff[512];\n"
"	int mask;\n"
"	int l, m, a, c;\n"
"	char * string;\n"
"	extern char ** environ;\n"
"\n"
"	mask = (int) chkenv ^ (int) getpid();\n"
"	sprintf(buff, \"x%x\", mask);\n"
"	string = getenv(buff);\n"
"	l = strlen(buff);\n"
"	if (!string) {\n"
"		/* 1st */\n"
"		sprintf(&buff[l], \"=%d %d\", mask, argc);\n"
"		putenv(strdup(buff));\n"
"		return 0;\n"
"	}\n"
"	c = sscanf(string, \"%d %d%c\", &m, &a, buff);\n"
"	if (c == 2 && m == mask) {\n"
"		/* 3rd */\n"
"		if (rm)\n"
"			rmarg(environ, &string[-l - 1]);\n"
"		return 1 + (argc - a);\n"
"	}\n"
"	return -1;\n"
"}\n"
"\n"
"#ifdef DEBUGEXEC\n"
"#define DEBUGEXEC	/* Define if you want to debug execvp calls */\n"
"\n"
"void debugexec(char * shll, char ** argv)\n"
"{\n"
"	int i;\n"
"	fprintf(stderr, \"shll=%s\\n\", shll ? shll : \"<null>\");\n"
"	for (i = 0; argv && argv[i]; i++) {\n"
"		fprintf(stderr, \"argv[%d]=%.60s\\n\", i, argv[i]);\n"
"	}\n"
"}\n"
"\n"
"#endif /* DEBUGEXEC */\n"
"\n"
"#define UNTRACEABLE	/* Define to prevent ptrace this executable */\n"
"#ifdef UNTRACEABLE\n"
"\n"
"#include <sys/ptrace.h>\n"
"#include <sys/types.h>\n"
"#include <sys/wait.h>\n"
"#include <signal.h>\n"
"#include <stdio.h>\n"
"#include <unistd.h>\n"
"\n"
"void untraceable(char * argv0)\n"
"{\n"
"	int pid;\n"
"\n"
"	switch(pid = vfork()) {\n"
"	case  0:\n"
"		pid = getppid();\n"
"		if (!ptrace(PTRACE_ATTACH, pid, 0, 0) && !kill(pid, SIGCONT))\n"
"			_exit(0);\n"
"		kill(pid, SIGKILL);\n"
"	case -1:\n"
"		break;\n"
"	default:\n"
"		if (pid == waitpid(pid, 0, 0))\n"
"			return;\n"
"	}\n"
"	perror(argv0);\n"
"	_exit(1);\n"
"}\n"
"#endif	/* UNTRACEABLE */\n"
"\n"
"void xsh(int argc, char ** argv)\n"
"{\n"
"	char buff[512];\n"
"	char * scrpt;\n"
"	int ret, i, j;\n"
"	char ** varg;\n"
"\n"
"	ret = chkenv(argc, 0);\n"
"	if (ret < 0) {\n"
"		fprintf(stderr, \"%s: unnormal behavior\\n\", argv[0]);\n"
"		exit(1);\n"
"	}\n"
"	varg = (char **)calloc(argc + 10, sizeof(char *));\n"
"	if (varg == NULL) {\n"
"		perror(argv[0]);\n"
"		exit(1);\n"
"	}\n"
"	if (ret) {\n"
"		key_with_file(relax ? NULL : shll);\n"
"		rc4(opts, sizeof(opts_t));\n"
"		rc4(text, sizeof(text_t));\n"
"		rc4(chk2, sizeof(chk2_t));\n"
"		if (strcmp(\"Rosales\", chk2)) {\n"
"			fprintf(stderr, \"%s: Shell have changed.\\n\", argv[0]);\n"
"			exit(1);\n"
"		}\n"
"		memset(head, (int) ' ', sizeof(head));\n"
"		head[0] = '#';\n"
"		scrpt = head;		/* Script text */\n"
"		if (&head[sizeof(head)] != text) {\n"
"			fprintf(stderr, \"%s: Bad alignement.\\n\", argv[0]);\n"
"			exit(1);\n"
"		}\n"
"	} else {			/* Reexecute */\n"
"		if (*xecc) {\n"
"			sprintf(buff, xecc, argv[0]);\n"
"			scrpt = buff;\n"
"		} else {\n"
"			scrpt = argv[0];\n"
"		}\n"
"	}\n"
"	j = 0;\n"
"	varg[j++] = argv[0];		/* My own name at execution */\n"
"	if (ret && *opts)\n"
"		varg[j++] = opts;	/* Options on 1st line of code */\n"
"	if (*inlo)\n"
"		varg[j++] = inlo;	/* Option introducing inline code */\n"
"	varg[j++] = scrpt;\n"
"	if (*lsto)\n"
"		varg[j++] = lsto;	/* Option meaning last option */\n"
"	i = 0;\n"
"	if (ret > 1) {\n"
"		j -= ret;\n"
"		i = ret;\n"
"	}\n"
"	for (; i <= argc; i++)\n"
"		varg[i + j] = argv[i];	/* Main run-time arguments */\n"
"	if (ret && ret != chkenv(argc, 1))\n"
"		return;\n"
"#ifdef DEBUGEXEC\n"
"	debugexec(shll, varg);\n"
"#endif\n"
"	execvp(shll, varg);\n"
"	perror(shll);\n"
"	exit(1);\n"
"}\n"
"\n"
"int main(int argc, char ** argv)\n"
"{\n"
"#ifdef DEBUGEXEC\n"
"	debugexec(\"main\", argv);\n"
"#endif\n"
"#ifdef UNTRACEABLE\n"
"	untraceable(argv[0]);\n"
"#endif\n"
"	if (date && (date < (long)time(NULL))) {\n"
"		fprintf(stderr, \"%s\\n\", stmp);\n"
"		fprintf(stderr, \"%s: Out of date\\n\", argv[0]);\n"
"		fprintf(stderr, \"Contact with %s\\n\", mail);\n"
"		exit(0);\n"
"	}\n"
"	state_0();\n"
"	key(pswd, sizeof(pswd_t));\n"
"	rc4(shll, sizeof(shll_t));\n"
"	rc4(inlo, sizeof(inlo_t));\n"
"	rc4(xecc, sizeof(xecc_t));\n"
"	rc4(lsto, sizeof(lsto_t));\n"
"	rc4(chk1, sizeof(chk1_t));\n"
"	if (strcmp(\"Francisco\", chk1)) {\n"
"		fprintf(stderr, \"%s: I have changed.\\n\", argv[0]);\n"
"		exit(1);\n"
"	}\n"
"	xsh(argc, argv);\n"
"	/* This must never end this way */\n"
"	exit(1);\n"
"	return 1;\n"
"}\n";

static void error(const char * type, const char * frm, ...)
{
	va_list ap;
	char * frm2 = "\n";

	va_start(ap, frm);
	if (strchr(type, 's'))
		frm2 = ": %s\n";
	if(strchr(type, 'd') && !debuging)
		return;
	if(strchr(type, 'v') && !verbose)
		return;

	fprintf(stderr, "%s", my_name);
	vfprintf(stderr, frm, ap);
	fprintf(stderr, frm2, strerror(errno));

	if (strchr(type, 'x'))
		exit(1);
	va_end(ap);
}

static int parse_an_arg(int argc, char * argv[])
{
	extern char * optarg;
	const char * opts = "e:m:f:i:x:l:rvCAh";
	const char * nvv_fmt = " parse(-%c %s): Not a valid value";
	struct tm tmp[1];
	int cnt;
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
			error("", nvv_fmt, 'x', optarg);
			return -1;
		}
		break;
	case 'm':
		mail = optarg;
		break;
	case 'f':
		if (file) {
			error("", " parse(-f): Specified more than once");
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
	case 'C':
		error("", " %s, %s", version, subject);
		error("", " %s", cpright);
		error("", " %s", authorm);
		error("", " %s", copying);
		exit(0);
		break;
	case 'A':
		error("", " %s, %s", version, subject);
		error("", " %s", cpright);
		error("", " %s", authorm);
		error("", " %s", abstract);
		exit(0);
		break;
	case 'h':
		error("", " %s, %s", version, subject);
		error("", " %s", cpright);
		error("", " %s", authorm);
		error("", " %s%s", usage, help);
		exit(0);
		break;
	case -1:
		if (!file) {
			error("", " parse(-f): No specified");
			file = "";
			return -1;
		}
		return 0;
	case ':':
		error("", " parse: Missing parameter");
		return -1;
	case '?':
		error("", " parse: Unknown option");
		return -1;
	default:
		error("", " parse: Unknown return");
		return -1;
	}
	return 1;
}

static void parse_args(int argc, char * argv[])
{
	int err = 0;
	int ret;

	my_name = strrchr(argv[0], '/');
	if (my_name)
		my_name++;
	else
		my_name = argv[0];

	do {
		ret = parse_an_arg(argc, argv);
		if (ret == -1)
			err++;
	} while (ret);
	if (err)
		error("x", " %s", usage);
}

/**
 * 'Alleged RC4' Source Code picked up from the news.
 * From: allen@gateway.grumman.com (John L. Allen)
 * Newsgroups: comp.lang.c
 * Subject: Shrink this C code for fame and fun
 * Date: 21 May 1996 10:49:37 -0400
 */

static unsigned char state[256], * ptr, indx, jndx, tmp;

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
	ptr = (unsigned char *)str;
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
	ptr = (unsigned char *)str;
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

void key_with_file(char * file)
{
	struct stat statf[1];
	struct stat control[1];

	if (!file)
		return;

	if (stat(file, statf) < 0) {
		error("sx", " Invalid file name: %s", file);
	}
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
	{ "sh",   "-c", "",   "exec %s \"$@\"" }, /* IRIX_nvi */
	{ "bash", "-c", "--", "exec %s \"$@\"" },
	{ "bsh",  "-c", "",   "exec %s \"$@\"" }, /* AIX_nvi */
	{ "Rsh",  "-c", "",   "exec %s \"$@\"" }, /* AIX_nvi */
	{ "ksh",  "-c", "--", "exec %s \"$@\"" },
	{ "tsh",  "-c", "--", "exec %s \"$@\"" }, /* AIX */
	{ "ash",  "-c", "--", "exec %s \"$@\"" }, /* Linux */
	{ "csh",  "-c", "-b", "exec %s $argv" }, /* AIX: No file for $0 */
	{ "tcsh", "-c", "-b", "exec %s $argv" },
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
	ptr = malloc(i + 1);
	shll = malloc(i + 1);
	opts = malloc(i + 1);
	if (!ptr || !shll || !opts)
		return -1;
	strncpy(ptr, text, i);
	ptr[i] = '\0';

	*opts = '\0';
	i = sscanf(ptr, " #!%s%s %c", shll, opts, opts);
	if (i < 1 || i > 2) {
		error("", " Invalid script's first line: %s", ptr);
		return -1;
	}
	free(ptr);

	shll = realloc(shll, strlen(shll) + 1);
	ptr = strrchr(shll, (int)'/');
	if (*ptr == '/')
		ptr++;
	error("v", " shll=%s", ptr);

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
		error("", " Unknown shell (%s): specify [-i][-x][-l]", ptr);
		return -1;
	}
	error("v", " [-i]=%s", inlo);
	error("v", " [-x]=%s", xecc);
	error("v", " [-l]=%s", lsto);

	opts = realloc(opts, strlen(opts) + 1);
	if (*opts && !strcmp(opts, lsto)) {
		error("", " opts=%s : Is equal to [-l]. Removing opts", opts);
		*opts = '\0';
	} else if (!strcmp(opts, "-")) {
		error("", " opts=%s : No real one. Removing opts", opts);
		*opts = '\0';
	}
	error("v", " opts=%s", opts);
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
	return text;
}

int noise(char * ptr, int min, int xtra)
{
	if (xtra) xtra = rand() % xtra;
	xtra += min;
	for (min = 0; min < xtra; min++)
		*ptr++ = (char) rand();
	return xtra;
}

void print_str(FILE * o, char * ptr, int l, int n)
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

void print_data(FILE * o, char * ptr, char * name, int l)
{
	fprintf(o, "typedef char %s_t[%d];\n", name, l);
	fprintf(o, "static char %s[] = ", name);
	print_str(o, ptr, l, l + (rand() & 0xf));
	fprintf(o, ";\n");
}

void dump_data(FILE * o, char * ptr, char * name, int l)
{
	rc4(ptr, l);
	print_data(o, ptr, name, l);
}

int write_C(char * file)
{
	FILE * o;
	char * shll2;
	char buf[512];
	int l;

	sprintf(buf, "%s.x.c", file);
	o = fopen(buf, "w");
	if (!o)
		return -1;
	srand((unsigned)time(NULL));
	fprintf(o, "/* %s */\n\n", buf);
	fprintf(o, "static char stmp[] = \"%s %s, %s\\n\"\n\"%s %s\";\n",
		my_name, version, subject, cpright, authorm);
	fprintf(o, "static long date = %ld;\n", date);
	fprintf(o, "static char mail[] = \"%s\";\n", mail);
	fprintf(o, "static int relax = %d;\n", relax);
	l = noise(buf, 256, 256);
	dump_data(o, buf, "pswd", l);
	state_0();
	key(buf, l);
	shll2 = strdup(shll);
	dump_data(o, shll, "shll", strlen(shll) + 1);
	shll = shll2;
	dump_data(o, inlo, "inlo", strlen(inlo) + 1);
	dump_data(o, xecc, "xecc", strlen(xecc) + 1);
	dump_data(o, lsto, "lsto", strlen(lsto) + 1);
	dump_data(o, strdup("Francisco"), "chk1", 10);
	key_with_file(relax ? NULL : shll);
	dump_data(o, opts, "opts", strlen(opts) + 1);
	fprintf(o, "static char head[4096] = \"#! \";\n");
	dump_data(o, text, "text", strlen(text) + 1);
	dump_data(o, strdup("Rosales"), "chk2", 8);
	fprintf(o, "%s", RTC);
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
	error("v", ": %s", cmd);
	if (system(cmd))
		return -1;
	sprintf(cmd, "strip %s.x", file);
	error("v", ": %s", cmd);
	if (system(cmd))
		error("", ": It does not matter");
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
	if (write_C(file))
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

