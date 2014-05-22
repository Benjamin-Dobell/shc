/* shc.c */

static char *my_name = "shc";
static char *version = "Version 2.4";
static char *subject = "Generic Script Compiler";
static char *cpright =
"Copyright (c) 1994, 1995 Francisco Rosales <frosal@fi.upm.es>";

static char *copying =
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

static char *abstract =
"Abstract:\n"
"\n"
"    This tool generates a stripped binary executable version\n"
"    of the script specified at command line.\n"
"\n"
"    Binary version will be named with .x extension, and will usually be\n"
"    shorter than ascii one.\n"
"\n"
"    You can specify expiration date [-e] too, after which binary will\n"
"    refuse to be executed, displaying \"Contact with [-m]\" instead.\n"
"\n"
"    You can compile whatever interpreted script, but valid [-i], [-x]\n"
"    and [-l] options must be given.\n";

static char *usage =
"Usage: -f script [-e date] [-m addr] [-i iopt] [-x cmnd] [-l lopt] [-vCAh]";

static char *help =
"\n"
"    -e %s  Expiration date in mm/dd/yy format [NO]\n"
"    -m %s  e-Mail address to contact with at expiration [your provider]\n"
"    -f %s  File name of the script to compile\n"
"    -i %s  Inline option for this interpreter i.e: -e\n"
"    -x %s  eXec command, as a printf format i.e: exec(\\'%s\\',@ARGV);\n"
"    -l %s  Last option i.e: --\n"
"    -v     Verbose\n"
"    -C     Copying\n"
"    -A     Abstract\n"
"    -h     Help\n";

#include <sys/types.h>
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
#define SIZE 1024

static char *file = NULL;
static time_t date = ((unsigned) -1) >> 1;
static char *mail = "your provider";
static char *inlo = NULL;
static char *xecc = NULL;
static char *lsto = NULL;
static char shll[SIZE];
static char opts[SIZE];
static verbose = 0;
static debuging = 0;
static char *RTC =
"#define SIZE 4096"
"\n"
"#include <sys/types.h>"
"\n"
"#include <sys/stat.h>"
"\n"
"#include <sys/wait.h>"
"\n"
"#include <stdio.h>"
"\n"
"#include <stdlib.h>"
"\n"
"#include <string.h>"
"\n"
"#include <time.h>"
"\n"
"#include <unistd.h>"
"\n"
"extern char **environ;"
"\n"
"void zcat()"
"{"
	"char *argv[] ="
	"{\"zcat\", NULL};"
	"putenv(\"PATH=/bin:/usr/bin:/usr/ucb:/usr/local/bin\");"
	"execvp(argv[0], argv);"
	"perror(argv[0]);"
	"exit(1);"
"}"
"char *zread(int in)"
"{"
	"int tot, cnt;"
	"char *D;"
	"tot = SIZE;"
	"D = malloc(tot + SIZE);"
	"if (D == NULL)"
		"return NULL;"
	"memset(D, (int) ' ', --tot);"
	"D[tot++] = '\\n';"
	"while ((cnt = read(in, &D[tot], SIZE)) > 0) {"
		"tot += cnt;"
		"D = realloc(D, tot + SIZE);"
		"if (D == NULL)"
			"return NULL;"
	"}"
	"D[tot] = '\\0';"
	"close(in);"
	"if (cnt < 0)"
		"return NULL;"
	"tot -= SIZE;"
	"tot = tot > SIZE ? SIZE : tot;"
	"return &D[tot];"
"}"
"char *script(int argc, char **argv, char *shll, char *inlo, char *xecc)"
"{"
	"pid_t pid;"
	"int wz[2];"
	"int zx[2];"
	"char *D;"
	"if (pipe(zx))"
		"return NULL;"
	"switch (pid = fork()) {"
	"case -1:"
		"break;"
	"case 0:"
		"close(1);"
		"dup(zx[1]);"
		"close(zx[0]);"
		"close(zx[1]);"
		"if (pipe(wz))"
			"break;"
		"switch (fork()) {"
		"case -1:"
			"break;"
		"case 0:"
			"close(1);"
			"dup(wz[1]);"
			"close(wz[0]);"
			"close(wz[1]);"
			"writez();"
			"break;"
		"default:"
			"close(0);"
			"dup(wz[0]);"
			"close(wz[0]);"
			"close(wz[1]);"
			"zcat();"
		"}"
		"break;"
	"default:"
		"close(zx[1]);"
		"D = zread(zx[0]);"
		"if (waitpid(pid, NULL, 0) >= 0)"
			"return D;"
	"}"
	"return NULL;"
"}"
"void rmarg(char **argv, char *arg)"
"{"
	"for (; argv && *argv && *argv != arg; argv++);"
	"for (; argv && *argv; argv++)"
		"*argv = argv[1];"
"}"
"int chkenv(char *shll, int mask, int argc, int rm)"
"{"
	"struct stat statf;"
	"char buff[512];"
	"int l, m, a, c;"
	"char *string;"
	"if (stat(shll, &statf) < 0) {"
		"perror(shll);"
		"exit(1);"
	"}"
	"mask ^= (int) getpid();"
	"sprintf(buff, \"x%%x\", mask);"
	"string = getenv(buff);"
	"mask ^= (int) statf.st_dev ^ (int) statf.st_ino;"
	"l = strlen(buff);"
	"if (!string) {"
		"/* 1st */"
		"sprintf(&buff[l], \"=%%d %%d\", mask, argc);"
		"putenv(strdup(buff));"
		"return 0;"
	"}"
	"c = sscanf(string, \"%%d %%d%%c\", &m, &a, buff);"
	"if (c == 2 && m == mask) {"
		"/* 3rd */"
		"if (rm)"
			"rmarg(environ, &string[-l - 1]);"
		"return 1 + (argc - a);"
	"}"
	"return -1;"
"}"
"void debugexec(char *shll,  char **argv)"
"{"
	"int i;"
	"fprintf(stderr, \"shll=%%s\\n\", shll?shll:\"<null>\");"
	"for (i = 0; argv && argv[i]; i++)"
		"fprintf(stderr, \"argv[%%d]=%%s\\n\", i, argv[i]);"
"}"
"void xsh(int argc, char **argv, char *shll, char *opts, char *inlo, "
"char *xecc, char *lsto, int mask)"
"{"
	"char buff[512];"
	"int ret, i, j = 0;"
	"char **varg;"
	"ret = chkenv(shll, mask, argc, 0);"
	"if (ret < 0)"
		"return;"
	"varg = (char **) calloc(sizeof(char *), argc + 10);"
	"if (varg == NULL)"
		"return;"
	"varg[j++] = argv[0];"		/* My own name at execution */
	"if (ret && *opts)"
		"varg[j++] = opts;"	/* Options on 1st line of code */
	"if (*inlo)"
		"varg[j++] = inlo;"	/* Option introducing inline code */
	"if (ret) {"
		"xecc = script(argc, argv, shll, inlo, xecc);"
	"} else {"
		"if (*xecc) {"
			"sprintf(buff, xecc, argv[0]);"
			"xecc = buff;"
		"} else {"
			"xecc = argv[0];"
		"}"
	"}"
	"if (!xecc)"
		"return;"
	"varg[j++] = xecc;"		/* Script itself or Reexecute myself */
	"if (*lsto)"
		"varg[j++] = lsto;"	/* Option meaning last option */
	"i = 0;"
	"if (ret > 1) {"
		"j -= ret;"
		"i = ret;"
	"}"
	"for (; i <= argc; i++)"
		"varg[i + j] = argv[i];"/* Main run-time arguments */
	"if (ret && ret != chkenv(shll, mask, argc, 1))"
		"return;"
/* XXX	"debugexec(shll, varg);" */
	"execvp(shll, varg);"
	"perror(shll);"
	"exit(1);"
"}"
"void main(int argc, char **argv)"
"{"
	"char *stmp = \"%s\";"
	"char *shll = \"%s\";"
	"char *opts = \"%s\";"
	"char *inlo = \"%s\";"
	"char *xecc = \"%s\";"
	"char *lsto = \"%s\";"
	"char *mail = \"%s\";"
	"time_t date = %d;"
	"int mask = %d;"
	"if ((date - time(NULL)) < 0) {"
		"fprintf(stderr, \"%%s\\n\", stmp);"
		"fprintf(stderr, \"%%s: Out of date\\n\", argv[0]);"
		"fprintf(stderr, \"Contact with %%s\\n\", mail);"
		"exit(0);"
	"}"
	"xsh(argc, argv, shll, opts, inlo, xecc, lsto, mask);"
	"perror(argv[0]);"
	"exit(1);"
"}"
"\n";

static int error(char *type, char *frm, ...)
{
	va_list ap;
	int ret;
	extern int errno;
	extern char *sys_errlist[];
	char *frm2 = "\n";

	va_start(ap, frm);
	if (strchr(type, 's'))
		frm2 = ": %s\n";
	if(strchr(type, 'd') && !debuging)
		return 0;
	if(strchr(type, 'v') && !verbose)
		return 0;

	ret = fprintf(stderr, "%s", my_name);
	ret += vfprintf(stderr, frm, ap);
	ret += fprintf(stderr, frm2, sys_errlist[errno]);

	if (strchr(type, 'x'))
		exit(1);
	va_end(ap);
	return ret;
}

static int parse_an_arg(int argc, char *argv[])
{
	extern char *optarg;
	char *opts = "e:m:f:i:x:l:vCAh";
	char *nvv_fmt = " parse(-%c %s): Not a valid value";
	struct tm tmp[1];
	int cnt;
	char ctrl;

	switch (getopt(argc, argv, opts)) {
	case 'e':
		memset(tmp, 0, sizeof(tmp));
		cnt = sscanf(optarg, "%2d/%2d/%4d%c",
			 &tmp->tm_mon, &tmp->tm_mday, &tmp->tm_year, &ctrl);
		if (cnt == 3) {
			tmp->tm_mon--;
			if (tmp->tm_year > 99)
				tmp->tm_year -= 1900;
			date = mktime(tmp);
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
	case 'v':
		verbose++;
		break;
	case 'C':
		error("", " %s, %s", version, subject);
		error("", " %s", cpright);
		error("", " %s", copying);
		exit(0);
		break;
	case 'A':
		error("", " %s, %s", version, subject);
		error("", " %s", cpright);
		error("", " %s", abstract);
		exit(0);
		break;
	case 'h':
		error("", " %s, %s", version, subject);
		error("", " %s", cpright);
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

static int parse_args(int argc, char *argv[])
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
	return 0;
}

/*
 * NVI stands for Shells that complaint "Not Valid Identifier" on
 * environment variables with characters as "=|#:*?$ ".
 */
struct {
	char *shll;
	char *inlo;
	char *lsto;
	char *xecc;
} shellsDB[] = {
	{ "perl", "-e", "--", "exec(\\'%s\\',@ARGV);" },
	{ "rc",   "-c", "",   "builtin exec %s $*" },
	{ "sh",   "-c", "",   "exec %s \\\"$@\\\"" }, /* IRIX_nvi */
	{ "bash", "-c", "",   "exec %s \\\"$@\\\"" },
	{ "bsh",  "-c", "",   "exec %s \\\"$@\\\"" }, /* AIX_nvi */
	{ "Rsh",  "-c", "",   "exec %s \\\"$@\\\"" }, /* AIX_nvi */
	{ "ksh",  "-c", "--", "exec %s \\\"$@\\\"" },
	{ "tsh",  "-c", "--", "exec %s \\\"$@\\\"" }, /* AIX */
	{ "ash",  "-c", "--", "exec %s \\\"$@\\\"" }, /* Linux */
	{ "csh",  "-c", "-b", "exec %s $argv" }, /* AIX: No file for $0 */
	{ "tcsh", "-c", "-b", "exec %s $argv" },
	{ NULL,   NULL, NULL, NULL },
};

int eval_shell()
{
	FILE *i;
	char line[SIZE];
	int cnt;
	char *name;

	i = fopen(file, "r");
	if (!i)
		return -2;
	if (!fgets(line, SIZE, i))
		return -2;
	fclose(i);
	opts[0] = '\0';
	cnt = sscanf(line, " #! %s %s %c", shll, opts, opts);
	if (cnt < 1 || cnt > 2) {
		error("", " Invalid script's first line: %s", line);
		return -2;
	}
	name = strrchr(shll, (int) '/');
	if (*name == '/')
		name++;
	error("v", "shll=%s", name);
	if(*opts)
		error("v", "opts=%s", opts);
	for(cnt=0; shellsDB[cnt].shll; cnt++) {
		if(!strcmp(name, shellsDB[cnt].shll)) {
			if (!inlo)
				inlo = shellsDB[cnt].inlo;
			if (!xecc)
				xecc = shellsDB[cnt].xecc;
			if (!lsto)
				lsto = shellsDB[cnt].lsto;
		}
	}
	if (!inlo || !xecc || !lsto) {
		error("", " Unknown shell (%s): specify [-i][-x][-l]", name);
		return -2;
	}
	error("v", " [-i]=%s", inlo);
	error("v", " [-x]=%s", xecc);
	error("v", " [-l]=%s", lsto);
	return 0;
}

int script_to_C()
{
	char cmd[512];
	FILE *i, *o;
	int seed;
	int cnt, c;
	int Zc = 0;
	unsigned char Z[SIZE];

	sprintf(cmd, "compress -cf %s", file);
	i = popen(cmd, "r");
	if (!i)
		return -2;
	sprintf(cmd, "sort > %s.x.c", file);
	o = popen(cmd, "w");
	if (!o)
		return -2;

	seed = time(NULL);
	srand(seed);
	for (;;) {
		cnt = abs(rand()) % SIZE;
		if (!cnt)
			cnt = 1;
		cnt = fread(Z, 1, cnt, i);
		if (!cnt)
			break;
		Zc++;
		fprintf(o, "static unsigned char Z%d[%d]={", abs(rand()), cnt);
		for (c = 0; c < cnt - 1; c++)
			fprintf(o, "%#o,", Z[c]);
		fprintf(o, "%#o};\n", Z[c]);
	}
	pclose(i);
	srand(seed);
	fprintf(o, "void writez(){if(");
	for (c = 0; c < Zc; c++) {
		cnt = rand();
		cnt = abs(rand());
		fprintf(o, "(write(1,Z%d,sizeof(Z%d))<0)||", cnt, cnt);
	}
	fprintf(o, "0) return; exit(0); }\n");

	sprintf(cmd, "%s %s, %s\\n%s", my_name, version, subject, cpright);
	fprintf(o, RTC, cmd, shll, opts, inlo, xecc, lsto, mail, date, seed);
	pclose(o);
	return 0;
}

int make()
{
	char *cc, *cflags;
	char cmd[SIZE];

	cc = getenv("CC");
	if (!cc)
		cc = "cc";
	cflags = getenv("CFLAGS");
	if (!cflags) {
#ifdef _HPUX_SOURCE
		cflags = "-Wall -O -Ae";
#elif __GNUC__
		cflags = "-Wall -O2";
#else
		cflags = "";
#endif
	}
	sprintf(cmd, "%s %s %s.x.c -o %s.x", cc, cflags, file, file);
	error("v", ": %s", cmd);
	if (system(cmd))
		return -2;
	sprintf(cmd, "strip %s.x", file);
	error("v", ": %s", cmd);
	if (system(cmd))
		error("", ": It does not matter");
	return 0;
}

int do_all(int argc, char *argv[])
{
	if (eval_shell())
		return 1;
	if (script_to_C())
		return 1;
	if (make())
		return 1;
	return 0;
}

void main(int argc, char *argv[])
{
	putenv("LANG=");
	parse_args(argc, argv);
	if (do_all(argc, argv)) {
		perror(argv[0]);
		exit(1);
	}
	exit(0);
}

