# Makefile
#

# For SCO
CFLAGS = -b elf -O -D_SVID

# For IRIX
CFLAGS = -xansi -fullwarn -O3 -g0

# For Solaris
CFLAGS = -fast -xO4 -s -v -Xa

# For HPUX
CFLAGS = -Wall -O -Ae

# For OSF1
CFLAGS = -w -verbose -fast -std1 -g0

# For GNU C compiler
CFLAGS = -Wall -O6 -s -pedantic

SHELL = /bin/sh

all: shc test

test: match.x
	@echo '***' Running $<
	./match.x sh
	@echo '***' Please try...	strings -n 7 $< \| more

match.x: match.x.c

match.x.c: match
	@echo '***' Compiling script $<
	CFLAGS="$(CFLAGS)" ./shc -v -r -f $<

clean:
	rm -f *.o *~ *.x.c

cleanall: clean
	rm -f shc *.x

install:
	install -c -s shc /usr/local/bin/
	install -c -m 644 shc.1 /usr/local/man/man1/

