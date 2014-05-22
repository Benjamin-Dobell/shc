# Makefile
#
CFLAGS	= -Wall -O

all: shc test

test:
	@echo Testing match
	./shc -v -f match
	@echo Running match
	./match.x less  

clean:
	rm -f shc *.o *~ *.x *.x.c

install:
	install -c -s shc /bin/
	install -c -m 644 shc.1 /usr/man/man1

