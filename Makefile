# quark - simple httpd get daemon

include config.mk

SRC = quark.c
OBJ = ${SRC:.c=.o}

all: options quark

options:
	@echo quark build options:
	@echo "CFLAGS   = ${CFLAGS}"
	@echo "LDFLAGS  = ${LDFLAGS}"
	@echo "CC       = ${CC}"

.c.o:
	@echo CC $<
	@${CC} -c ${CFLAGS} $<

${OBJ}: config.mk config.h

config.h:
	@echo creating $@ from config.def.h
	@cp config.def.h $@

quark: ${OBJ}
	@echo CC -o $@
	@${CC} -o $@ ${OBJ} ${LDFLAGS}
	@strip $@

clean:
	@echo cleaning
	@rm -f quark ${OBJ} quark-${VERSION}.tar.gz

dist: clean
	@echo creating dist tarball
	@mkdir -p quark-${VERSION}
	@cp -R LICENSE Makefile README config.mk ${SRC} quark-${VERSION}
	@tar -cf quark-${VERSION}.tar quark-${VERSION}
	@gzip quark-${VERSION}.tar
	@rm -rf quark-${VERSION}

install: all
	@echo installing executable file to ${DESTDIR}${PREFIX}/bin
	@mkdir -p ${DESTDIR}${PREFIX}/bin
	@cp -f quark ${DESTDIR}${PREFIX}/bin
	@chmod 755 ${DESTDIR}${PREFIX}/bin/quark
	@echo installing manual page to ${DESTDIR}${MANPREFIX}/man1
	@mkdir -p ${DESTDIR}${MANPREFIX}/man1

uninstall:
	@echo removing executable file from ${DESTDIR}${PREFIX}/bin
	@rm -f ${DESTDIR}${PREFIX}/bin/quark
	@echo removing manual page from ${DESTDIR}${MANPREFIX}/man1

.PHONY: all options clean dist install uninstall
