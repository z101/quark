# quark version
VERSION = 0.1

# Customize below to fit your system

# paths
PREFIX = /usr/local
MANPREFIX = ${PREFIX}/share/man

# includes and libs
INCS = -I. -I/usr/include
LIBS = -L/usr/lib -lc

# flags
CPPFLAGS = -DVERSION=\"${VERSION}\" -D_POSIX_C_SOURCE=200809 -D_BSD_SOURCE
CFLAGS = -g -std=c99 -pedantic -Wall -O0 ${INCS} ${CPPFLAGS}
LDFLAGS = ${LIBS}
#LDFLAGS = -s ${LIBS}

# compiler and linker
CC = cc
