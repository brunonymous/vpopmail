# Don't edit Makefile! Use conf-* for configuration.

SHELL=/bin/sh

default: all

install: all
install-strip: all

cdb.a: \
makelib cdb_hash.o cdb_unpack.o cdb_seek.o
	./makelib cdb.a cdb_hash.o cdb_unpack.o cdb_seek.o

cdb_hash.o: \
compile cdb_hash.c cdb.h uint32.h
	./compile cdb_hash.c

cdb_seek.o: \
compile cdb_seek.c cdb.h uint32.h
	./compile cdb_seek.c

cdb_unpack.o: \
compile cdb_unpack.c cdb.h uint32.h
	./compile cdb_unpack.c

cdbmake.a: \
makelib cdbmake_pack.o cdbmake_hash.o cdbmake_add.o
	./makelib cdbmake.a cdbmake_pack.o cdbmake_hash.o \
	cdbmake_add.o

cdbmake_add.o: \
compile cdbmake_add.c cdbmake.h uint32.h
	./compile cdbmake_add.c

cdbmake_hash.o: \
compile cdbmake_hash.c cdbmake.h uint32.h
	./compile cdbmake_hash.c

cdbmake_pack.o: \
compile cdbmake_pack.c cdbmake.h uint32.h
	./compile cdbmake_pack.c

compile: \
warn-auto.sh conf-cc
	( cat warn-auto.sh; \
	echo exec "`head -1 conf-cc`" -fPIC '-c $${1+"$$@"}' \
	) > compile
	chmod 755 compile

load: \
warn-auto.sh conf-ld
	( cat warn-auto.sh; \
	echo 'main="$$1"; shift'; \
	echo exec "`head -1 conf-ld`" \
	'-o "$$main" "$$main".o $${1+"$$@"}' \
	) > load
	chmod 755 load

distclean: clean

clean: 
	rm -rf *.o *.a uint32.h systype

all: \
cdb.a cdbmake.a 

systype: \
find-systype.sh conf-cc trycpp.c
	( cat warn-auto.sh; \
	echo CC=\'`head -1 conf-cc`\'; \
	echo LD=\'`head -1 conf-ld`\'; \
	cat find-systype.sh; \
	) | sh > systype

makelib: \
warn-auto.sh systype
	( cat warn-auto.sh; \
	echo 'main="$$1"; shift'; \
	echo 'rm -f "$$main"'; \
	echo 'ar cr "$$main" $${1+"$$@"}'; \
	case "`cat systype`" in \
	sunos-5.*) ;; \
	unix_sv*) ;; \
	irix64-*) ;; \
	irix-*) ;; \
	dgux-*) ;; \
	hp-ux-*) ;; \
	sco*) ;; \
	*) echo 'ranlib "$$main"' ;; \
	esac \
	) > makelib
	chmod 755 makelib


uint32.h: \
tryulong32.c compile load uint32.h1 uint32.h2
	( ( ./compile tryulong32.c && ./load tryulong32 && \
	./tryulong32 ) >/dev/null 2>&1 \
	&& cat uint32.h2 || cat uint32.h1 ) > uint32.h
	rm -f tryulong32.o tryulong32
