
PROG=	lsop
MAN=	
SRCS=	lsop.c

CFLAGS += -Wall -Wextra
CFLAGS += -g -O0
LDFLAGS += -g

LDADD+=	-lprocstat
DPADD+=	${LIBUTIL} ${LIBPROCSTAT} ${LIBKVM}

.include <bsd.prog.mk>

# test library removed
test1: force
	mkdir -p test1/lib test1/libexec test1/bin
	cp /libexec/ld-elf.so.1 test1/libexec
	cp /lib/libc.so.7 test1/lib
	cp /bin/sleep test1/bin
	chroot ${PWD}/test1 /bin/sleep 60 &
	sleep 1
	rm test1/lib/libc.so.7

# test library replaced
test2: force
	mkdir -p test2/lib test2/libexec test2/bin
	cp /libexec/ld-elf.so.1 test2/libexec
	cp /lib/libc.so.7 test2/lib
	cp /bin/sleep test2/bin
	chroot ${PWD}/test2 /bin/sleep 60 &
	sleep 1
	cp /lib/libc.so.7 test2/lib/libc.so.7-
	mv test2/lib/libc.so.7- test2/lib/libc.so.7

# test binary removed
test3: force
	mkdir -p test3/lib test3/libexec test3/bin
	cp /libexec/ld-elf.so.1 test3/libexec
	cp /lib/libc.so.7 test3/lib
	cp /bin/sleep test3/bin
	chroot ${PWD}/test3 /bin/sleep 60 &
	sleep 1
	rm -f test3/bin/sleep

# test binary replaced
test4: force
	mkdir -p test4/lib test4/libexec test4/bin
	cp /libexec/ld-elf.so.1 test4/libexec
	cp /lib/libc.so.7 test4/lib
	cp /bin/sleep test4/bin
	chroot ${PWD}/test4 /bin/sleep 60 &
	sleep 1
	cp /bin/sleep test4/bin/sleep-
	mv -f test4/bin/sleep- test4/bin/sleep

alltests: test1 test2 test3 test4

whitelist: $(PROG)
	-./$(PROG) -c whitelist.txt

use-whitelist: $(PROG)
	./$(PROG) -w whitelist.txt

force:
