
CFLAGS+=-Wall -g -I.
# CFLAGS+=-Wall -I.

INCS = splinter.h

CORE_OBJS = atoms.o  \
       parser.o      \
       shot.o        \
       operators.o   \
       ringbuf.o     \
       strings.o     \
       misc.o        \
       hooks.o       \
       symbols.o

ALL_OBJS = atoms.o   \
       parser.o      \
       operators.o   \
       hooks.o       \
       misc.o        \
       ringbuf.o     \
       strings.o     \
       disass.o      \
       shot.o        \
       both.o        \
       exit.o        \
       core.o        \
       handlers.o    \
       symbols.o     \
       swap.o        \
       entry.o

all: module

version:
	# sed -r -i -e "s/(^\s*#define\s+SPLINTER_VERSION\s+).*/\1\"$(shell date +%y%m%d%H%M%S)\"/" config.h

test: version $(ALL_OBJS) test.o $(INCS)
	gcc $(CFLAGS) -g -o test $(ALL_OBJS) test.o

linker: version $(ALL_OBJS) linker.o clone.o $(INCS)
	gcc -o splinter.so -shared -nostartfiles $(ALL_OBJS) clone.o linker.o -ldl

validator: version $(CORE_OBJS) validator.o $(INCS)
	gcc -o validator $(CORE_OBJS) validator.o

module: version
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules

install:
	mkdir -p /lib/modules/$(shell uname -r)/misc
	cp splinter.ko /lib/modules/$(shell uname -r)/misc
	depmod -A
	cp splinter.py /usr/local/bin/splinter
	chmod +x /usr/local/bin/splinter
	cp splinter.cfg /etc
	chmod a-x /etc/splinter.cfg
	mkdir -p /usr/local/share/splinter.d
	cp -r splinter.d/* /usr/local/share/splinter.d

uninstall:
	rmmod splinter || true && rm -rf /usr/local/share/splinter.d /usr/local/bin/splinter /etc/splinter.cfg /lib/modules/$(shell uname -r)/misc/splinter.ko && depmod -A

clean:
	rm -rf *.o *.ko *~ *.mod.? .*.ko.cmd .*.o.cmd Module.markers Module.symvers modules.order .tmp_versions test .tmp_versions Makefile.xen splinter.so validator gmon.out

indent:
	indent \
		--blank-lines-after-declarations \
		--blank-lines-after-procedures \
		--blank-lines-before-block-comments \
		--braces-on-if-line \
		--braces-on-func-def-line \
		--brace-indent0 \
		--braces-after-struct-decl-line \
		--comment-indentation0 \
		--case-brace-indentation2 \
		--cuddle-do-while \
		--cuddle-else \
		--continuation-indentation2 \
		--case-indentation2 \
		--honour-newlines \
		--indent-level2 \
		--line-length120 \
		--comment-line-length120 \
		--no-space-after-function-call-names \
		--no-space-after-parentheses \
		--dont-break-procedure-type \
		--no-space-after-for \
		--no-space-after-if \
		--no-space-after-while \
		--dont-space-special-semicolon \
		--no-tabs \
		--preprocessor-indentation2 \
		--standard-output \
			splinter.h

