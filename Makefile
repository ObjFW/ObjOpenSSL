LIB = objopenssl
LIB_MAJOR = 0
LIB_MINOR = 0

CPPFLAGS += -Wall -g
LIBS += -lssl -lcrypto -lz

includedir = ObjOpenSSL
prefix ?= /usr/local
INSTALL ?= install

LIB_PREFIX = `objfw-config --lib-prefix`
LIB_SUFFIX = `objfw-config --lib-suffix`
LIB_FILE = ${LIB_PREFIX}${LIB}${LIB_SUFFIX}

.SILENT:

all:
	objfw-compile --lib ${LIB_MAJOR}.${LIB_MINOR} ${CPPFLAGS} ${LIBS} \
		-o ${LIB} src/*.m

install: install-lib install-headers

install-lib: all
	mkdir -p ${destdir}${prefix}/lib
	export LIB_MAJOR=${LIB_MAJOR}; \
	export LIB_MINOR=${LIB_MINOR}; \
	echo "Installing ${LIB_FILE}..."; \
	${INSTALL} -m 755 ${LIB_FILE} ${destdir}${prefix}/lib/${LIB_FILE}

install-headers:
	mkdir -p ${destdir}${prefix}/include/${includedir}
	cd src && for i in *.h; do \
		echo "Installing $$i..."; \
		install -m 644 $$i \
			${destdir}${prefix}/include/${includedir}/$$i; \
	done

clean:
	export LIB_MAJOR=${LIB_MAJOR}; \
	export LIB_MINOR=${LIB_MINOR}; \
	for i in src/*.o ${LIB_FILE}; do \
		echo "Deleting $$i..."; \
		rm -f $$i; \
	done
