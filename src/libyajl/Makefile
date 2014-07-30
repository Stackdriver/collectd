.PHONY: all clean distclean install package test distro
all: distro doc test test-api

distro:
	@cd build && make

doc:
	@cd build && make doc

test:
	@cd build && make test

test-api:
	@cd build && make test-api

clean:
	@cd build && make clean

distclean:
	@rm -rf Makefile build
	@rm -f yajl-*.tgz

install: distro doc
	@cd build && make install

package: all
	@echo \"compressing to yajl-2.1.1.tgz\"
	@cd build && tar czf ../yajl-*.tgz yajl-*
