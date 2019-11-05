
all:	papi

clean:	clean-papi

#
#
#
.PHONY:	clean-luajit luajit

luajit:
	$(MAKE) -C luajit $(JX)

clean-luajit:
	$(MAKE) -C luajit clean

#
#
#
.PHONY:	config-papi clean-papi papi

config-papi:
	$(MAKE) -C papi/src -f Makefile.configure

papi:	config-papi
	$(MAKE) -C papi/src install

clean-papi:
	$(MAKE) -C papi/src clean
