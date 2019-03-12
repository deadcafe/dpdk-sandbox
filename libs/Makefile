
all:	papi

clean:	clean-papi

#
#
#
.PHONY:	clean-luajit luajit

luajit:

clean-luajit:


#
#
#
.PHONY:	config-papi clean-papi papi

config-papi:
	$(MAKE) -C papi/src -f Makefile.configure

papi:	config-papi
	$(MAKE) -C papi/src $(JX) all
	$(MAKE) -C papi/src install

clean-papi:
	$(MAKE) -C papi/src clean
