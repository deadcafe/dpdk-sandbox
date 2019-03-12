#
# Copyright (c) 2019 deadcafe.beef@gmail.com. All rights reserved.
#

export LC_ALL=C

export ROOT=$(CURDIR)
export BUILD_DIR=build
export OUTPUT=$(ROOT)/$(BUILD_DIR)

export RTE_SDK=$(ROOT)/dpdk
export RTE_TARGET=../$(BUILD_DIR)
export RTE_OUTPUT=$(OUTPUT)

HTML_DIR=$(ROOT)/html
DPDK_CONFIG=x86_64-native-linuxapp-gcc

PROCESSORS=$(shell grep processor /proc/cpuinfo | wc -l)

JX = -j$(PROCESSORS)

#
# build options
#
.PHONY:	all config clean tags

all:	app

clean:	clean-engine

clean-all:	clean clean-dpdk clean-tags

tags:
	-@ htags --suggest2

clean-bin:
	-@ rm -rf $(BUILD_DIR)

clean-tags:
	-@ rm -rf HTML GPATH GRTAGS GTAGS

#
# Engine
#
.PHONY:	engine clean-engine

engine:
	$(MAKE) $(JX) -C engine all

clean-engine:
	$(MAKE) $(JX) -C engine clean

#
# App
#
.PHONY:	app clean-app

app:	engine
	$(MAKE) $(JX) -C app all

clean-app:
	$(MAKE) $(JX) -C app clean

#
# DPDK
#
.PHONY:	clean-dpdk dpdk config-dpdk

dpdk:	config-dpdk
	$(MAKE) $(JX) -C $(RTE_SDK) all

config-dpdk:
	$(MAKE) -C $(RTE_SDK) config T=$(DPDK_CONFIG)

clean-dpdk:	
	$(MAKE) $(JX) -C $(RTE_SDK) clean


#
# libs
#
.PHONY:	clean-libs libs

libs:
	$(MAKE) -C libs all JX=$(JX)

clean-libs:	
	$(MAKE) $(JX) -C libs JX=$(JX) clean


