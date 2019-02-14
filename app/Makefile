#
# Copyright (c) 2019 deadcafe.beef@gmal.com. All rights reserved.
#

ifeq ($(origin ROOT),undefined)
ROOT=..

all:
	$(MAKE) -C $(ROOT)

clean:
	$(MAKE) -C $(ROOT) clean-app

else
##############################################################################
# from top dir
##############################################################################
include $(RTE_SDK)/mk/rte.vars.mk
export RTE_OUTPUT=$(OUTPUT)/app

TARGET := hoge

APP = $(TARGET)

DC_CPPFLAGS=			\
	-I.			\
	-I$(ROOT)/compat	\
	-I$(ROOT)/engine	\
	-D_GNU_SOURCE

DC_CFLAGS=	\
	-O3 -g -std=gnu11 -Werror -Wall -W -Wunused -mrtm -mhle

LDLIBS = -L$(OUTPUT)/engine/lib -leng

CPPFLAGS += $(DC_CPPFLAGS)
CFLAGS += $(DC_CFLAGS)

SRCS-y := 		\
	global_db.c	\
	task_null.c	\
	task_busy.c	\
	main.c

include $(RTE_SDK)/mk/rte.extapp.mk

##############################################################################
endif
