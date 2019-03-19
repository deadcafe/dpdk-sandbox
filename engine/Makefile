#
# Copyright (c) 2019 deadcafe.beef@gmal.com. All rights reserved.
#

ifeq ($(origin ROOT),undefined)
ROOT=..

all:
	$(MAKE) -C $(ROOT)

clean:
	$(MAKE) -C $(ROOT) clean-engine

else
##############################################################################
# from top dir
##############################################################################
include $(RTE_SDK)/mk/rte.vars.mk
export RTE_OUTPUT=$(OUTPUT)/engine

LIB := libeng.a

DC_CPPFLAGS=			\
	-I.			\
	-I$(ROOT)/compat	\
	-I$(OUTPUT)/libs/include	\
	-D_GNU_SOURCE

DC_CFLAGS=	\
	-O3 -g -std=gnu11 -Werror -Wall -Wextra -Wunused

CPPFLAGS += $(DC_CPPFLAGS)
CFLAGS += $(DC_CFLAGS)

SRCS-y := 		\
	linenoise.c	\
	task_if.c	\
	eng_conf.c	\
	eng_thread.c	\
	eng_mbuf.c	\
	eng_port.c	\
	eng_addon.c	\
	eng_pdump.c	\
	eng_log.c	\
	eng_cmd.c	\
	eng_cli.c	\
	eng_timer.c

#	task_rps.c	\

include $(RTE_SDK)/mk/rte.extlib.mk

##############################################################################
endif
