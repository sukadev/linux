
TEST_GEN_PROGS := ftw-1 ftw-2 ftw-3 ftw-sendfd ftw-badaddr
EXTRA_SOURCES := ftw-helpers.c

CFLAGS += -I$(CURDIR)

include ../../lib.mk

$(TEST_GEN_PROGS): LDLIBS += -lpthread

$(TEST_GEN_PROGS): $(EXTRA_SOURCES)
