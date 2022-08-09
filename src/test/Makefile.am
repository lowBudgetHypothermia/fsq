AUTOMAKE_OPTIONS = subdir-objects

noinst_HEADERS = CuTest.h test_utils.h

test_fsqapi_CFLAGS = -I../lib
bin_PROGRAMS = test_fsqapi
test_fsqapi_SOURCES = test_fsqapi.c CuTest.c test_utils.c ../lib/xattr.c
test_fsqapi_LDADD = ../lib/libfsqapi.a

fsqbench_CFLAGS = -I../lib -I@LTSM_SRC_DIR@/
bin_PROGRAMS += fsqbench
fsqbench_SOURCES = fsqbench.c test_utils.c ../lib/xattr.c
fsqbench_LDADD = ../lib/libfsqapi.a
