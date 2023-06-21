AUTOMAKE_OPTIONS = subdir-objects

noinst_HEADERS = CuTest.h test_utils.h

test_fsqapi_CFLAGS = -I../lib
bin_PROGRAMS = test_fsqapi
test_fsqapi_SOURCES = test_fsqapi.c CuTest.c test_utils.c
test_fsqapi_LDADD = ../lib/libfsqapi.la
