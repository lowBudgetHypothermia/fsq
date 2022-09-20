libfsqapi_la_SOURCES = fsqapi.c common.c log.c

if BUILD_FSQD
    libfsqapi_la_SOURCES += xattr.c
endif

include_HEADERS = fsqapi.h common.h log.h
noinst_HEADERS = xattr.h list.h queue.h chashtable.h qtable.h measurement.h util.h

lib_LTLIBRARIES = libfsqapi.la
libfsqapi_la_LDFLAGS = -version-info 1:0
