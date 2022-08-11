libfsqapi_a_SOURCES = fsqapi.c common.c log.c

if BUILD_FSQD
    libfsqapi_a_SOURCES += xattr.c
endif

noinst_LIBRARIES = libfsqapi.a
noinst_HEADERS = fsqapi.h xattr.h common.h log.h list.h queue.h chashtable.h qtable.h measurement.h util.h
