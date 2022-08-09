SUBDIRS = lib

if TESTS
    SUBDIRS += test
endif

AUTOMAKE_OPTIONS = subdir-objects

if BUILD_FSQD
    fsqd_CFLAGS = -I@LUSTRE_SRC_DIR@/lustre/include -I@LUSTRE_SRC_DIR@/lustre/include/uapi -I@TSM_SRC_DIR@/ -I@LTSM_SRC_DIR@/ -Ilib
    sbin_PROGRAMS = fsqd
    fsqd_SOURCES = fsqd.c lib/xattr.c
    fsqd_LDADD = lib/libfsqapi.a
endif

fsqc_CFLAGS = -Ilib
bin_PROGRAMS = fsqc
fsqc_SOURCES = fsqc.c
fsqc_LDADD = lib/libfsqapi.a
