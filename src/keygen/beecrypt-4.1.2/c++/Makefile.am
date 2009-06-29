LIBBEECRYPT_CXX_LT_CURRENT = 10
LIBBEECRYPT_CXX_LT_AGE = 4
LIBBEECRYPT_CXX_LT_REVISION = 0

INCLUDES = -I$(top_srcdir)/..

AUTOMAKE_OPTIONS = gnu no-dependencies

SUBDIRS = lang io nio util security crypto beeyond . provider

libaltdir=$(prefix)/lib@LIBALT@
cxxdir=$(pkgincludedir)/c++

libalt_LTLIBRARIES = libbeecrypt_cxx.la

libbeecrypt_cxx_la_SOURCES = \
adapter.cxx \
bstream.cxx \
resource.cxx

libbeecrypt_cxx_la_LIBADD = ../libbeecrypt.la beeyond/libcxxbeeyond.la crypto/libcxxcrypto.la io/libcxxio.la lang/libcxxlang.la util/libcxxutil.la security/libcxxsecurity.la -licuuc -licuio
libbeecrypt_cxx_la_LDFLAGS = -no-undefined -version-info $(LIBBEECRYPT_CXX_LT_CURRENT):$(LIBBEECRYPT_CXX_LT_REVISION):$(LIBBEECRYPT_CXX_LT_AGE)

cxx_HEADERS = \
array.h \
bstream.h \
mutex.h

noinst_HEADERS = \
adapter.h \
resource.h

TESTS = testks testdsa testrsa testdhaes 

check_PROGRAMS = testks testdsa testrsa testdhaes 

testks_SOURCES = testks.cxx
testks_LDADD = libbeecrypt_cxx.la

testdsa_SOURCES = testdsa.cxx
testdsa_LDADD = libbeecrypt_cxx.la

testrsa_SOURCES = testrsa.cxx
testrsa_LDADD = libbeecrypt_cxx.la

testdhaes_SOURCES = testdhaes.cxx
testdhaes_LDADD = libbeecrypt_cxx.la
