INCLUDES = -I$(top_srcdir)/..

LIBS = -licuuc -licuio

AUTOMAKE_OPTIONS = gnu no-dependencies

noinst_LTLIBRARIES = libcxxbeeyond.la

libcxxbeeyond_la_SOURCES = \
AnyEncodedKeySpec.cxx \
BeeCertificate.cxx \
BeeCertPath.cxx \
BeeCertPathParameters.cxx \
BeeCertPathValidatorResult.cxx \
BeeEncodedKeySpec.cxx \
BeeInputStream.cxx \
BeeOutputStream.cxx \
DHAESParameterSpec.cxx \
PKCS12PBEKey.cxx

noinst_HEADERS = \
AnyEncodedKeySpec.h \
BeeCertificate.h \
BeeCertPath.h \
BeeCertPathParameters.h \
BeeCertPathValidatorResult.h \
BeeEncodedKeySpec.h \
BeeInputStream.h \
BeeOutputStream.h \
DHAESParameterSpec.h \
PKCS12PBEKey.h

TESTS = testcert

check_PROGRAMS = testcert

testcert_SOURCES = testcert.cxx
testcert_LDADD = ../libbeecrypt_cxx.la
