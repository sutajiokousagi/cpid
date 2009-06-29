INCLUDES = -I$(top_srcdir)/..

AUTOMAKE_OPTIONS = gnu no-dependencies

noinst_LTLIBRARIES = libcxxnio.la
cxxniodir= $(pkgincludedir)/c++/nio

libcxxnio_la_SOURCES = \
Buffer.cxx \
ByteOrder.cxx \
InvalidMarkException.cxx \
ReadOnlyBufferException.cxx

cxxnio_HEADERS = \
Buffer.h \
ByteOrder.h \
InvalidMarkException.h \
ReadOnlyBufferException.h
