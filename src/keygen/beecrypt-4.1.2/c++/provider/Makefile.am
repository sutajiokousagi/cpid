INCLUDES = -I$(top_srcdir)/..

LIBS = -licuuc -licuio

AUTOMAKE_OPTIONS = gnu no-dependencies

pkgaltlibdir=$(prefix)/lib@LIBALT@/beecrypt
pkgaltlib_LTLIBRARIES = base.la

nodist_sysconf_DATA = beecrypt.conf

base_la_SOURCES = \
AESCipher.cxx \
BeeCertificateFactory.cxx \
BeeCertPathValidator.cxx \
BaseProvider.cxx \
BeeKeyFactory.cxx \
BeeKeyStore.cxx \
BeeSecureRandom.cxx \
BlockCipher.cxx \
BlowfishCipher.cxx \
DHAESCipher.cxx \
DHAESParameters.cxx \
DHKeyAgreement.cxx \
DHKeyFactory.cxx \
DHKeyPairGenerator.cxx \
DHParameterGenerator.cxx \
DHParameters.cxx \
DHPrivateKeyImpl.cxx \
DHPublicKeyImpl.cxx \
DSAKeyFactory.cxx \
DSAKeyPairGenerator.cxx \
DSAParameterGenerator.cxx \
DSAParameters.cxx \
DSAPrivateKeyImpl.cxx \
DSAPublicKeyImpl.cxx \
HMAC.cxx \
HMACMD5.cxx \
HMACSHA1.cxx \
HMACSHA256.cxx \
HMACSHA384.cxx \
HMACSHA512.cxx \
KeyProtector.cxx \
MD5Digest.cxx \
MD5withRSASignature.cxx \
PKCS1RSASignature.cxx \
PKCS12KeyFactory.cxx \
RSAKeyFactory.cxx \
RSAKeyPairGenerator.cxx \
RSAPrivateCrtKeyImpl.cxx \
RSAPrivateKeyImpl.cxx \
RSAPublicKeyImpl.cxx \
SHA1Digest.cxx \
SHA256Digest.cxx \
SHA384Digest.cxx \
SHA512Digest.cxx \
SHA1withDSASignature.cxx \
SHA1withRSASignature.cxx \
SHA256withRSASignature.cxx \
SHA384withRSASignature.cxx \
SHA512withRSASignature.cxx

base_la_LDFLAGS = -module
base_la_LIBADD = $(top_builddir)/c++/libbeecrypt_cxx.la

noinst_HEADERS = \
AESCipher.h \
BeeCertificateFactory.h \
BeeCertPathValidator.h \
BaseProvider.h \
BeeKeyFactory.h \
BeeKeyStore.h \
BeeSecureRandom.h \
BlockCipher.h \
BlowfishCipher.h \
DHAESCipher.h \
DHAESParameters.h \
DHKeyAgreement.h \
DHKeyFactory.h \
DHKeyPairGenerator.h \
DHParameterGenerator.h \
DHParameters.h \
DHPrivateKeyImpl.h \
DHPublicKeyImpl.h \
DSAKeyFactory.h \
DSAKeyPairGenerator.h \
DSAParameterGenerator.h \
DSAParameters.h \
DSAPrivateKeyImpl.h \
DSAPublicKeyImpl.h \
HMAC.h \
HMACMD5.h \
HMACSHA1.h \
HMACSHA256.h \
HMACSHA384.h \
HMACSHA512.h \
KeyProtector.h \
MD5Digest.h \
MD5withRSASignature.h \
PKCS1RSASignature.h \
PKCS12KeyFactory.h \
RSAKeyFactory.h \
RSAKeyPairGenerator.h \
RSAPrivateCrtKeyImpl.h \
RSAPrivateKeyImpl.h \
RSAPublicKeyImpl.h \
SHA1Digest.h \
SHA256Digest.h \
SHA384Digest.h \
SHA512Digest.h \
SHA1withDSASignature.h \
SHA1withRSASignature.h \
SHA256withRSASignature.h \
SHA384withRSASignature.h \
SHA512withRSASignature.h 

beecrypt.conf:
	@echo "provider.1=$(pkgaltlibdir)/base.so" > beecrypt.conf
