/*
 * Copyright (c) 2004 Beeyond Software Holding BV
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "beecrypt/c++/provider/AESCipher.h"
#include "beecrypt/c++/provider/BeeCertificateFactory.h"
#include "beecrypt/c++/provider/BeeCertPathValidator.h"
#include "beecrypt/c++/provider/BaseProvider.h"
#include "beecrypt/c++/provider/BeeKeyFactory.h"
#include "beecrypt/c++/provider/BeeKeyStore.h"
#include "beecrypt/c++/provider/BeeSecureRandom.h"
#include "beecrypt/c++/provider/BlowfishCipher.h"
#include "beecrypt/c++/provider/DHAESCipher.h"
#include "beecrypt/c++/provider/DHAESParameters.h"
#include "beecrypt/c++/provider/DHKeyAgreement.h"
#include "beecrypt/c++/provider/DHKeyFactory.h"
#include "beecrypt/c++/provider/DHKeyPairGenerator.h"
#include "beecrypt/c++/provider/DHParameterGenerator.h"
#include "beecrypt/c++/provider/DHParameters.h"
#include "beecrypt/c++/provider/DSAKeyFactory.h"
#include "beecrypt/c++/provider/DSAKeyPairGenerator.h"
#include "beecrypt/c++/provider/DSAParameterGenerator.h"
#include "beecrypt/c++/provider/DSAParameters.h"
#include "beecrypt/c++/provider/HMACMD5.h"
#include "beecrypt/c++/provider/HMACSHA1.h"
#include "beecrypt/c++/provider/HMACSHA256.h"
#include "beecrypt/c++/provider/HMACSHA384.h"
#include "beecrypt/c++/provider/HMACSHA512.h"
#include "beecrypt/c++/provider/MD5Digest.h"
#include "beecrypt/c++/provider/MD5withRSASignature.h"
#include "beecrypt/c++/provider/PKCS12KeyFactory.h"
#include "beecrypt/c++/provider/RSAKeyFactory.h"
#include "beecrypt/c++/provider/RSAKeyPairGenerator.h"
#include "beecrypt/c++/provider/SHA1Digest.h"
#include "beecrypt/c++/provider/SHA256Digest.h"
#include "beecrypt/c++/provider/SHA384Digest.h"
#include "beecrypt/c++/provider/SHA512Digest.h"
#include "beecrypt/c++/provider/SHA1withDSASignature.h"
#include "beecrypt/c++/provider/SHA1withRSASignature.h"
#include "beecrypt/c++/provider/SHA256withRSASignature.h"
#include "beecrypt/c++/provider/SHA384withRSASignature.h"
#include "beecrypt/c++/provider/SHA512withRSASignature.h"

namespace {
	const String PROVIDER_NAME = UNICODE_STRING_SIMPLE("BeeCrypt++");
	const String PROVIDER_INFO = UNICODE_STRING_SIMPLE("Copyright (c) 2004 Beeyond Software Holding BV");
	const double PROVIDER_VERSION = 0.2;
}

extern "C" {

#if WIN32
# define PROVAPI __declspec(dllexport)
#else
# define PROVAPI
#endif

PROVAPI
void* beecrypt_AESCipher_create()
{
	return new beecrypt::provider::AESCipher();
}

PROVAPI
void* beecrypt_BeeCertificateFactory_create()
{
	return new beecrypt::provider::BeeCertificateFactory();
}

PROVAPI
void* beecrypt_BeeCertPathValidator_create()
{
	return new beecrypt::provider::BeeCertPathValidator();
}

PROVAPI
void* beecrypt_BeeKeyFactory_create()
{
	return new beecrypt::provider::BeeKeyFactory();
}

PROVAPI
void* beecrypt_BeeKeyStore_create()
{
	return new beecrypt::provider::BeeKeyStore();
}

PROVAPI
void* beecrypt_BeeSecureRandom_create()
{
	return new beecrypt::provider::BeeSecureRandom();
}

PROVAPI
void* beecrypt_BlowfishCipher_create()
{
	return new beecrypt::provider::BlowfishCipher();
}

PROVAPI
void* beecrypt_DHAESCipher_create()
{
	return new beecrypt::provider::DHAESCipher();
}

PROVAPI
void* beecrypt_DHAESParameters_create()
{
	return new beecrypt::provider::DHAESParameters();
}

PROVAPI
void* beecrypt_DHKeyAgreement_create()
{
	return new beecrypt::provider::DHKeyAgreement();
}

PROVAPI
void* beecrypt_DHKeyFactory_create()
{
	return new beecrypt::provider::DHKeyFactory();
}

PROVAPI
void* beecrypt_DHKeyPairGenerator_create()
{
	return new beecrypt::provider::DHKeyPairGenerator();
}

PROVAPI
void* beecrypt_HParameterGenerator_create()
{
	return new beecrypt::provider::DHParameterGenerator();
}

PROVAPI
void* beecrypt_DHParameters_create()
{
	return new beecrypt::provider::DHParameters();
}

PROVAPI
void* beecrypt_DSAKeyFactory_create()
{
	return new beecrypt::provider::DSAKeyFactory();
}

PROVAPI
void* beecrypt_DSAKeyPairGenerator_create()
{
	return new beecrypt::provider::DSAKeyPairGenerator();
}

PROVAPI
void* beecrypt_DSAParameterGenerator_create()
{
	return new beecrypt::provider::DSAParameterGenerator();
}

PROVAPI
void* beecrypt_DSAParameters_create()
{
	return new beecrypt::provider::DSAParameters();
}

PROVAPI
void* beecrypt_HMACMD5_create()
{
	return new beecrypt::provider::HMACMD5();
}

PROVAPI
void* beecrypt_HMACSHA1_create()
{
	return new beecrypt::provider::HMACSHA1();
}

PROVAPI
void* beecrypt_HMACSHA256_create()
{
	return new beecrypt::provider::HMACSHA256();
}

PROVAPI
void* beecrypt_HMACSHA384_create()
{
	return new beecrypt::provider::HMACSHA384();
}

PROVAPI
void* beecrypt_HMACSHA512_create()
{
	return new beecrypt::provider::HMACSHA512();
}

PROVAPI
void* beecrypt_MD5Digest_create()
{
	return new beecrypt::provider::MD5Digest();
}

PROVAPI
void* beecrypt_MD5withRSASignature_create()
{
	return new beecrypt::provider::MD5withRSASignature();
}

PROVAPI
void* beecrypt_PKCS12KeyFactory_create()
{
	return new beecrypt::provider::PKCS12KeyFactory();
}

PROVAPI
void* beecrypt_RSAKeyFactory_create()
{
	return new beecrypt::provider::RSAKeyFactory();
}

PROVAPI
void* beecrypt_RSAKeyPairGenerator_create()
{
	return new beecrypt::provider::RSAKeyPairGenerator();
}

PROVAPI
void* beecrypt_SHA1Digest_create()
{
	return new beecrypt::provider::SHA1Digest();
}

PROVAPI
void* beecrypt_SHA256Digest_create()
{
	return new beecrypt::provider::SHA256Digest();
}

PROVAPI
void* beecrypt_SHA384Digest_create()
{
	return new beecrypt::provider::SHA384Digest();
}

PROVAPI
void* beecrypt_SHA512Digest_create()
{
	return new beecrypt::provider::SHA512Digest();
}

PROVAPI
void* beecrypt_SHA1withDSASignature_create()
{
	return new beecrypt::provider::SHA1withDSASignature();
}

PROVAPI
void* beecrypt_SHA1withRSASignature_create()
{
	return new beecrypt::provider::SHA1withRSASignature();
}

PROVAPI
void* beecrypt_SHA256withRSASignature_create()
{
	return new beecrypt::provider::SHA256withRSASignature();
}

PROVAPI
void* beecrypt_SHA384withRSASignature_create()
{
	return new beecrypt::provider::SHA384withRSASignature();
}

PROVAPI
void* beecrypt_SHA512withRSASignature_create()
{
	return new beecrypt::provider::SHA512withRSASignature();
}

}

using namespace beecrypt::provider;

BaseProvider::BaseProvider() : Provider(PROVIDER_NAME, PROVIDER_VERSION, PROVIDER_INFO)
{
	_dlhandle = 0;

	putall();
}

BaseProvider::BaseProvider(void* dlhandle) : Provider(PROVIDER_NAME, PROVIDER_VERSION, PROVIDER_INFO)
{
	_dlhandle = dlhandle;

	putall();
}

BaseProvider::~BaseProvider()
{
}

void BaseProvider::putall()
{
	put("AlgorithmParameterGenerator.DH"           , "beecrypt_DHParameterGenerator_create");
	put("AlgorithmParameterGenerator.DSA"          , "beecrypt_DSAParameterGenerator_create");
	put("AlgorithmParameters.DH"                   , "beecrypt_DHParameters_create");
	put("AlgorithmParameters.DHAES"                , "beecrypt_DHAESParameters_create");
	put("AlgorithmParameters.DSA"                  , "beecrypt_DSAParameters_create");
	put("CertificateFactory.BEE"                   , "beecrypt_BeeCertificateFactory_create");
	put("CertPathValidator.BEE"                    , "beecrypt_BeeCertificateFactory_create");
	put("Cipher.AES"                               , "beecrypt_AESCipher_create");
	put("Cipher.Blowfish"                          , "beecrypt_BlowfishCipher_create");
	put("Cipher.DHAES"                             , "beecrypt_DHAESCipher_create");
	put("KeyAgreement.DH"                          , "beecrypt_DHKeyAgreement_create");
	put("KeyFactory.BEE"                           , "beecrypt_BeeKeyFactory_create");
	put("KeyFactory.DH"                            , "beecrypt_DHKeyFactory_create");
	put("KeyFactory.DSA"                           , "beecrypt_DSAKeyFactory_create");
	put("KeyFactory.RSA"                           , "beecrypt_RSAKeyFactory_create");
	put("KeyStore.BEE"                             , "beecrypt_BeeKeyStore_create");
	put("KeyPairGenerator.DH"                      , "beecrypt_DHKeyPairGenerator_create");
	put("KeyPairGenerator.DSA"                     , "beecrypt_DSAKeyPairGenerator_create");
	put("KeyPairGenerator.RSA"                     , "beecrypt_RSAKeyPairGenerator_create");
	put("Mac.HMAC-MD5"                             , "beecrypt_HMACMD5_create");
	put("Mac.HMAC-SHA-1"                           , "beecrypt_HMACSHA1_create");
	put("Mac.HMAC-SHA-256"                         , "beecrypt_HMACSHA256_create");
	put("Mac.HMAC-SHA-384"                         , "beecrypt_HMACSHA384_create");
	put("Mac.HMAC-SHA-512"                         , "beecrypt_HMACSHA512_create");
	put("MessageDigest.MD5"                        , "beecrypt_MD5Digest_create");
	put("MessageDigest.SHA-1"                      , "beecrypt_SHA1Digest_create");
	put("MessageDigest.SHA-256"                    , "beecrypt_SHA256Digest_create");
	put("MessageDigest.SHA-384"                    , "beecrypt_SHA384Digest_create");
	put("MessageDigest.SHA-512"                    , "beecrypt_SHA512Digest_create");
	put("SecretKeyFactory.PKCS#12/PBE"             , "beecrypt_PKCS12KeyFactory_create");
//  put("SecretKeyFactory.HMAC-MD5"                , "beecrypt_HMACMD5KeyFactory_create");
//  put("SecretKeyFactory.HMAC-SHA1"               , "beecrypt_HMACMD5KeyFactory_create");
//  put("SecretKeyFactory.HMAC-SHA256"             , "beecrypt_HMACMD5KeyFactory_create");
	put("SecureRandom.BEE"                         , "beecrypt_BeeSecureRandom_create");
	put("Signature.MD5withRSA"                     , "beecrypt_MD5withRSASignature_create");
	put("Signature.SHA1withDSA"                    , "beecrypt_SHA1withDSASignature_create");
	put("Signature.SHA1withRSA"                    , "beecrypt_SHA1withRSASignature_create");
	put("Signature.SHA256withRSA"                  , "beecrypt_SHA256withRSASignature_create");
	put("Signature.SHA384withRSA"                  , "beecrypt_SHA384withRSASignature_create");
	put("Signature.SHA512withRSA"                  , "beecrypt_SHA512withRSASignature_create");
	put("Alg.Alias.KeyAgreement.DiffieHellman"     , "KeyAgreement.DH");
	put("Alg.Alias.KeyFactory.DiffieHellman"       , "KeyFactory.DH");
	put("Alg.Alias.KeyPairGenerator.DiffieHellman" , "KeyPairGenerator.DH");
	put("Alg.Alias.Signature.DSS"                  , "Signature.SHA1withDSA");
	put("Alg.Alias.Signature.SHAwithDSA"           , "Signature.SHA1withDSA");
	put("Alg.Alias.Signature.SHA/DSA"              , "Signature.SHA1withDSA");
	put("Alg.Alias.Signature.SHA-1/DSA"            , "Signature.SHA1withDSA");
}

namespace {
	bool init = false;
	BaseProvider* singleton;
}

extern "C" {

#if WIN32
__declspec(dllexport)
BOOL WINAPI DllMain(HINSTANCE hInst, DWORD wDataSeg, LPVOID lpReserved)
{
	switch (wDataSeg)
	{
   	case DLL_PROCESS_ATTACH:
   		break;
	case DLL_PROCESS_DETACH:
		break;
   	}
   	return TRUE;
}

__declspec(dllexport)
#endif
const Provider& provider_const_ref(void *dlhandle)
{
	if (!init)
	{
		singleton = new BaseProvider(dlhandle);
		init = true;
	}
	return *singleton;
}

}
