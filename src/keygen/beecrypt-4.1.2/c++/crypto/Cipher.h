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

/*!\file Cipher.h
 * \ingroup CXX_CRYPTO_m
 */

#ifndef _CLASS_CIPHER_H
#define _CLASS_CIPHER_H

#ifdef __cplusplus

#include "beecrypt/c++/crypto/CipherSpi.h"
using beecrypt::crypto::CipherSpi;
#include "beecrypt/c++/crypto/NoSuchPaddingException.h"
using beecrypt::crypto::NoSuchPaddingException;
#include "beecrypt/c++/lang/Object.h"
using beecrypt::lang::Object;
#include "beecrypt/c++/security/Provider.h"
using beecrypt::security::Provider;
#include "beecrypt/c++/security/NoSuchAlgorithmException.h"
using beecrypt::security::NoSuchAlgorithmException;
#include "beecrypt/c++/security/NoSuchProviderException.h"
using beecrypt::security::NoSuchProviderException;
#include "beecrypt/c++/security/cert/Certificate.h"
using beecrypt::security::cert::Certificate;

namespace beecrypt {
	namespace crypto {
		/*!\ingroup CXX_CRYPTO_m
		 */
		class BEECRYPTCXXAPI Cipher : public beecrypt::lang::Object
		{
		public:
			static Cipher* getInstance(const String& transformation) throw (NoSuchAlgorithmException, NoSuchPaddingException);
			static Cipher* getInstance(const String& transformation, const String& provider) throw (NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException);
			static Cipher* getInstance(const String& transformation, const Provider& provider) throw (NoSuchAlgorithmException, NoSuchPaddingException);

			static const int ENCRYPT_MODE;
			static const int DECRYPT_MODE;
			static const int WRAP_MODE;
			static const int UNWRAP_MODE;

			static size_t getMaxAllowedKeyLength(const String& transformation) throw (NoSuchAlgorithmException);
			static AlgorithmParameterSpec* getMaxAllowedParameterSpec(const String& transformation) throw (NoSuchAlgorithmException);

		private:
			CipherSpi*      _cspi;
			String          _algo;
			const Provider* _prov;
			bool            _init;

		protected:
			Cipher(CipherSpi* cipherSpi, const Provider* provider, const String& transformation);

		public:
			virtual ~Cipher();

			bytearray* doFinal() throw (IllegalStateException, IllegalBlockSizeException, BadPaddingException);
			bytearray* doFinal(const bytearray& input) throw (IllegalStateException, IllegalBlockSizeException, BadPaddingException);
			size_t doFinal(bytearray& output, size_t outputOffset) throw (IllegalStateException, IllegalBlockSizeException, ShortBufferException, BadPaddingException);
			bytearray* doFinal(const byte* input, size_t inputOffset, size_t inputLength) throw (IllegalStateException, IllegalBlockSizeException, BadPaddingException);
			size_t doFinal(const byte* input, size_t inputOffset, size_t inputLength, bytearray& output, size_t outputOffset = 0) throw (IllegalStateException, IllegalBlockSizeException, ShortBufferException, BadPaddingException);
//			virtual size_t doFinal(ByteBuffer& input, ByteBuffer& output) throw (IllegalStateException, ShortBufferException, BadPaddingException);

			size_t getBlockSize() const throw ();
			size_t getKeySize() const throw ();
			size_t getOutputSize(size_t inputLength) throw ();
			AlgorithmParameters* getParameters() throw ();

			bytearray* getIV();

			void init(int opmode, const Certificate& certificate, SecureRandom* random = 0) throw (InvalidKeyException);
			void init(int opmode, const Key& key, SecureRandom* random = 0) throw (InvalidKeyException);
			void init(int opmode, const Key& key, AlgorithmParameters* params, SecureRandom* random = 0) throw (InvalidKeyException, InvalidAlgorithmParameterException);
			void init(int opmode, const Key& key, const AlgorithmParameterSpec& params, SecureRandom* random = 0) throw (InvalidKeyException, InvalidAlgorithmParameterException);

			bytearray* update(const bytearray& input) throw (IllegalStateException);
			bytearray* update(const byte* input, size_t inputOffset, size_t inputLength) throw (IllegalStateException);
			size_t update(const byte* input, size_t inputOffset, size_t inputLength, bytearray& output, size_t outputOffset = 0) throw (IllegalStateException, ShortBufferException);
//			size_t update(ByteBuffer& input, ByteBuffer& output) throw (IllegalStateException, ShortBufferException);

			const String& getAlgorithm() const throw ();
			const Provider& getProvider() const throw ();
		};
	}
}

#endif

#endif
