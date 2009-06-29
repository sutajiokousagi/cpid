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

/*!\file KeyAgreement.h
 * \ingroup CXX_CRYPTO_m
 */

#ifndef _CLASS_KEYAGREEMENT_H
#define _CLASS_KEYAGREEMENT_H

#ifdef __cplusplus

#include "beecrypt/c++/crypto/KeyAgreementSpi.h"
using beecrypt::crypto::KeyAgreementSpi;
#include "beecrypt/c++/lang/Object.h"
using beecrypt::lang::Object;

namespace beecrypt {
	namespace crypto {
		/*!\ingroup CXX_CRYPTO_m
		 */
		class BEECRYPTCXXAPI KeyAgreement : public beecrypt::lang::Object
		{
		public:
			static KeyAgreement* getInstance(const String&) throw (NoSuchAlgorithmException);
			static KeyAgreement* getInstance(const String&, const String&) throw (NoSuchAlgorithmException, NoSuchProviderException);
			static KeyAgreement* getInstance(const String&, const Provider&) throw (NoSuchAlgorithmException);

		private:
			KeyAgreementSpi* _kspi;
			const Provider*  _prov;
			String           _algo;

		protected:
			KeyAgreement(KeyAgreementSpi* spi, const Provider* provider, const String& algorithm);

		public:
			virtual ~KeyAgreement();

			void init(const Key&, SecureRandom* = 0) throw (InvalidKeyException);
			void init(const Key&, const AlgorithmParameterSpec&, SecureRandom* = 0) throw (InvalidKeyException);

			Key* doPhase(const Key&, bool) throw (InvalidKeyException, IllegalStateException);

			bytearray* generateSecret() throw (IllegalStateException);
			size_t generateSecret(bytearray&, size_t) throw (IllegalStateException, ShortBufferException);
			SecretKey* generateSecret(const String&) throw (IllegalStateException, NoSuchAlgorithmException, InvalidKeyException);
		};
	}
}

#endif

#endif
