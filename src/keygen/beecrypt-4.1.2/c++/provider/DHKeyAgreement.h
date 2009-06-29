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

/*!\file DHKeyAgreement.h
 * \ingroup CXX_PROVIDER_m
 */

#ifndef _CLASS_DHKEYAGREEMENT_H
#define _CLASS_DHKEYAGREEMENT_H

#include "beecrypt/dlsvdp-dh.h"

#ifdef __cplusplus

#include "beecrypt/c++/crypto/KeyAgreementSpi.h"
using beecrypt::crypto::KeyAgreementSpi;

namespace beecrypt {
	namespace provider {
		class DHKeyAgreement : public beecrypt::crypto::KeyAgreementSpi
		{
		private:
			static const int UNINITIALIZED = 0;
			static const int INITIALIZED = 1;
			static const int SHARED = 2;

			int _state;

			dhparam _param;

			mpnumber _x;
			mpnumber _y;

			bytearray* _secret;

		protected:
			virtual void engineInit(const Key&, SecureRandom*) throw (InvalidKeyException);
			virtual void engineInit(const Key&, const AlgorithmParameterSpec&, SecureRandom*) throw (InvalidKeyException, InvalidAlgorithmParameterException);

			virtual Key* engineDoPhase(const Key&, bool) throw (InvalidKeyException, IllegalStateException);

			virtual bytearray* engineGenerateSecret() throw (IllegalStateException);
			virtual size_t engineGenerateSecret(bytearray&, size_t) throw (IllegalStateException, ShortBufferException);
			virtual SecretKey* engineGenerateSecret(const String&) throw (IllegalStateException, NoSuchAlgorithmException, InvalidKeyException);
		public:
			DHKeyAgreement();
			virtual ~DHKeyAgreement();
		};
	}
}

#endif

#endif
