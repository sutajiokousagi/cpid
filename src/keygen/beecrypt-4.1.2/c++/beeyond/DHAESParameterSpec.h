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

/*!\file DHAESParameterSpec.h
 * \ingroup CXX_BEEYOND_m
 */

#ifndef _CLASS_DHAESPARAMETERSPEC_H
#define _CLASS_DHAESPARAMETERSPEC_H

#ifdef __cplusplus

#include "beecrypt/c++/array.h"
using beecrypt::bytearray;
#include "beecrypt/c++/crypto/interfaces/DHPublicKey.h"
using beecrypt::crypto::interfaces::DHPublicKey;
#include "beecrypt/c++/lang/Object.h"
using beecrypt::lang::Object;
#include "beecrypt/c++/lang/String.h"
using beecrypt::lang::String;
#include "beecrypt/c++/security/spec/AlgorithmParameterSpec.h"
using beecrypt::security::spec::AlgorithmParameterSpec;

namespace beecrypt {
	namespace beeyond {
		/*!\ingroup CXX_BEEYOND_m
		 */
		class BEECRYPTCXXAPI DHAESParameterSpec : public beecrypt::lang::Object, public beecrypt::security::spec::AlgorithmParameterSpec
		{
		private:
			String _fullName;
			String _messageDigestAlgorithm;
			String _cipherAlgorithm;
			String _macAlgorithm;

			size_t _cipherKeyLength;
			size_t _macKeyLength;

			bytearray _mac;

			mpnumber _y;

		public:
			DHAESParameterSpec(const DHAESParameterSpec& copy);
			DHAESParameterSpec(const DHAESParameterSpec& copy, const mpnumber& key, const bytearray& mac);
			DHAESParameterSpec(const String& messageDigestAlgorithm, const String& cipherAlgorithm, const String& macAlgorithm, size_t cipherKeyLength = 0, size_t macKeyLength = 0);
			DHAESParameterSpec(const mpnumber& key, const bytearray& mac, const String& messageDigestAlgorithm, const String& cipherAlgorithm, const String& macAlgorithm, size_t cipherKeyLength = 0, size_t macKeyLength = 0);
			virtual ~DHAESParameterSpec();

			const String& getCipherAlgorithm() const throw ();
			const String& getMacAlgorithm() const throw ();
			const String& getMessageDigestAlgorithm() const throw ();

			size_t getCipherKeyLength() const throw ();
			size_t getMacKeyLength() const throw ();

			const mpnumber& getEphemeralPublicKey() const throw ();

			const bytearray& getMac() const throw ();

			const String& toString() const throw ();
		};
	}
}

#endif

#endif
