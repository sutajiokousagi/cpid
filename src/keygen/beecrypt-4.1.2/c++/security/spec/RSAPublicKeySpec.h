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

/*!\file RSAPublicKeySpec.h
 * \ingroup CXX_SECURITY_SPEC_m
 */

#ifndef _CLASS_RSAPUBLICKEYSPEC_H
#define _CLASS_RSAPUBLICKEYSPEC_H

#include "beecrypt/api.h"
#include "beecrypt/mpbarrett.h"

#ifdef __cplusplus

#include "beecrypt/c++/lang/Object.h"
using beecrypt::lang::Object;
#include "beecrypt/c++/security/spec/KeySpec.h"
using beecrypt::security::spec::KeySpec;

namespace beecrypt {
	namespace security {
		namespace spec {
			/*!\ingroup CXX_SECURITY_SPEC_m
			 */
			class BEECRYPTCXXAPI RSAPublicKeySpec : public beecrypt::lang::Object, public beecrypt::security::spec::KeySpec
			{
			private:
				mpbarrett _n;
				mpnumber _e;

			public:
				RSAPublicKeySpec(const mpbarrett& modulus, const mpnumber& publicExponent);
				virtual ~RSAPublicKeySpec();

				const mpbarrett& getModulus() const throw ();
				const mpnumber& getPublicExponent() const throw ();
			};
		}
	}
}

#endif

#endif
