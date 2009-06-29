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

/*!\file KeySpec.h
 * \ingroup CXX_SECURITY_SPEC_m
 */

#ifndef _INTERFACE_KEYSPEC_H
#define _INTERFACE_KEYSPEC_H

#include "beecrypt/api.h"

#ifdef __cplusplus

namespace beecrypt {
	namespace security {
		namespace spec {
			/*!\brief Transparent specification of key material that represent a cryptographic key
			 * \ingroup CXX_SECURITY_SPEC_m
			 */
			class BEECRYPTCXXAPI KeySpec
			{
			public:
				virtual ~KeySpec() {};
			};
		}
	}
}

#endif

#endif
