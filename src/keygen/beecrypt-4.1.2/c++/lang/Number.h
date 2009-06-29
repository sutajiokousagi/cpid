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

/*!\file Number.h
 * \ingroup CXX_LANG_m
 */

#ifndef _BEECRYPT_CLASS_NUMBER_H
#define _BEECRYPT_CLASS_NUMBER_H

#include "beecrypt/api.h"

#ifdef __cplusplus

#include "beecrypt/c++/lang/Object.h"

namespace beecrypt {
	namespace lang {
		/*!\ingroup CXX_LANG_m
		 */
		class BEECRYPTCXXAPI Number : public beecrypt::lang::Object
		{
		public:
			virtual javabyte byteValue() const throw () = 0;
			virtual javashort shortValue() const throw () = 0;
			virtual javaint intValue() const throw () = 0;
			virtual javalong longValue() const throw () = 0;
			// virtual javafloat floatValue() const throw () = 0;
			// virtual javadouble doubeValue() const throw () = 0;
		};
	}
}

#endif

#endif
