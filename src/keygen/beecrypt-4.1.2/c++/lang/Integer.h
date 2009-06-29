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

/*!\file Integer.h
 * \ingroup CXX_LANG_m
 */

#ifndef _BEECRYPT_CLASS_INTEGER_H
#define _BEECRYPT_CLASS_INTEGER_H

#include "beecrypt/api.h"

#ifdef __cplusplus

#include "beecrypt/c++/lang/Comparable.h"
using beecrypt::lang::Comparable;
#include "beecrypt/c++/lang/Number.h"
using beecrypt::lang::Number;
#include "beecrypt/c++/lang/NumberFormatException.h"
using beecrypt::lang::NumberFormatException;

namespace beecrypt {
	namespace lang {
		/*!\ingroup CXX_LANG_m
		 */
		class BEECRYPTCXXAPI Integer : public beecrypt::lang::Number, public beecrypt::lang::Comparable<Integer>
		{
		private:
			javaint _val;

		public:
			static const javaint MIN_VALUE;
			static const javaint MAX_VALUE;

			static const String& toHexString(javaint l) throw ();
			static const String& toOctalString(javaint l) throw ();
			static const String& toString(javaint l) throw ();

			static javaint parseInteger(const String& s) throw (NumberFormatException);

		public:
			Integer(javaint value);
			Integer(const String& s) throw (NumberFormatException);
			virtual ~Integer() {};

			virtual javabyte byteValue() const throw ();
			virtual javashort shortValue() const throw ();
			virtual javaint intValue() const throw ();
			virtual javalong longValue() const throw ();

			virtual int compareTo(const Integer& anotherInteger) const throw ();
		};
	}
}

#endif

#endif
