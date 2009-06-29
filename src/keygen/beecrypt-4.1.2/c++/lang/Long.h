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

/*!\file Long.h
 * \ingroup CXX_LANG_m
 */

#ifndef _BEECRYPT_CLASS_LONG_H
#define _BEECRYPT_CLASS_LONG_H

#include "beecrypt/api.h"

#ifdef __cplusplus

#include "beecrypt/c++/lang/Comparable.h"
using beecrypt::lang::Comparable;
#include "beecrypt/c++/lang/Number.h"
using beecrypt::lang::Number;
#include "beecrypt/c++/lang/NumberFormatException.h"
using beecrypt::lang::NumberFormatException;
#include "beecrypt/c++/lang/String.h"
using beecrypt::lang::String;

namespace beecrypt {
	namespace lang {
		/*!\ingroup CXX_LANG_m
		 */
		class BEECRYPTCXXAPI Long : public beecrypt::lang::Number, public beecrypt::lang::Comparable<Long>
		{
		private:
			javalong _val;

		public:
			static const javalong MIN_VALUE;
			static const javalong MAX_VALUE;

			static const String& toHexString(javalong l) throw ();
			static const String& toOctalString(javalong l) throw ();
			static const String& toString(javalong l) throw ();

			static javalong parseLong(const String& s) throw (NumberFormatException);

		public:
			Long(javalong value);
			Long(const String& s) throw (NumberFormatException);
			virtual ~Long() {};

			virtual javabyte byteValue() const throw ();
			virtual javashort shortValue() const throw ();
			virtual javaint intValue() const throw ();
			virtual javalong longValue() const throw ();

			virtual int compareTo(const Long& anotherLong) const throw ();
		};
	}
}

#endif

#endif
