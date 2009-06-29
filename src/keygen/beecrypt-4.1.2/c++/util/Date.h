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

/*!\file Date.h
 * \ingroup CXX_UTIL_m
 */

#ifndef _CLASS_DATE_H
#define _CLASS_DATE_H

#include "beecrypt/api.h"

#ifdef __cplusplus

#include "beecrypt/c++/lang/Cloneable.h"
using beecrypt::lang::Cloneable;
#include "beecrypt/c++/lang/Comparable.h"
using beecrypt::lang::Comparable;
#include "beecrypt/c++/lang/Object.h"
using beecrypt::lang::Object;
#include "beecrypt/c++/lang/String.h"
using beecrypt::lang::String;

namespace beecrypt {
	namespace util {
		/*!\ingroup CXX_UTIL_m
		 */
		class BEECRYPTCXXAPI Date : public beecrypt::lang::Object, public beecrypt::lang::Cloneable, public beecrypt::lang::Comparable<Date>
		{
		private:
			javalong _time;

		public:
			Date() throw ();
			Date(javalong) throw ();
			virtual ~Date() {};

			virtual bool equals(const Object&) const throw ();

			virtual Date* clone() const throw ();

			virtual int compareTo(const Date& anotherDate) const throw ();

			const Date& operator=(const Date&) throw ();

			bool after(const Date&) const throw ();
			bool before(const Date&) const throw ();

			javalong getTime() const throw ();
			void setTime(javalong) throw ();

			const String& toString() const;
		};
	}
}

#endif

#endif
