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

#define BEECRYPT_CXX_DLL_EXPORT

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "beecrypt/c++/lang/Integer.h"
#include "beecrypt/c++/lang/String.h"
using beecrypt::lang::String;

#include <unicode/numfmt.h>

namespace {
	#if WIN32
	__declspec(thread) String* result = 0;
	#else
	__thread String* result = 0;
	#endif
};

using namespace beecrypt::lang;

const javaint Integer::MIN_VALUE = (((javaint) 1) << 31);
const javaint Integer::MAX_VALUE = ~MIN_VALUE;

const String& Integer::toString(javaint i) throw ()
{
	char tmp[12];

	#if SIZE_LONG == 4
	sprintf(tmp, "%d", i);
	#else
	sprintf(tmp, "%ld", i);
	#endif

	if (result)
		delete result;

	result = new String(tmp);

	return *result;
}

const String& Integer::toHexString(javaint i) throw ()
{
	char tmp[10];

	#if SIZEOF_LONG == 4
	sprintf(tmp, "%x", i);
	#else
	sprintf(tmp, "%lx", i);
	#endif

	if (result)
		delete result;

	result = new String(tmp);

	return *result;
}

const String& Integer::toOctalString(javaint i) throw ()
{
	char tmp[13];

	#if SIZEOF_INT == 4
	sprintf(tmp, "%o", i);
	#else
	sprintf(tmp, "%lo", i);
	#endif

	if (result)
		delete result;

	result = new String(tmp);

	return *result;
}

javaint Integer::parseInteger(const String& s) throw (NumberFormatException)
{
	UErrorCode status = U_ZERO_ERROR;

	NumberFormat* nf = NumberFormat::createInstance(status);

	if (nf)
	{
		Formattable fmt((int32_t) 0);

		nf->parse(s, fmt, status);

		delete nf;

		if (U_FAILURE(status))
			throw NumberFormatException("unable to parse string to javaint value");

		return fmt.getLong();
	}
	else
		throw RuntimeException("unable to create ICU NumberFormat instance");
}

Integer::Integer(javaint value)
{
	_val = value;
}

Integer::Integer(const String& s) throw (NumberFormatException)
{
	_val = parseInteger(s);
}

javabyte Integer::byteValue() const throw ()
{
	return (javabyte) _val;
}

javashort Integer::shortValue() const throw ()
{
	return (javashort) _val;
}

javaint Integer::intValue() const throw ()
{
	return _val;
}

javalong Integer::longValue() const throw ()
{
	return (javalong) _val;
}

int Integer::compareTo(const Integer& i) const throw ()
{
	if (_val == i._val)
		return 0;
	else if (_val < i._val)
		return -1;
	else
		return 1;
}
