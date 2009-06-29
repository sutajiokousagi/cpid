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

#include "beecrypt/c++/lang/Long.h"
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

const javalong Long::MIN_VALUE = (((javalong) 1) << 63);
const javalong Long::MAX_VALUE = ~MIN_VALUE;

const String& Long::toString(javalong l) throw ()
{
	char tmp[21];

	#if WIN32
	sprintf(tmp, "%I64d", l);
	#elif SIZE_LONG == 8
	sprintf(tmp, "%ld", l);
	#elif HAVE_LONG_LONG
	sprintf(tmp, "%lld", l);
	#else
	# error
	#endif

	if (result)
		delete result;

	result = new String(tmp);

	return *result;
}

const String& Long::toHexString(javalong l) throw ()
{
	char tmp[18];

	#if WIN32
	sprintf(tmp, "%I64x", l);
	#elif SIZEOF_LONG == 8
	sprintf(tmp, "%lx", l);
	#elif HAVE_LONG_LONG
	sprintf(tmp, "%llx", l);
	#else
	# error
	#endif

	if (result)
		delete result;

	result = new String(tmp);

	return *result;
}

const String& Long::toOctalString(javalong l) throw ()
{
	char tmp[23];

	#if WIN32
	sprintf(tmp, "%I64o", l);
	#elif SIZEOF_LONG == 8
	sprintf(tmp, "%lo", l);
	#elif HAVE_LONG_LONG
	sprintf(tmp, "%llo", l);
	#else
	# error
	#endif

	if (result)
		delete result;

	result = new String(tmp);

	return *result;
}

javalong Long::parseLong(const String& s) throw (NumberFormatException)
{
	UErrorCode status = U_ZERO_ERROR;

	NumberFormat* nf = NumberFormat::createInstance(status);

	if (nf)
	{
		Formattable fmt((int64_t) 0);

		nf->parse(s, fmt, status);

		delete nf;

		if (U_FAILURE(status))
			throw NumberFormatException("unable to parse string to javalong value");

		return fmt.getInt64();
	}
	else
		throw RuntimeException("unable to create ICU NumberFormat instance");
}

Long::Long(javalong value)
{
	_val = value;
}

Long::Long(const String& s) throw (NumberFormatException)
{
	_val = parseLong(s);
}

javabyte Long::byteValue() const throw ()
{
	return (javabyte) _val;
}

javashort Long::shortValue() const throw ()
{
	return (javashort) _val;
}

javaint Long::intValue() const throw ()
{
	return (javaint) _val;
}

javalong Long::longValue() const throw ()
{
	return _val;
}

int Long::compareTo(const Long& l) const throw ()
{
	if (_val == l._val)
		return 0;
	else if (_val < l._val)
		return -1;
	else
		return 1;
}
