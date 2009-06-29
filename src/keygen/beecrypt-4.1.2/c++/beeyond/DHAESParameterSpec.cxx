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

#include "beecrypt/c++/beeyond/DHAESParameterSpec.h"

#include "beecrypt/c++/lang/Long.h"
using beecrypt::lang::Long;

using namespace beecrypt::beeyond;

DHAESParameterSpec::DHAESParameterSpec(const DHAESParameterSpec& copy) : _fullName(copy._fullName), _mac(copy._mac)
{
	_messageDigestAlgorithm = copy._messageDigestAlgorithm;
	_cipherAlgorithm = copy._cipherAlgorithm;
	_macAlgorithm = copy._macAlgorithm;

	_cipherKeyLength = copy._cipherKeyLength;
	_macKeyLength = copy._macKeyLength;

	_y = copy._y;
}

DHAESParameterSpec::DHAESParameterSpec(const DHAESParameterSpec& copy, const mpnumber& key, const bytearray& mac) : _fullName(copy._fullName), _mac(mac)
{
	_messageDigestAlgorithm = copy._messageDigestAlgorithm;
	_cipherAlgorithm = copy._cipherAlgorithm;
	_macAlgorithm = copy._macAlgorithm;

	_cipherKeyLength = copy._cipherKeyLength;
	_macKeyLength = copy._macKeyLength;

	_y = key;
}

DHAESParameterSpec::DHAESParameterSpec(const String& messageDigestAlgorithm, const String& cipherAlgorithm, const String& macAlgorithm, size_t cipherKeyLength, size_t macKeyLength) : _mac()
{
	if (cipherKeyLength == 0 && macKeyLength == 0)
		_fullName = "DHAES(" + messageDigestAlgorithm + "," + cipherAlgorithm + "," + macAlgorithm + ")";
	else if (macKeyLength == 0)
		_fullName = "DHAES(" + messageDigestAlgorithm + "," + cipherAlgorithm + "," + macAlgorithm + "," + Long::toString(cipherKeyLength) + ")";
	else
		_fullName = "DHAES(" + messageDigestAlgorithm + "," + cipherAlgorithm + "," + macAlgorithm + "," + Long::toString(cipherKeyLength) + "," + Long::toString(macKeyLength) + ")";

	_messageDigestAlgorithm = messageDigestAlgorithm;
	_cipherAlgorithm = cipherAlgorithm;
	_macAlgorithm = macAlgorithm;

	_cipherKeyLength = cipherKeyLength;
	_macKeyLength = macKeyLength;
}

DHAESParameterSpec::DHAESParameterSpec(const mpnumber& key, const bytearray& mac, const String& messageDigestAlgorithm, const String& cipherAlgorithm, const String& macAlgorithm, size_t cipherKeyLength, size_t macKeyLength) : _mac(mac)
{
	if (cipherKeyLength == 0 && macKeyLength == 0)
		_fullName = "DHAES(" + messageDigestAlgorithm + "," + cipherAlgorithm + "," + macAlgorithm + ")";
	else if (macKeyLength == 0)
		_fullName = "DHAES(" + messageDigestAlgorithm + "," + cipherAlgorithm + "," + macAlgorithm + "," + Long::toString(cipherKeyLength) + ")";
	else
		_fullName = "DHAES(" + messageDigestAlgorithm + "," + cipherAlgorithm + "," + macAlgorithm + "," + Long::toString(cipherKeyLength) + "," + Long::toString(macKeyLength) + ")";

	_messageDigestAlgorithm = messageDigestAlgorithm;
	_cipherAlgorithm = cipherAlgorithm;
	_macAlgorithm = macAlgorithm;

	_cipherKeyLength = cipherKeyLength;
	_macKeyLength = macKeyLength;

	_y = key;
}

DHAESParameterSpec::~DHAESParameterSpec()
{
}

const String& DHAESParameterSpec::getCipherAlgorithm() const throw ()
{
	return _cipherAlgorithm;
}

size_t DHAESParameterSpec::getCipherKeyLength() const throw ()
{
	return _cipherKeyLength;
}

const String& DHAESParameterSpec::getMacAlgorithm() const throw ()
{
	return _macAlgorithm;
}

size_t DHAESParameterSpec::getMacKeyLength() const throw ()
{
	return _macKeyLength;
}

const String& DHAESParameterSpec::getMessageDigestAlgorithm() const throw ()
{
	return _messageDigestAlgorithm;
}

const mpnumber& DHAESParameterSpec::getEphemeralPublicKey() const throw ()
{
	return _y;
}

const bytearray& DHAESParameterSpec::getMac() const throw ()
{
	return _mac;
}

const String& DHAESParameterSpec::toString() const throw ()
{
	return _fullName;
}
