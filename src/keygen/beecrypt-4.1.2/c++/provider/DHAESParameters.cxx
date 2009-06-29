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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "beecrypt/c++/provider/DHAESParameters.h"
#include "beecrypt/c++/security/ProviderException.h"
using beecrypt::security::ProviderException;

using namespace beecrypt::provider;

DHAESParameters::DHAESParameters()
{
	_spec = 0;
}

DHAESParameters::~DHAESParameters()
{
	if (_spec)
	{
		delete _spec;
		_spec = 0;
	}
}

AlgorithmParameterSpec* DHAESParameters::engineGetParameterSpec(const type_info& info) throw (InvalidParameterSpecException)
{
	if (info == typeid(AlgorithmParameterSpec) || info == typeid(DHAESParameterSpec))
	{
		if (_spec)
		{
			return new DHAESParameterSpec(*_spec);
		}
		else
			throw InvalidParameterSpecException("not initialized");
	}
	else
		throw InvalidParameterSpecException("expected a DHAESParameterSpec");
}

void DHAESParameters::engineInit(const AlgorithmParameterSpec& spec) throw (InvalidParameterSpecException)
{
	const DHAESParameterSpec* tmp = dynamic_cast<const DHAESParameterSpec*>(&spec);

	if (tmp)
	{
		if (_spec)
		{
			delete _spec;
			_spec = 0;
		}
		_spec = new DHAESParameterSpec(*tmp);
	}
	else
		throw InvalidParameterSpecException("expected a DHAESParameterSpec");
}

void DHAESParameters::engineInit(const byte*, size_t)
{
	throw ProviderException("not implemented");
}

void DHAESParameters::engineInit(const byte*, size_t, const String& format)
{
	throw ProviderException("not implemented");
}
