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

#include "beecrypt/c++/provider/DHAESCipher.h"
#include "beecrypt/c++/provider/DHPublicKeyImpl.h"
#include "beecrypt/c++/crypto/SecretKeyFactory.h"
using beecrypt::crypto::SecretKeyFactory;
#include "beecrypt/c++/crypto/spec/SecretKeySpec.h"
using beecrypt::crypto::spec::SecretKeySpec;
#include "beecrypt/c++/security/ProviderException.h"
using beecrypt::security::ProviderException;

#include <unicode/ustream.h>

using namespace beecrypt::provider;

DHAESCipher::DHAESCipher()
{
	_spec = 0;
	_srng = 0;

	_kpg = 0;
	_ka = 0;

	_d = 0;
	_c = 0;
	_m = 0;

	_msg = 0;

	try
	{
		_kpg = KeyPairGenerator::getInstance("DiffieHellman");
		_ka = KeyAgreement::getInstance("DiffieHellman");
	}
	catch (NoSuchAlgorithmException e)
	{
		throw ProviderException(e.getMessage());
	}
}

DHAESCipher::~DHAESCipher()
{
	if (_spec)
	{
		delete _spec;
		_spec = 0;
	}
	if (_kpg)
	{
		delete _kpg;
		_kpg = 0;
	}
	if (_ka)
	{
		delete _ka;
		_ka = 0;
	}
	if (_m)
	{
		delete _m;
		_m = 0;
	}
	if (_c)
	{
		delete _c;
		_c = 0;
	}
	if (_d)
	{
		delete _d;
		_d = 0;
	}
	if (_msg)
	{
		delete _msg;
		_msg = 0;
	}
	_srng = 0;
}

bytearray* DHAESCipher::engineDoFinal(const byte* input, size_t inputOffset, size_t inputLength) throw (IllegalBlockSizeException, BadPaddingException)
{
	bytearray* tmp;

	if (_buf)
	{
		bytearray ciphertext;

		_buf->write(input, inputOffset, inputLength);
		_buf->toByteArray(ciphertext);

		if (_m->doFinal(ciphertext) == _spec->getMac())
		{
			// MAC matches; we can decrypt
			tmp = _c->doFinal(ciphertext);
		}
		else
			tmp = 0;
	}
	else
	{
		tmp = _c->doFinal(input, inputOffset, inputLength);

		_m->update(*tmp);

		DHAESParameterSpec* newspec = new DHAESParameterSpec(_msg->getY(), _m->doFinal(), _spec->getMessageDigestAlgorithm(), _spec->getCipherAlgorithm(), _spec->getMacAlgorithm(), _spec->getCipherKeyLength(), _spec->getMacKeyLength());

		delete _spec;

		_spec = newspec;
	}

	reset();

	return tmp;
}

size_t DHAESCipher::engineDoFinal(const byte* input, size_t inputOffset, size_t inputLength, bytearray& output, size_t outputOffset) throw (ShortBufferException, IllegalBlockSizeException, BadPaddingException)
{
	size_t tmp;

	if (_buf)
	{
		bytearray ciphertext;

		_buf->write(input, inputOffset, inputLength);
		_buf->toByteArray(ciphertext);

		if (_m->doFinal(ciphertext) == _spec->getMac())
		{
			// Mac matches; we can decrypt
			tmp = _c->doFinal(ciphertext.data(), 0, ciphertext.size(), output, outputOffset);
		}
		else
			tmp = 0;
	}
	else
	{
		tmp = _c->doFinal(input, inputOffset, inputLength, output, outputOffset);

		_m->update(output.data(), outputOffset, tmp);

		DHAESParameterSpec* newspec = new DHAESParameterSpec(_msg->getY(), _m->doFinal(), _spec->getMessageDigestAlgorithm(), _spec->getCipherAlgorithm(), _spec->getMacAlgorithm(), _spec->getCipherKeyLength(), _spec->getMacKeyLength());

		delete _spec;

		_spec = newspec;
	}

	reset();

	return tmp;
}

size_t DHAESCipher::engineGetBlockSize() const throw ()
{
	return _c->getBlockSize();
}

bytearray* DHAESCipher::engineGetIV()
{
	return _c->getIV();
}

size_t DHAESCipher::engineGetOutputSize(size_t inputLength) throw ()
{
	return _c->getOutputSize(inputLength + (_buf ? _buf->size() : 0));
}

AlgorithmParameters* DHAESCipher::engineGetParameters() throw ()
{
	AlgorithmParameters* tmp = 0;

	try
	{
		tmp = AlgorithmParameters::getInstance("DHAES");

		tmp->init(*_spec);
	}
	catch (InvalidAlgorithmParameterException e)
	{
		delete tmp;

		throw ProviderException(e.getMessage());
	}
	catch (NoSuchAlgorithmException e)
	{
		throw ProviderException(e.getMessage());
	}

	return tmp;
}

void DHAESCipher::engineInit(int opmode, const Key& key, SecureRandom* random) throw (InvalidKeyException)
{
	throw ProviderException("DHAESCipher must be initialized with a key and parameters");
}

void DHAESCipher::engineInit(int opmode, const Key& key, AlgorithmParameters* params, SecureRandom* random) throw (InvalidKeyException, InvalidAlgorithmParameterException)
{
	if (params)
	{
		AlgorithmParameterSpec* tmp;
		try
		{
			tmp = params->getParameterSpec(typeid(DHAESParameterSpec));
			engineInit(opmode, key, *tmp, random);
			delete tmp;
		}
		catch (InvalidParameterSpecException e)
		{
			throw InvalidAlgorithmParameterException(e.getMessage());
		}
		catch (...)
		{
			delete tmp;
			throw;
		}
	}
	else
		engineInit(opmode, key, random);
}

void DHAESCipher::engineInit(int opmode, const Key& key, const AlgorithmParameterSpec& params, SecureRandom *random) throw (InvalidKeyException, InvalidAlgorithmParameterException)
{
	const DHAESParameterSpec* tmp = dynamic_cast<const DHAESParameterSpec*>(&params);

	if (tmp)
	{
		if (_spec)
		{
			delete _spec;
			_spec = 0;
		}

		if (_d)
		{
			delete _d;
			_d = 0;
		}
		if (_c)
		{
			delete _c;
			_c = 0;
		}
		if (_m)
		{
			delete _m;
			_m = 0;
		}

		try
		{
			_d = MessageDigest::getInstance(tmp->getMessageDigestAlgorithm());
			_c = Cipher::getInstance(tmp->getCipherAlgorithm() + "/CBC/PKCS5Padding");
			_m = Mac::getInstance(tmp->getMacAlgorithm());
		}
		catch (NoSuchAlgorithmException e)
		{
			throw InvalidAlgorithmParameterException(e.getMessage());
		}

		if (tmp->getCipherKeyLength() == 0)
		{
			if (tmp->getCipherKeyLength() != 0)
				throw new InvalidAlgorithmParameterException("DHAESParameterSpec invalid: if cipher key length equals 0 then mac key length must also be 0");
		}
		else
		{
			size_t total = _d->getDigestLength();

			if (tmp->getCipherKeyLength() >= total)
				throw new InvalidAlgorithmParameterException("DHAESParameterSpec invalid: cipher key length must be less than digest size");

			if (tmp->getMacKeyLength() >= total)
				throw new InvalidAlgorithmParameterException("DHAESParameterSpec invalid: mac key length must be less than digest size");

			if (tmp->getCipherKeyLength() + tmp->getMacKeyLength() > total)
				throw new InvalidAlgorithmParameterException("DHAESParameterSpec invalid: sum of cipher and mac key length exceeds digest size");
		}

		_spec = new DHAESParameterSpec(*tmp);
	}
	else
		throw InvalidAlgorithmParameterException("not a DHAESParameterSpec");

	if (opmode == Cipher::ENCRYPT_MODE)
	{
		const DHPublicKey* pub = dynamic_cast<const DHPublicKey*>(&key);
		if (pub)
		{
			_enc = pub;
			_dec = 0;
			_buf = 0;
			_opmode = Cipher::ENCRYPT_MODE;
		}
		else
			throw InvalidKeyException("DHPublicKey expected when encrypting");
	}
	else if (opmode == Cipher::DECRYPT_MODE)
	{
		const DHPrivateKey* pri = dynamic_cast<const DHPrivateKey*>(&key);
		if (pri)
		{
			_enc = 0;
			_dec = pri;
			_buf = new ByteArrayOutputStream();
			_opmode = Cipher::DECRYPT_MODE;
		}
		else
			throw InvalidKeyException("DHPrivateKey expected when decrypting");
	}
	else
		throw ProviderException("unsupported opmode");

	_srng = random;

	reset();
}

bytearray* DHAESCipher::engineUpdate(const byte* input, size_t inputOffset, size_t inputLength)
{
	if (_buf)
	{
		_buf->write(input, inputOffset, inputLength);

		return 0;
	}
	else
	{
		return _c->update(input, inputOffset, inputLength);
	}
}

size_t DHAESCipher::engineUpdate(const byte* input, size_t inputOffset, size_t inputLength, bytearray& output, size_t outputOffset) throw (ShortBufferException)
{
	if (_buf)
	{
		_buf->write(input, inputOffset, inputLength);

		return 0;
	}
	else
	{
		return _c->update(input, inputOffset, inputLength, output, outputOffset);
	}
}

void DHAESCipher::engineSetMode(const String& mode) throw (NoSuchAlgorithmException)
{
	throw ProviderException("unsupported method");
}

void DHAESCipher::engineSetPadding(const String& padding) throw (NoSuchPaddingException)
{
	throw ProviderException("unsupported method");
}

void DHAESCipher::reset()
{
	if (_msg)
	{
		delete _msg;
		_msg = 0;
	}

	try
	{
		if (_buf)
		{
			_msg = new DHPublicKeyImpl(_dec->getParams(), _spec->getEphemeralPublicKey());

			_ka->init(*_dec, _srng);
			_ka->doPhase(*_msg, true);
		}
		else
		{
			// generate an ephemeral keypair
			_kpg->initialize(DHParameterSpec(_enc->getParams()), _srng);

			KeyPair* pair;

			try
			{
				pair = _kpg->generateKeyPair();

				_msg = new DHPublicKeyImpl(dynamic_cast<const DHPublicKey&>(pair->getPublic()));

				_ka->init(pair->getPrivate(), _srng);
				_ka->doPhase(*_enc, true);

				delete pair;
			}
			catch (...)
			{
				delete pair;

				throw ProviderException();
			}

		}

		const mpnumber& y = _msg->getY();

		size_t bits = mpnbits(&y);
		size_t bytes = ((bits+7) >> 3) + (((bits&7) == 0) ? 1 : 0);

		bytearray tmp(bytes);

		i2osp(tmp.data(), bytes, y.data, y.size);

		_d->reset();
		_d->update(tmp);
		_d->update(*_ka->generateSecret());

		bytearray key(_d->getDigestLength());

		_d->digest(key.data(), 0, key.size());

		size_t cl = _spec->getCipherKeyLength(), ml = _spec->getMacKeyLength();
		SecretKeySpec *cipherKeySpec, *macKeySpec;

		if ((cl & 0x3) || (ml & 0x3))
			throw InvalidAlgorithmParameterException("cipher and mac key lengths must be a whole number of butes");

		cl <<= 3;
		ml <<= 3;
	
		if (cl == 0 && ml == 0)
		{
			// both key lengths are zero; divide available key in two equal halves
			cipherKeySpec = new SecretKeySpec(key.data(), 0, key.size() >> 1, "RAW");
			macKeySpec = new SecretKeySpec(key.data(), key.size() >> 1, key.size() >> 1, "RAW");
		}
		else if (cl == 0)
		{
			throw InvalidAlgorithmParameterException("when specifying a non-zero mac key size you must also specify a non-zero cipher key size");
		}
		else if (ml == 0)
		{
			if (cl >= key.size())
				throw InvalidAlgorithmParameterException("requested key size for cipher exceeds total key size");

			cipherKeySpec = new SecretKeySpec(key.data(), 0, cl, "RAW");
			macKeySpec = new SecretKeySpec(key.data(), cl, key.size() - cl, "RAW");
		}
		else
		{
			if ((cl + ml) > key.size())
				throw InvalidAlgorithmParameterException("requested key sizes for cipher and mac exceed total key size");

			cipherKeySpec = new SecretKeySpec(key.data(), 0, cl, "RAW");
			macKeySpec = new SecretKeySpec(key.data(), cl, ml, "RAW");
		}

		try
		{
			// first try initializing the Cipher with the SecretKeySpec
			_c->init(_opmode, (const Key&) *cipherKeySpec, (SecureRandom*) 0);
		}
		catch (InvalidKeyException)
		{
			// on failure, let's see if there's a SecretKeyFactory for the Cipher
			SecretKeyFactory* skf;
			SecretKey* s;

			try
			{
				skf = SecretKeyFactory::getInstance(_c->getAlgorithm());

				s = skf->generateSecret(*cipherKeySpec);

				_c->init(_opmode, (const Key&) *s, (SecureRandom*) 0);

				delete s;
			}
			catch (InvalidKeySpecException e)
			{
				delete s;

				throw InvalidKeyException(e.getMessage());
			}
			catch (NoSuchAlgorithmException)
			{
				throw ProviderException("cannot initialize cipher");
			}
		}

		try
		{
			// first try initializing the Mac with the SecretKeySpec
			_m->init(*macKeySpec);
		}
		catch (InvalidKeyException)
		{
			// on failure, let's see if there's a SecretKeyFactory for the Mac
			SecretKeyFactory* skf;
			SecretKey* s;

			try
			{
				skf = SecretKeyFactory::getInstance(_m->getAlgorithm());

				s = skf->generateSecret(*macKeySpec);

				_m->init(*s);

				delete s;
			}
			catch (InvalidKeySpecException e)
			{
				delete s;

				throw InvalidKeyException(e.getMessage());
			}
			catch (NoSuchAlgorithmException)
			{
				throw ProviderException("cannot initialize mac");
			}
		}
	}
	catch (InvalidAlgorithmParameterException e)
	{
		std::cout << "got InvalidAlgorithmParameterException " << e.getMessage() << std::endl;
		throw ProviderException(e.getMessage());
	}
	catch (Exception e)
	{
		std::cout << "got Exception " << e.getMessage() << std::endl;
		throw e;
	}
}
