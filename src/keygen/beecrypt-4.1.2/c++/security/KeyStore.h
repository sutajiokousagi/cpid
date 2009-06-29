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

/*!\file KeyStore.h
 * \ingroup CXX_SECURITY_m
 */

#ifndef _CLASS_KEYSTORE_H
#define _CLASS_KEYSTORE_H

#include "beecrypt/api.h"

#ifdef __cplusplus

#include "beecrypt/c++/io/InputStream.h"
using beecrypt::io::InputStream;
#include "beecrypt/c++/io/OutputStream.h"
using beecrypt::io::OutputStream;
#include "beecrypt/c++/lang/Object.h"
using beecrypt::lang::Object;
#include "beecrypt/c++/security/KeyStoreSpi.h"
using beecrypt::security::KeyStoreSpi;
#include "beecrypt/c++/security/KeyStoreException.h"
using beecrypt::security::KeyStoreException;
#include "beecrypt/c++/security/PrivateKey.h"
using beecrypt::security::PrivateKey;
#include "beecrypt/c++/security/Provider.h"
using beecrypt::security::Provider;
#include "beecrypt/c++/security/NoSuchProviderException.h"
using beecrypt::security::NoSuchProviderException;

namespace beecrypt {
	namespace security {
		/*!\ingroup CXX_SECURITY_m
		 */
		class BEECRYPTCXXAPI KeyStore : public beecrypt::lang::Object
		{
		#if FOR_NEXT_VERSION_COMPATIBLE_WITH_JAVA_1_5
		public:
			class BEECRYPTCXXAPI Entry : public beecrypt::lang::Object
			{
			public:
				virtual ~Entry() {};
			};

			class BEECRYPTCXXAPI PrivateKeyEntry : public Entry
			{
			private:
				PrivateKey* _pri;
				vector<Certificate*> _chain;

			public:
				PrivateKeyEntry(const PrivateKey* privateKey, vector<Certificate*> chain);
				virtual ~PrivateKeyEntry() {};

				virtual const Certificate* getCertificate() const;
				virtual const vector<Certificate*>* getCertificateChain() const;
				virtual const PrivateKey* getPrivateKey() const;
			};

			class TrustedCertificateEntry : public Entry
			{
			private:
				Certificate* _cert;

			public:
				TrustedCertificateEntry(const Certificate& cert);
				virtual ~TrustedCertificateEntry() {};

				virtual const Certificate* getTrustedCertificate() const;
			};
		#endif

		public:
			static KeyStore* getInstance(const String& type) throw (KeyStoreException);
			static KeyStore* getInstance(const String& type, const String& provider) throw (KeyStoreException, NoSuchProviderException);
			static KeyStore* getInstance(const String& type, const Provider& provider) throw (KeyStoreException);

			static const String& getDefaultType();

		private:
			KeyStoreSpi*    _kspi;
			const Provider* _prov;
			String          _type;
			bool            _init;

		protected:
			KeyStore(KeyStoreSpi* spi, const Provider* provider, const String& type);

		public:
			virtual ~KeyStore();

			Enumeration* aliases();
			bool containsAlias(const String& alias) throw (KeyStoreException);

			const Certificate* getCertificate(const String& alias) throw (KeyStoreException);
			const String& getCertificateAlias(const Certificate& cert) throw (KeyStoreException);
			const vector<Certificate*>* getCertificateChain(const String& alias) throw (KeyStoreException);
			bool isCertificateEntry(const String& alias) throw (KeyStoreException);
			void setCertificateEntry(const String& alias, const Certificate& cert) throw (KeyStoreException);
				
			void deleteEntry(const String& alias) throw (KeyStoreException);
				
			Key* getKey(const String& alias, const array<javachar>& password) throw (KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException);
			bool isKeyEntry(const String& alias) throw (KeyStoreException);
			void setKeyEntry(const String& alias, const bytearray& key, const vector<Certificate*>&) throw (KeyStoreException);
			void setKeyEntry(const String& alias, const Key& key, const array<javachar>& password, const vector<Certificate*>&) throw (KeyStoreException);

			size_t size() const throw (KeyStoreException);

			void load(InputStream* in, const array<javachar>* password) throw (IOException, NoSuchAlgorithmException, CertificateException);
			void store(OutputStream& out, const array<javachar>* password) throw (KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException);

			const String& getType() const throw ();
			const Provider& getProvider() const throw ();
		};
	}
}

#endif

#endif
