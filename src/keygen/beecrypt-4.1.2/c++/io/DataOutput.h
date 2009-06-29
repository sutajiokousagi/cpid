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

/*!\file DataOutput.h
 * \ingroup CXX_IO_m
 */

#ifndef _INTERFACE_DATAOUTPUT_H
#define _INTERFACE_DATAOUTPUT_H

#ifdef __cplusplus

#include "beecrypt/c++/array.h"
using beecrypt::bytearray;
#include "beecrypt/c++/io/IOException.h"
using beecrypt::io::IOException;

namespace beecrypt {
	namespace io {
		/*!\ingroup CXX_IO_m
		 */
		class DataOutput
		{
		public:
			virtual void write(const bytearray& b) throw (IOException) = 0;
			virtual void write(const byte* data, size_t offset, size_t length) throw (IOException) = 0;
			virtual void write(byte v) throw (IOException) = 0;
			virtual void writeBoolean(bool v) throw (IOException) = 0;
			virtual void writeByte(byte v) throw (IOException) = 0;
			virtual void writeChars(const String& s) throw (IOException) = 0;
			virtual void writeInt(javaint v) throw (IOException) = 0;
			virtual void writeLong(javalong v) throw (IOException) = 0;
			virtual void writeShort(javashort v) throw (IOException) = 0;
			virtual void writeUTF(const String& str) throw (IOException) = 0;
		};
	}
}

#endif

#endif
