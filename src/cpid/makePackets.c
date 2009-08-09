/*
  Code in this file is partially original Chumby code (2007) and portions of
  code from the GPG2.0.1 source tree. Here is the copyright header from
  the files that were used:

  * base64.c
  *	Copyright (C) 2001, 2003 Free Software Foundation, Inc.
  *
  * This file is part of GnuPG.
  *
  * GnuPG is free software; you can redistribute it and/or modify
  * it under the terms of the GNU General Public License as published by
  * the Free Software Foundation; either version 2 of the License, or
  * (at your option) any later version.
  *
  * GnuPG is distributed in the hope that it will be useful,
  * but WITHOUT ANY WARRANTY; without even the implied warranty of
  * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  * GNU General Public License for more details.
  *
  * You should have received a copy of the GNU General Public License
  * along with this program; if not, write to the Free Software
  * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
  * USA.
  *
  */

#include <string.h>
#include <stdlib.h>
#include "commonCrypto.h"

#ifdef HAVE_DOSISH_SYSTEM
  #define LF "\r\n"
#warning "outputting two characters per LF"
#else
  #define LF "\n"
#endif

int ccount = 0;

/* The base-64 character list */
static char bintoasc[] =  // per ET, removed number 64 as it is redundant
       "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
       "abcdefghijklmnopqrstuvwxyz"
       "0123456789+/";

struct privKeyInFlash *setKey(unsigned int keyNumber) {
  struct privKeyInFlash *retval;

  if( keyNumber >= MAXKEYS )
    return NULL;

  retval = (struct privKeyInFlash *)(KEYBASE + KEYRECSIZE * keyNumber);

  // just an insanity check
  //  if( retval >= KEYMAXBOUND || retval < KEYMINBOUND )
  //    retval = NULL;

  return(retval);
}

int outputPublicKey(unsigned int keyNumber) {
  struct pubKeyVer3Pkt keypkt;
  struct privKeyInFlash *flashKey;
  struct writer_cb_parm_s writer;
  int i;

  memset(&writer, 0, sizeof(writer));

  if( keyNumber >= MAXKEYS ) {
    CPputs( "FAIL" ); 
    CPputc( ASCII_EOF );
    return -1;
  }

  flashKey = setKey(keyNumber);
  if( flashKey == NULL ) {
    CPputs( "FAIL" ); 
    CPputc( ASCII_EOF );
    return -1; // crash on null per ET
  }

  keypkt.version = 0x3;  // hard coded to version 3 output

  keypkt.created[3] = flashKey->created[3];
  keypkt.created[2] = flashKey->created[2];
  keypkt.created[1] = flashKey->created[1];
  keypkt.created[0] = flashKey->created[0];

  keypkt.validFor[1] = 0; // never expires
  keypkt.validFor[0] = 0;

  keypkt.pkAlg = 0x1; // RSA encrypt or sign value from RFC2440, section 9.1

  keypkt.nSize[0] = 0x4; // 0x400 = 1024 bits size
  keypkt.nSize[1] = 0x0;
  for( i = 0; i < 128; i++ ) {
    keypkt.n[i] = flashKey->n[i];
  }
  keypkt.eSize[0] = 0x0;
  keypkt.eSize[1] = 0x20; // 0x20 = 32 bits size
  for( i = 0; i < 4; i++ ) {
    keypkt.e[i] = flashKey->e[i];
  }
  base64_writer( &writer, &keypkt, sizeof(keypkt), "PGP PUBLIC KEY BLOCK" );
  base64_finish_write(&writer, "PGP PUBLIC KEY BLOCK" );

  CPputc( ASCII_EOF );

  return 0;
}

int base64_writer (void *cb_value, const void *buffer, size_t count, char *pem_name) {
  struct writer_cb_parm_s *parm = cb_value;
  unsigned char radbuf[4];
  int i, c, idx, quad_count;
  const unsigned char *p;

  if (!count)
    return 0;

  if (!parm->wrote_begin)
    {
      if (pem_name)
        {
          CPputs ("-----BEGIN ");
          CPputs (pem_name);
          CPputs ("-----\n");
        }
      parm->wrote_begin = 1;
      parm->base64.idx = 0;
      parm->base64.quad_count = 0;
    }

  idx = parm->base64.idx;
  quad_count = parm->base64.quad_count;
  for (i=0; i < idx; i++)
    radbuf[i] = parm->base64.radbuf[i];

  for (p=buffer; count; p++, count--)
    {
      radbuf[idx++] = *p;
      if (idx > 2)
        {
          idx = 0;
          c = bintoasc[(*radbuf >> 2) & 077];
          CPputc (c); ccount++;
          c = bintoasc[(((*radbuf<<4)&060)|((radbuf[1] >> 4)&017))&077];
          CPputc (c); ccount++;
          c = bintoasc[(((radbuf[1]<<2)&074)|((radbuf[2]>>6)&03))&077];
          CPputc (c); ccount++;
          c = bintoasc[radbuf[2]&077];
          CPputc (c); ccount++;
          if (++quad_count >= (64/4))
            {
              CPputs (LF); ccount++;
              quad_count = 0;
            }
        }
    }
  for (i=0; i < idx; i++)
    parm->base64.radbuf[i] = radbuf[i];
  parm->base64.idx = idx;
  parm->base64.quad_count = quad_count;

  return 0;
}

int base64_finish_write (struct writer_cb_parm_s *parm, char *pem_name) {
  unsigned char radbuf[4];
  int i, c, idx, quad_count;

  if (!parm->wrote_begin)
    return 0; /* nothing written */

  /* flush the base64 encoding */
  idx = parm->base64.idx;
  quad_count = parm->base64.quad_count;
  for (i=0; i < idx; i++)
    radbuf[i] = parm->base64.radbuf[i];

  if (idx)
    {
      c = bintoasc[(*radbuf>>2)&077];
      CPputc (c); ccount++;
      if (idx == 1)
        {
          c = bintoasc[((*radbuf << 4) & 060) & 077];
          CPputc (c); ccount++;
          CPputc ('='); ccount++;
          CPputc ('='); ccount++;
        }
      else
        {
          c = bintoasc[(((*radbuf<<4)&060)|((radbuf[1]>>4)&017))&077];
          CPputc (c); ccount++;
          c = bintoasc[((radbuf[1] << 2) & 074) & 077];
          CPputc (c); ccount++;
          CPputc ('='); ccount++;

        }
      if (++quad_count >= (64/4))
        {
          CPputs (LF); ccount++;
          quad_count = 0;
        }
    }

  if (quad_count)
    CPputs (LF); ccount++;

  //  printf( "\nbase64writer finished with %d characters\n", ccount );
  ccount = 0;

  if (pem_name)
    {
      CPputs ("-----END ");
      CPputs (pem_name);
      CPputs ("-----\n");
    }
  return 0;
}

/*!\
 * Decode white space character set (default).
 */
extern const char* b64decode_whitespace;
#define B64DECODE_WHITESPACE	" \f\n\r\t\v"

const char* b64decode_whitespace = B64DECODE_WHITESPACE;

int b64decode(const char* s, void** datap, size_t* lenp)
{
  unsigned char b64dec[256];
  const unsigned char *t;
  unsigned char *te;
  int ns, nt;
  unsigned a, b, c, d;

  if (s == NULL)	return 1;

  /* Setup character lookup tables. */
  memset(b64dec, 0x80, sizeof(b64dec));
  for (c = 'A'; c <= 'Z'; c++)
    b64dec[ c ] = 0 + (c - 'A');
  for (c = 'a'; c <= 'z'; c++)
    b64dec[ c ] = 26 + (c - 'a');
  for (c = '0'; c <= '9'; c++)
    b64dec[ c ] = 52 + (c - '0');
  b64dec[(unsigned)'+'] = 62;
  b64dec[(unsigned)'/'] = 63;
  b64dec[(unsigned)'='] = 0;

  /* Mark whitespace characters. */
  if (b64decode_whitespace)
    {
      const char *e;
      for (e = b64decode_whitespace; *e != '\0'; e++)
	{
	  if (b64dec[ (unsigned)*e ] == 0x80)
	    b64dec[ (unsigned)*e ] = 0x81;
	}
    }

  /* Validate input buffer */
  ns = 0;
  for (t = (unsigned char*) s; *t != '\0'; t++)
    {
      switch (b64dec[(unsigned) *t])
	{
	case 0x80:	/* invalid chararcter */
	  return 3;
	case 0x81:	/* white space */
	  break;
	default:
	  ns++;
	  break;
	}
    }

  if (((unsigned) ns) & 0x3)	return 2;

  nt = (ns / 4) * 3;
  t = te = calloc(nt + 1, 1);   // need to clear in case return type is bigger than extracted data
  if( t == NULL ) // per ET
    return 1;

  while (ns > 0)
    {
      /* Get next 4 characters, ignoring whitespace. */
      while ((a = b64dec[ (unsigned)*s++ ]) == 0x81)
	;
      while ((b = b64dec[ (unsigned)*s++ ]) == 0x81)
	;
      while ((c = b64dec[ (unsigned)*s++ ]) == 0x81)
	;
      while ((d = b64dec[ (unsigned)*s++ ]) == 0x81)
	;

      ns -= 4;
      *te++ = (a << 2) | (b >> 4);
      if (s[-2] == '=') break;
      *te++ = (b << 4) | (c >> 2);
      if (s[-1] == '=') break;
      *te++ = (c << 6) | d;
    }

  if (ns != 0)
    {	/* XXX can't happen, just in case */
      if (t) free((void *)t);
      return 1;
    }
  if (lenp)
    *lenp = (te - t);

  if (datap)
    *datap = (void *)t;
  else
    if (t) free((void *)t);

  return 0;
}
