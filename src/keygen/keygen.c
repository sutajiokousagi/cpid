/*
 * Key generator for Chumby Ironforge
 * bunnie@chumby.com                   copyright (c) 2007 bunnie
 */

/*
 * Beecrypt Libarries:
 * Copyright (c) 2003 Bob Deblier
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
 *
 */

#include <stdio.h>
#include <time.h>

#include "beecrypt.h"
#include "rsa.h"

#define TESTING 0

/// public key of the AQS (testing, private key is known)
#if TESTING
static const char* rsa_n  = "BD9F9545D325639D2EA557D404C4FBB1F5EDEA28CEC1919F0668722DC25EECE5B1E8481EBBC371D02B8AE5BDE91665035B4DF9A25C462975126A06ABC14B6E0260CF19B2130779FCE8C121E7CEEBDF02A79C6AAE971A7AAC7428E49B6262487B35E35666FE5E751100DAA483EE92E9735B2DBAA52160088FAE869507BCAE87C2C8924C48A9461044B212951436F2B9E59FF4B266D555505CD9FE21787886B71E002F2CD927ACC8A924D399BE075635FB8092ED80F664A776CE5F64BC6BA49D3AB81E44B520E7629B58361E53F6C909C6460DB276294CB0FA0440B7775A28E13612C92A001BAF5E0345E39F7A1E5C2AF38ADF830C45C4D151F7C0B24C3ED82035";
static const char* rsa_e  = "00000029";
#else
/// public key of the AQS (permanent, private key is known by no man)
static const char* rsa_n  = "CC942A09714B30B2A5A704769563F70E5B5392D41DF185C59DCA7F152494AA626456EF2A298E9F6BF3515431AE78EB035967E69A8AC002A6C7EFE26CA6254218F5BF6D0482479A5E69AB50C1ECBBCA65F0C4E98127F8A5DFCEC34B4AF07D4347F58C589014CF52FE5D5EDCC18A30D17F9C81CB92500501E0AD8CC18CDBAE245FA2C314BB48C63591488A0D8CD379414857465EAFA4EE7C5B36C906022E4F623AED47EA8A92F91031C1CD7A40712ED2BCADA8D15469A9D04292849041109D104AE0608112849FD0910E1BDD95C34962E09D6F232A269459D33661045604A3AED5A57C39C346C0185A0131CBCB83E0A05D862980FFBCC9B0DEF8172BF629937A31";
static const char* rsa_e  = "00000029";
#endif

char SN[33];
char VERS[33];

void printmpNum(unsigned char *data, unsigned int size) {
  int i;

  for( i = 0; i < size; i+=4 ) {
    printf("%02X", data[i+3]);
    printf("%02X", data[i+2]);
    printf("%02X", data[i+1]);
    printf("%02X", data[i+0]);
    fflush(stdout);
  }
  printf( "\n" );
}

void fprintmpNum(unsigned char *data, unsigned int size, FILE *ofile) {
  int i;

  for( i = 0; i < size; i+=4 ) {
    fprintf(ofile, "%02X", data[i+3]);
    fprintf(ofile, "%02X", data[i+2]);
    fprintf(ofile, "%02X", data[i+1]);
    fprintf(ofile, "%02X", data[i+0]);
    fflush(ofile);
  }
  fprintf( ofile, "\n" );
}

unsigned int writempNum(unsigned char *data, unsigned int size, FILE *ofile ) {
  int i;
  unsigned int bytes = 0;

  for( i = 0; i < size; i+=4 ) {
    bytes += fwrite( &(data[i+3]), 1, 1, ofile);
    bytes += fwrite( &(data[i+2]), 1, 1, ofile);
    bytes += fwrite( &(data[i+1]), 1, 1, ofile);
    bytes += fwrite( &(data[i+0]), 1, 1, ofile);
  }
  fflush(ofile);

  return bytes;
}

unsigned int pad(unsigned int bytes, FILE *ofile) {
  int i;
  unsigned ret = 0;
  unsigned char c = 0x0; // pad to the fully programmed value so that ppl can't selectively inject data

  for( i = 0; i < bytes; i++ ) {
    ret += fwrite( &c, 1, 1, ofile);
  }

  return ret;
}

// placeholder functions until barcode scanner functions are integrated
void setVersion() {
  // done by command line now
  // strcpy(VERS, "00030004000000000000000000000000" );   // version 3.4 -- 3 is ironforge, at sub-revision 4
}

// placeholder functions until barcode scanner functions are integrated
void setSerial() {
  // done by command line now
  //  strcpy(SN,   "00000000000000000000000000000108");
}

#define TESTRNG 0

#define NUM_PCC 24              // number of private keys to be generated
#define PRIVKEY_BITS 1024       // number of bits in the private key
#define PRIVKEY_REC_SIZE 0x200  // pad to this size for the private key record
#define NUM_OK  128             // number of OKs to generate

int main(int argc, char **argv)
{
  int failures = 0;
  
  rsakp keypair;
  mpnumber m, cipher, decipher;
  randomGeneratorContext rngc;
  int i = 0;
  mpnumber pid;
  mpnumber guid;
  mpnumber *pidPtr = &pid;
  mpnumber sn;
  int key = 0;
  FILE *ofile;
  FILE *pkeyFile;
  time_t now, rfc2440_time;
  unsigned long elapsed;
  struct tm base_tm;
  unsigned int bytes = 0;

  if( argc < 3 ) {
    printf( "Usage: keygen SN VERS\n" );
    printf( "Warning! Using defaults.\n" );
    strcpy(SN,   "00000000000000000000000000000108");
    strcpy(VERS, "00030005000000000000000000000000" );   // version 3.4 -- 3 is ironforge, at sub-revision 4
  } else {
    for( i = 0; i < 32 - strlen(argv[1]); i++ )
      SN[i] = '0';
    strcpy(&SN[i],   argv[1]);
    for( i = 0; i < 32 - strlen(argv[2]); i++ )
      VERS[i] = '0';
    strcpy(&VERS[i], argv[2]);
  }
  
#if TESTING
  printf( "WARNING: Using the test AQS public key. Hit enter to continue\n" );
  getchar();
#else
  printf( "Using the production AQS public key.\n" );
#endif

  base_tm.tm_sec = 0;
  base_tm.tm_min = 0;
  base_tm.tm_hour = 0;
  base_tm.tm_mday = 1;
  base_tm.tm_mon = 0;
  base_tm.tm_year = 70;
  base_tm.tm_wday = 4;
  base_tm.tm_yday = 0;
  base_tm.tm_isdst = 0;
  rfc2440_time = mktime(&base_tm);
  //printf( "Time offsest computed from %s", ctime(&rfc2440_time) );
  now = time(NULL);
  elapsed = (unsigned long) difftime(now, rfc2440_time);
  printf( "Current time offset in seconds since epoch: %d\n", elapsed );

  ofile = fopen( "keyfile", "wb" );
  if( ofile == NULL ) {
    printf( "Can't open keyfile for writing\n" );
    exit(-1);
  }

  pkeyFile = fopen( "keyfile.pub", "wb" );
  if( pkeyFile == NULL ) {
    printf( "Can't open keyfile.pub for writing\n" );
  }

  if (randomGeneratorContextInit(&rngc, randomGeneratorDefault()) == 0)
    {
#if TESTRNG
      while(1) {
	mpnsize(&pid, 4);
	rngc.rng->next(rngc.param, (byte*) pid.data, MP_WORDS_TO_BYTES(pid.size)); 
	bytes += writempNum((unsigned char *)pid.data, MP_WORDS_TO_BYTES(pid.size), ofile );
      }
#endif

      // generate ID field
      mpnsize(&guid, 4);
      rngc.rng->next(rngc.param, (byte*) guid.data, MP_WORDS_TO_BYTES(guid.size)); 
      //printf( "id.size %d\n", MP_WORDS_TO_BYTES(guid.size) );
      fprintf( pkeyFile, "GUID:0:" ); fprintmpNum( (unsigned char *)guid.data, MP_WORDS_TO_BYTES(guid.size), pkeyFile );

      // generate SN field
      mpnsize(&sn, 4);
      setSerial();
      mpnsethex(&sn, SN);
      //printf( "sn.size %d\n", MP_WORDS_TO_BYTES(sn.size) );
      fprintf( pkeyFile, "SN:0:" ); fprintmpNum( (unsigned char *)sn.data, MP_WORDS_TO_BYTES(sn.size), pkeyFile );

      // generate HW ver field
      mpnsize(&pid, 4);
      setVersion();
      mpnsethex(&pid, VERS);
      //printf( "vers.size %d\n", MP_WORDS_TO_BYTES(pid.size) );
      fprintf( pkeyFile, "VERS:0:" ); fprintmpNum( (unsigned char *)pid.data, MP_WORDS_TO_BYTES(pid.size), pkeyFile );
      
      printf( "Generating private keys" );
      fflush(stdout);
      for( key = 0; key < NUM_PCC; key++ ) {
	rsakpInit(&keypair);
	bytes = 0;
	mpnsize(&pid, 4);
	rngc.rng->next(rngc.param, (byte*) pid.data, MP_WORDS_TO_BYTES(pid.size)); 
     
	//printf( "pid.size %d\n", MP_WORDS_TO_BYTES(pid.size) );
	//printf( "key ID: " ); printmpNum( (unsigned char *)pid.data, MP_WORDS_TO_BYTES(pid.size) );
	fprintf( pkeyFile, "PKEY_ID:%d:", key ); fprintmpNum( (unsigned char *)pid.data, MP_WORDS_TO_BYTES(pid.size), pkeyFile );
	bytes += writempNum((unsigned char *)pid.data, MP_WORDS_TO_BYTES(pid.size), ofile );

	rsakpMake(&keypair, &rngc, PRIVKEY_BITS);
	printf( "." );
	fflush(stdout);
	fprintf( stderr, "." );
	fflush(stderr);

	//printf( "p.size %d\n", MP_WORDS_TO_BYTES(keypair.p.size) );
	//printf( "p: " ); printmpNum( (unsigned char *)keypair.p.modl, MP_WORDS_TO_BYTES(keypair.p.size) );
	bytes += writempNum((unsigned char *)keypair.p.modl, MP_WORDS_TO_BYTES(keypair.p.size), ofile );

	//printf( "q.size %d\n", MP_WORDS_TO_BYTES(keypair.q.size) );
	//printf( "q: " ); printmpNum( (unsigned char *)keypair.q.modl, MP_WORDS_TO_BYTES(keypair.q.size) );
	bytes += writempNum((unsigned char *)keypair.q.modl, MP_WORDS_TO_BYTES(keypair.q.size), ofile );

	//printf( "dp.size %d\n", MP_WORDS_TO_BYTES(keypair.dp.size) );
	//printf( "dp:" );  printmpNum( (unsigned char *)keypair.dp.data, MP_WORDS_TO_BYTES(keypair.dp.size) );
	bytes += writempNum((unsigned char *)keypair.dp.data, MP_WORDS_TO_BYTES(keypair.dp.size), ofile );

	//printf( "dq.size %d\n", MP_WORDS_TO_BYTES(keypair.dq.size) );
	//printf( "dq:" );  printmpNum( (unsigned char *)keypair.dq.data, MP_WORDS_TO_BYTES(keypair.dq.size) );
	bytes += writempNum((unsigned char *)keypair.dq.data, MP_WORDS_TO_BYTES(keypair.dq.size), ofile );

	//printf( "qi.size %d\n", MP_WORDS_TO_BYTES(keypair.qi.size) );
	//printf( "qi:" );  printmpNum( (unsigned char *)keypair.qi.data, MP_WORDS_TO_BYTES(keypair.qi.size) );
	bytes += writempNum((unsigned char *)keypair.qi.data, MP_WORDS_TO_BYTES(keypair.qi.size), ofile );

	fprintf( pkeyFile, "PKEY_N:%d:", key ); fprintmpNum( (unsigned char *)keypair.n.modl, MP_WORDS_TO_BYTES(keypair.n.size), pkeyFile );
	//printf( "n.size %d\n", MP_WORDS_TO_BYTES(keypair.n.size) );
	//printf( "n: " );  printmpNum( (unsigned char *)keypair.n.modl, MP_WORDS_TO_BYTES(keypair.n.size) );
	bytes += writempNum((unsigned char *)keypair.n.modl, MP_WORDS_TO_BYTES(keypair.n.size), ofile );

	fprintf( pkeyFile, "PKEY_E:%d:", key ); fprintmpNum( (unsigned char *)keypair.e.data, MP_WORDS_TO_BYTES(keypair.e.size), pkeyFile );	//printf( "e.size %d\n", MP_WORDS_TO_BYTES(keypair.e.size) );
	//printf( "e:" );  printmpNum( (unsigned char *)keypair.e.data, MP_WORDS_TO_BYTES(keypair.e.size) );
	bytes += writempNum((unsigned char *)keypair.e.data, MP_WORDS_TO_BYTES(keypair.e.size), ofile );

	now = time(NULL);
	elapsed = (unsigned long) difftime(now, rfc2440_time);
	//printf( "creation time in seconds: %d\n", elapsed );
	bytes += writempNum((unsigned char *)&elapsed, 4, ofile );

	// add padding here
	if( bytes < PRIVKEY_REC_SIZE )
	  pad( PRIVKEY_REC_SIZE - bytes, ofile );
	else
	  printf( "Error: number of bytes written exceeds record length.\n" );

	rsakpFree(&keypair);
      }
      printf( "\n" );


      // commit ID field
      printf( "GUID: " ); printmpNum( (unsigned char *)guid.data, MP_WORDS_TO_BYTES(guid.size) );
      bytes += writempNum((unsigned char *)guid.data, MP_WORDS_TO_BYTES(guid.size), ofile );

      // generate SN field
      printf( "SN:   " ); printmpNum( (unsigned char *)sn.data, MP_WORDS_TO_BYTES(sn.size) );
      bytes += writempNum((unsigned char *)sn.data, MP_WORDS_TO_BYTES(sn.size), ofile );

      // generate HW ver field
      mpnsize(&pid, 4);
      setVersion();
      mpnsethex(&pid, VERS);
      //printf( "vers.size %d\n", MP_WORDS_TO_BYTES(pid.size) );
      printf( "VERS: " ); printmpNum( (unsigned char *)pid.data, MP_WORDS_TO_BYTES(pid.size) );
      bytes += writempNum((unsigned char *)pid.data, MP_WORDS_TO_BYTES(pid.size), ofile );
      
      for( key = 0; key < NUM_OK; key++ ) {
	mpnsize(&pid, 4);
	rngc.rng->next(rngc.param, (byte*) pid.data, MP_WORDS_TO_BYTES(pid.size)); 
	//printf( "OK.size %d\n", MP_WORDS_TO_BYTES(pid.size) );
	//printf( "OK%02d: ", key ); printmpNum( (unsigned char *)pid.data, MP_WORDS_TO_BYTES(pid.size) );
	bytes += writempNum((unsigned char *)pid.data, MP_WORDS_TO_BYTES(pid.size), ofile );
      }

      rsakpInit(&keypair);
      mpbsethex(&keypair.n, rsa_n);
      mpnsethex(&keypair.e, rsa_e);
      //printf( "AQS n.size %d\n", MP_WORDS_TO_BYTES(keypair.n.size) );
      //printf( "n: " );  printmpNum( (unsigned char *)keypair.n.modl, MP_WORDS_TO_BYTES(keypair.n.size) );
      bytes += writempNum((unsigned char *)keypair.n.modl, MP_WORDS_TO_BYTES(keypair.n.size), ofile );

      //printf( "AQS e.size %d\n", MP_WORDS_TO_BYTES(keypair.e.size) );
      //printf( "e:" );  printmpNum( (unsigned char *)keypair.e.data, MP_WORDS_TO_BYTES(keypair.e.size) );
      bytes += writempNum((unsigned char *)keypair.e.data, MP_WORDS_TO_BYTES(keypair.e.size), ofile );
      //      pad( 256 + 4, ofile ); // pad out the AQS public keys for now
      rsakpFree(&keypair);
      
      for( key = 0; key < 16; key++ ) {
	mpnsize(&pid, 4);
	rngc.rng->next(rngc.param, (byte*) pid.data, MP_WORDS_TO_BYTES(pid.size)); 
	//printf( "entropy.size %d\n", MP_WORDS_TO_BYTES(pid.size) );
	//printf( "entropy%02d: ", key ); printmpNum( (unsigned char *)pid.data, MP_WORDS_TO_BYTES(pid.size) );
	bytes += writempNum((unsigned char *)pid.data, MP_WORDS_TO_BYTES(pid.size), ofile );
      }

    }
  fclose(ofile);

  return 0;
}
