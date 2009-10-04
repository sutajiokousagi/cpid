/*
  Cryptoprocessor code. Compliant to spec version 1.4.

  This code is released under a BSD license.

  bunnie@chumby.com 04/07, updated 5/07. All mistakes are mine.
  with contributions from and corrections by Nate Lawson
  with corrections by Eugene Tsyrklevich
*/

/***
    Power management schema.

    Requirements:
    1. Must always respond, instantaneously, to the power button being pressed.
    2. Goes into STOP mode after serial transactions.
    3. Goes into RUN mode when serial interrupt received.
    4. Power state changes while in STOP mode are completed and atomically returned to STOP mode.
***/

#define MAJOR_VERSION 7
#define MINOR_VERSION 1
// version 3.0: corresponds to spec version 1.2.
// version 3.2: changed orientation of power switch on initial reset.
// version 3.3: updated for v1.5 hardware, reset orientation of power switch
// version 4.1: changed to be spec version 1.3.1 compliant
// version 4.2: changed to be spec version 1.3.2 complaint, stripped out ADVL and RAND reporting.
// version 4.3: changed to reflect 16 MHz crystal operation, as well as fix of bug 266
// version 4.4: changed to add support for 5V UVLO reset monitor
// version 5.0: ported to STM32 for stormwind EVT0
// version 5.1: user present challenge mode added
// version 5.2: fixed padding bug on public key exchanges where zero-values are included in pad
// version 5.3: fixed bug where RTC is reset when power is lost while backup domain power is present
// version 6.0: introduced touchscreen controller & battery voltage monitor into code base; remapped pins
// version 6.1: fixed some bugs in touchscreen timing and handling; eliminated need for external pullup on Y+ (hopefully)
// version 6.2: rolled back double-reset hack for silvermoon
// version 7 is for Falconwing branch

#include "beecrypt/sha1.h"
#include "beecrypt/aes.h"
#include "beecrypt/rsa.h"
#include "beecrypt/fips186.h"
#include "beecrypt/entropy.h"

#include "commonCrypto.h"
#include <time.h>
#include <stdio.h>
#include <linux/i2c.h>
#include <linux/i2c-dev.h>
#include <fcntl.h>

#include <string.h>
#include <unistd.h>

#include <sys/ioctl.h>
//#include <linux/cryptodev.h>
#include "cryptodev.h"

unsigned int keyCandidate = 0xFFFFFFFF;
unsigned int *keyPtr = 0;
unsigned int **keyHandle = &keyPtr;
size_t keyLen = 0;
unsigned int lastWasDLK0 = 0;
byte entropy[20] = {0x01,0x0D,0x0E,0x0A,0x0D,0x0B,0x0E,0x0E,0x0F,0x05,
		    0x10,0xD0,0xE0,0xA0,0xD0,0xB0,0xE0,0xE0,0xF0,0x50};
unsigned int authCount = 0;
unsigned int lastAuthTime = 0;
unsigned int powerTimer = 0;

unsigned char userPresent = 0;
unsigned int userAuthTime = 0;

#define MAX_CHAL_RESULT_LEN  1024   // supposed to be smaller than 448 bytes
byte chalResult[MAX_CHAL_RESULT_LEN]; 
unsigned int chalResultPtr = 0;

typedef enum
{
  PARSE_CMD = 0x0,
  PARSE_DAT = 0x1,
  PARSE_END = 0x2,
  PARSE_WIPE = 0x3,
  PARSE_SURE = 0x4
} ParserState;

struct vector
{
	int input_size;
	byte* input;
	byte* expect;
};

//============================== code
/****
   This function creates a random number
   by doing a SHA-1 digest on an entropy pool that is flavored
   by randomness gathered from a noisy A/D converter
   and made time-variant by looking at the RTC output
****/

int getRandom( octet *rand ) {  // should be a 16-octet string for the return value
  struct machDataInFlash *machDat;
  octet *entropySeed;
  unsigned short adcVal = (unsigned short) random(); //// THIS IS VERY BAD DON"T USE THIS IN PRODUCTION!!!!!111one111
  sha1Param param;
  unsigned long curTime = time(NULL);
  int i;

#warning "Using random(); this is a *bad* RNG. This needs to be adapted to falconwing hardware RNG service"

  machDat = MACHDATABASE;
  entropySeed = machDat->entropySeed[adcVal & 0xF];  // pick a random entropy seed to start with

  if (sha1Reset(&param))
    goto cleanupRand;
  if (sha1Update(&param, (byte *) entropySeed, 16))
    goto cleanupRand;
  if (sha1Update(&param, (byte *) &curTime, 4))
    goto cleanupRand;
  if (sha1Update(&param, (byte *) &adcVal, 2))
    goto cleanupRand;
  if (sha1Update(&param, entropy, 20))
    goto cleanupRand;
  if (sha1Digest(&param, entropy))
    goto cleanupRand;

  for( i = 0; i < 16; i++ ) {
    rand[i] = entropy[i+1];
  }

  return 0;
 cleanupRand:
  return -1;

}

/*
  This function searches for the first available owner key that hasn't been deleted
  (e.g., all 0'd out)
*/
unsigned int getOKnum() {
  struct machDataInFlash *mdat = MACHDATABASE;
  int i;
  int j;

  for( i = 0; i < NUM_OK; i++ ) {
    for( j = 0; j < OK_SIZE; j++ ) {
      if(mdat->OK[i][j] != 0)
	return(i);  // return the first valid OK
    }
  }
  return i;
}

void doPidx(char *data, int datLen) {
  unsigned int *kPtr = NULL;
  unsigned int **kHandle = &kPtr;
  unsigned int len = 0;
  unsigned int x = 0;
  struct writer_cb_parm_s writer;
  struct privKeyInFlash *pkey;

  //  printf( "doing pidx.\n" ); fflush(stdout);
  //  printf( "b64data: %s\n", data );
  if(b64decode(data, (void **)kHandle, &len)) { // per ET
    free( *kHandle ); *kHandle = NULL;
    return;
  }
  if( len != 2 ) {
    free( *kHandle ); *kHandle = NULL;
    return;
  }
  //  printf( "b64len: %d\n", len );
  //  printf( "khandle, *khandle, **khandle: %lx, %lx, %lx\n", kHandle, *kHandle, **kHandle );
  x = (**kHandle) & 0xFFFF;
  //  printf( "x: %d\n", x);
  pkey = setKey(x);
  //  printf( "pkey: %lx\n", pkey );
  //  fflush(stdout);
  free( *kHandle ); *kHandle = NULL;
  if( pkey == NULL ) { CPputs( "FAIL" ); CPputc( ASCII_EOF ); return; }

  CPputs( "PIDX" );
  memset(&writer, 0, sizeof(writer));
  base64_writer( &writer, pkey->i, 16, NULL );
  base64_finish_write(&writer, NULL );

  // cap the transmission
  CPputc( ASCII_EOF );

  return;

}

/* Configure this for your RSA modulus size in bits. */
#define MODULUS_LEN		1024

/* Constants for SHA1 length and ASN.1 OID. */
#define SHA1_LEN	20
static UINT8 SHA1_OID[15] = {48,33,48,9,6,5,43,14,3,2,26,5,0,4,20};

/*
 * Given modulus size in bits, calculate number of 0xff bytes, subbing
 * prefix, 0 byte, SHA OID, and hash len.
 */
#define PKCS15_FF_LEN(modSize)	(((modSize) / 8) - 2 - 1 - \
	sizeof(SHA1_OID) - SHA1_LEN)

/*
 * Prepare a buffer with PKCS #1 ver 1.5 signature padding.  SHA-1 is
 * hardcoded as the hash algorithm.
 */
int GenPkcs1Padding(UINT8 *buf, int len, UINT8 *hashVal) {
  int i;
  UINT8 *ptr;

  if (len != MODULUS_LEN / 8)
    return (-1);

  ptr = buf;
  *ptr++ = 0x00;
  *ptr++ = 0x01;
  for (i = 0; i < PKCS15_FF_LEN(MODULUS_LEN); i++)
    *ptr++ = 0xff;
  *ptr++ = 0x00;
  for (i = 0; i < sizeof(SHA1_OID); i++)
    *ptr++ = SHA1_OID[i];
  for (i = 0; i < SHA1_LEN; i++)
    *ptr++ = hashVal[i];
  return (0);

}

void chalBufInit() {
  int i = 0;
  for( i = 0; i < MAX_CHAL_RESULT_LEN; i++ ) {
    chalResult[i] = 0;
  }
  chalResultPtr = 0;
}

void chalBufUpdate(byte *data, int size) {
  int i;

  i = 0;
  while( (chalResultPtr < MAX_CHAL_RESULT_LEN) && (i < size) ) {
    chalResult[chalResultPtr] = data[i];
    chalResultPtr++; i++;
  }
  if( chalResultPtr >= MAX_CHAL_RESULT_LEN ) {
    printf( "Warning: ran off the end of the challenge buffer, AES hash will be broken.\n" );
  }
}

#define	BLOCK_SIZE	16
#define	KEY_SIZE	16

#define STMP3XXX_DCP_ENC    0x0001
#define STMP3XXX_DCP_DEC    0x0002
#define STMP3XXX_DCP_ECB    0x0004
#define STMP3XXX_DCP_CBC    0x0008
#define STMP3XXX_DCP_CBC_INIT   0x0010
#define STMP3XXX_DCP_OTPKEY 0x0020
/* hash flags */
#define STMP3XXX_DCP_INIT   0x0001
#define STMP3XXX_DCP_UPDATE 0x0002
#define STMP3XXX_DCP_FINAL  0x0004

int chalBuffFlush() {
  // this sends the data to the AES unit and prints it to the console in base-64
  int fd = -1, cfd = -1;
  struct writer_cb_parm_s writer;

  struct {
    char	in[MAX_CHAL_RESULT_LEN],
      encrypted[MAX_CHAL_RESULT_LEN],
      decrypted[MAX_CHAL_RESULT_LEN],
      iv[BLOCK_SIZE],
      key[KEY_SIZE];
  } data;
  int i;

  struct session_op sess;
  struct crypt_op cryp;

  memset(&sess, 0, sizeof(sess));
  memset(&cryp, 0, sizeof(cryp));

  for( i = 0; i < BLOCK_SIZE; i++ ) {
    data.iv[i] = 0x00; // set initial value to 0
  }
  for( i = 0; i < MAX_CHAL_RESULT_LEN; i++ ) {
    data.in[i] = 0;
    data.encrypted[i] = 0;
    data.decrypted[i] = 0;
  }
  for( i = 0; i < KEY_SIZE; i++ ) {
    data.key[i] = 0;
  }
  
  /* Open the crypto device */
  fd = open("/dev/crypto", O_RDWR, 0);
  if (fd < 0) {
    perror("open(/dev/crypto)");
    return 1;
  }
  
  /* Clone file descriptor */
  if (ioctl(fd, CRIOGET, &cfd)) {
    perror("ioctl(CRIOGET)");
    return 1;
  }

  /* Set close-on-exec (not really neede here) */
  if (fcntl(cfd, F_SETFD, 1) == -1) {
    perror("fcntl(F_SETFD)");
    return 1;
  }
  /* Get crypto session for AES128 */
  sess.cipher = CRYPTO_CIPHER_NAME_CBC;
  sess.alg_name = "aes";
  sess.alg_namelen = strlen(sess.alg_name);
  sess.keylen = KEY_SIZE;
  // sess.key = data.key; // key is the OTP key
  if (ioctl(cfd, CIOCGSESSION, &sess)) {
    perror("ioctl(CIOCGSESSION)");
    return 1;
  }

  for( i = 0; i < chalResultPtr; i++ ) {
    data.in[i] = chalResult[i];
  }
  while( (i % 16) != 0 ) {
    i++;  // round up to the nearest block length
  }

  /* Encrypt data.in to data.encrypted */
  cryp.ses = sess.ses;
  cryp.len = i; // chalResultPtr rounded up to nearest 16-byte block (128-bit block)
  cryp.src = data.in;
  cryp.dst = data.encrypted;
  cryp.iv = data.iv;
  cryp.op = COP_ENCRYPT;
  cryp.flags = STMP3XXX_DCP_OTPKEY; // use the user un-readable OTP key
  if (ioctl(cfd, CIOCCRYPT, &cryp)) {
    perror("ioctl(CIOCCRYPT)");
    return 1;
  }
	
  memset(&writer, 0, sizeof(writer));
  base64_writer(&writer, data.encrypted, i, NULL); // send the encrypted data out!
  base64_finish_write(&writer, NULL );

  /* Finish crypto session */
  if (ioctl(cfd, CIOCFSESSION, &sess.ses)) {
    perror("ioctl(CIOCFSESSION)");
    return 1;
  }
  
  /* Close cloned descriptor */
  if (close(cfd)) {
    perror("close(cfd)");
    return 1;
  }
  
  /* Close the original descriptor */
  if (close(fd)) {
    perror("close(fd)");
    return 1;
  }

  return 0;
}

/*
output: rm, PAQS(OK), vers, S(rn, rm, x, h(PIDx), Paqs(OK), vers)
                                       temp     persist
0. rn is given                           0   /   16
0. x is given                            0   /    4
1. compute rm                           16   /   16
2. compute h(PIDx)                     ~100  /   20
3. compute Paqs(OK)
   load key                        260 (key) /    0
   pad signed data    620 (peak) 256 (after) /    0
   sign data                      1032 + 512 /  256
4. assemble message (rm, Paqs(OK),vers)  600 /    0
   (message is output and cleared)
5. assemble signature msg (rn, rm, x, h(PIDx), Paqs(OK), vers)
                                         700 /    0
6. create digest                         100 /   20  (-256, -20, -16, -4, -16 -- dealloc all temps)
7. pad digest                            300 /  128
8. generate blinding factor        520 + 256 /  128
9. blind padded data               520 + 256 /  128 (-256)
10. sign appendix                  520 + 256 /  128
11. check appendix                 520 + 256 /  128
12. output appendix                      256 /    0

*/

// rn, rm, x, h(pid), PAQS(OK), vers
#define M_PAQS_OFF  0
#define M_PAQS_SIZE 256
#define M_RN_OFF    M_PAQS_SIZE
#define M_RN_SIZE   16
#define M_RM_OFF    (M_PAQS_SIZE + M_RN_SIZE)
#define M_RM_SIZE   16
#define M_X_OFF     (M_PAQS_SIZE + M_RN_SIZE + M_RM_SIZE)
#define M_X_SIZE    4
#define M_HPID_OFF  (M_PAQS_SIZE + M_RN_SIZE + M_RM_SIZE + M_X_SIZE)
#define M_HPID_SIZE 20
#define M_VERS_OFF  (M_PAQS_SIZE + M_RN_SIZE + M_RM_SIZE + M_X_SIZE + M_HPID_SIZE)
#define M_VERS_SIZE 4
#define M_OS_SIZE   (M_PAQS_SIZE + M_RN_SIZE + M_RM_SIZE + M_X_SIZE + M_HPID_SIZE + M_VERS_SIZE)
#define M_OS_MPSIZE MP_BYTES_TO_WORDS(M_OS_SIZE + MP_WBYTES - 1)
#define PS_LEN    (256 - 16 - 3)   // octet PS length = k - mLen - 3 = 256 - 16 - 3 = 237

#define SIGM_PAQS_OFF  0
#define SIGM_PAQS_SIZE 256
#define SIGM_RM_OFF    (SIGM_PAQS_SIZE)
#define SIGM_RM_SIZE   16
#define SIGM_VERS_OFF  (SIGM_PAQS_SIZE + SIGM_RM_SIZE)
#define SIGM_VERS_SIZE 4
#define SIGM_OS_SIZE   (SIGM_PAQS_SIZE + SIGM_RM_SIZE + SIGM_VERS_SIZE)
#define SIGM_OS_MPSIZE MP_BYTES_TO_WORDS(SIGM_OS_SIZE + MP_WBYTES - 1)

// do the challenge response algorithm
// peak memory usage @ 2048 bits is 4268 bytes in total heap size
void doChal(char *data, int datLen, char userType) {
  unsigned int *kPtr = NULL;
  unsigned int **kHandle = &kPtr;
  unsigned short x;
  unsigned int len;
  unsigned int i, j;
  mpnumber rn;
  mpnumber rm;
  mpnumber rb;
  mpnumber pid;
  mpnumber m;
  octet    *m_os;
  struct writer_cb_parm_s writer;
  byte  h_pid_oct[20];
  octet rand_oct[16];
  octet rb_os[16];
  sha1Param param;
  struct machDataInFlash *mdat = MACHDATABASE;
  struct privKeyInFlash *pkey;
  rsakp keypair;
  mpnumber cipher;
  mpnumber B;
  mpnumber mblind;
  mpnumber mSecBlind;
  octet  *cipher_os;
  unsigned int OKnum;

  mpnzero(&rn);
  mpnzero(&rm);
  mpnzero(&rb);
  mpnzero(&pid);
  mpnzero(&m);
  mpnzero(&cipher);
  mpnzero(&B);
  mpnzero(&mblind);
  mpnzero(&mSecBlind);

  chalBufInit();

  if( userType == CHAL_NOUSER ) {  // only check/increment authcount on auths that don't require user presence
    if( authCount >= AUTH_MAX_AUTHS ) { // fail if auth count is too high
      CPputs( "AUTHCOUNT?\n" );
      CPputc( ASCII_EOF );
      return;
    }
    authCount++;
  }

  // ok now do the challenge
  i = 0;
  while( i < datLen ) {
    if( data[i] == '\n' )
      data[i] = '\0';
    i++;
  }

  len = 0; // per ET
  if(b64decode(data, (void **)kHandle, &len)) { // per ET
    free( *kHandle ); *kHandle = NULL;
    return;
  }
  if( len != 2 ) {
    free( *kHandle ); *kHandle = NULL;
    return;
  }
  x = ((unsigned short) **kHandle) & 0xFFFF;
  free( *kHandle ); *kHandle = NULL;
  if( x >= MAXKEYS ) { // fixed ge/gtr bug
    CPputs( "FAIL" );
    CPputc( ASCII_EOF );
    return;
  }
  pkey = setKey(x);
  if( pkey == NULL ) { CPputs( "FAIL" ); goto cleanup; }

  len = 0; // per ET
  if(b64decode(&(data[5]), (void **)kHandle, &len)) { // per ET
    free( *kHandle ); *kHandle = NULL;
    return;
  }
  if( len != 16 ) {
    free( *kHandle ); *kHandle = NULL;
    return;
  }
  mpnzero(&rn);
  if(mpnsetbin(&rn, (byte *) *kHandle, (size_t) len) != 0) {
    CPputs( "FAIL" );
    free( *kHandle ); *kHandle = NULL;
    goto cleanup;
  }
  free( *kHandle ); *kHandle = NULL;

  // RESP header
  CPputs( "RESP" );

  // rm, Paqs(OK), vers, S(rn, rm, x, h(PIDx), Paqs(OK), vers)
  // 16+ 256+      16+ ..256
  // generate rm
  mpnzero(&rm);
  if( getRandom( rand_oct ) != 0 ) { CPputs( "FAIL" ); CPputc( ASCII_EOF ); return; }
  if(mpnsetbin(&rm, (byte *) rand_oct, (size_t) 16) != 0) { CPputs( "FAIL" ); goto cleanup; }

  // generate hash of my PID
  mpnzero(&pid);
  if( sha1Reset(&param) ) { CPputs( "FAIL" ); goto cleanup; }
  // note that this is a byte-wise big-endian big-num hash of a 16-bit number
  if( sha1Update(&param, (byte *) pkey->i, 16 ) ) { CPputs( "FAIL" ); goto cleanup; }
  if( sha1Digest(&param, h_pid_oct) ) { CPputs( "FAIL" ); goto cleanup; }
  if(mpnsetbin(&pid, (byte *) h_pid_oct, (size_t) 20) != 0) { CPputs( "FAIL" ); goto cleanup; }
  if( sha1Reset(&param) ) { CPputs( "FAIL" ); goto cleanup; }

  // now build the encrypted owner key using PAQS
  // build the padded m
  OKnum = getOKnum();
  m_os = calloc(256, 1);
  if( m_os == NULL ) { CPputs( "FAIL" ); goto cleanup; }
  i = 0;
  m_os[i++] = 0x00;
  m_os[i++] = 0x02;
  for( ; i < 256; i++ ) {
    if( i >= 2 && i < PS_LEN + 2 ) {
      do { // generate a single, non-zero byte by repeatedly calling the prng until you get a non-zero value in byte 0
	if( getRandom( rand_oct ) != 0 ) { CPputs( "FAIL" ); CPputc( ASCII_EOF ); return; }
      } while( rand_oct[0] == 0x00 );
      // assign this non-zero byte to m_os
      m_os[i] = rand_oct[0];
      continue;
    }
    if( i == PS_LEN + 2 ) {
      m_os[i] = 0x00;
      j = 0;
      continue;
    } else {
      m_os[i] = (octet) mdat->OK[OKnum][j++];
      // copy through the OK into m
    }
  }
  mpnzero(&m);
  if(mpnsetbin(&m, (byte *) m_os, 256) != 0) { CPputs( "FAIL" ); goto cleanup; }
  free(m_os); m_os = NULL;// clear out the temp bufefr

  rsakpInit(&keypair);
  if( mpnsetbin(&keypair.e, mdat->AQSe, 4) != 0 ) { CPputs( "FAIL" ); goto cleanup; }
  if( mpbsetbin(&keypair.n, mdat->AQSn, 256) != 0) { CPputs( "FAIL" ); goto cleanup; }
  mpnzero(&cipher);

  // now do the maths and print the result
  rsapub(&keypair.n, &keypair.e, &m, &cipher);

  cipher_os = calloc(MP_WORDS_TO_BYTES(cipher.size),1);
  if( cipher_os == NULL ) { CPputs( "FAIL" ); goto cleanup; }
  if( i2osp( cipher_os, MP_WORDS_TO_BYTES(cipher.size), cipher.data, cipher.size ) != 0 ) {
    CPputs( "FAIL" );
    free( cipher_os ); cipher_os = NULL;
    goto cleanup;
  }
  mpnfree(&m);  // get rid of temp data
  mpnfree(&cipher);
  rsakpFree(&keypair);
  // now we are carrying around the PAQS(OK) data...256 extra bytes on the heap!!!

  // at this point, do "step 4": assemble message for transmission
  m_os = calloc(SIGM_OS_SIZE, 1);
  if( m_os == NULL ) { CPputs( "FAIL" ); goto cleanup; }
  for( i = 0; i < SIGM_PAQS_SIZE; i++ ) {
    m_os[i] = cipher_os[i];
  }
  if( i2osp( rand_oct, MP_WORDS_TO_BYTES(rm.size), rm.data, rm.size ) != 0 ) {
    CPputs( "FAIL" );
    goto cleanup;
  }
  for( j = 0, i = SIGM_RM_OFF; i < SIGM_VERS_OFF; i++, j++ ) {
    m_os[i] = rand_oct[j];
  }
  // version string in big-endian format
  m_os[i++] = MAJOR_VERSION;
  m_os[i++] = MINOR_VERSION;
  m_os[i++] = (octet) (userType & 0xFF); // passed in variable, careful...
  m_os[i++] = 0;

  memset(&writer, 0, sizeof(writer));
  chalBufUpdate(m_os, SIGM_OS_SIZE);
  base64_writer( &writer, m_os, SIGM_OS_SIZE, NULL );
  base64_finish_write(&writer, NULL );
  free( m_os ); m_os = NULL;

  // now build the message to sign: (rn, rm, x, h(PIDx), Paqs(OK), vers)
  // we re-use rand_oct for this purpose
  m_os = calloc(M_OS_SIZE, 1);
  if( m_os == NULL ) { CPputs( "FAIL" ); goto cleanup; }
  // assemble PAQS
  for( i = 0; i < SIGM_PAQS_SIZE; i++ ) {
    m_os[i] = cipher_os[i];
  }
  // assemble rn
  if( i2osp( rand_oct, 16, rn.data, rn.size ) != 0 ) { CPputs( "FAIL" ); goto cleanup; }
  for( j = 0, i = M_RN_OFF; i < M_RM_OFF; i++, j++ ) {
    m_os[i] = rand_oct[j];
  }
  // assemble rm
  if( i2osp( rand_oct, 16, rm.data, rm.size ) != 0 ) { CPputs( "FAIL" ); goto cleanup; }
  for( j = 0, i = M_RM_OFF; i < M_X_OFF; i++, j++ ) {
    m_os[i] = rand_oct[j];
  }
  // assemble x (4 bytes hard-coded)
  m_os[i++] = 0;
  m_os[i++] = 0;
  m_os[i++] = (x >> 8) & 0xFF;
  m_os[i++] = x & 0xFF;
  // assemble h_pid
  for( j = 0, i = M_HPID_OFF; i < M_VERS_OFF; i++, j++ ) {
    m_os[i] = h_pid_oct[j];
  }
  // assemble vers
  // version string in big-endian format
  m_os[i++] = MAJOR_VERSION;
  m_os[i++] = MINOR_VERSION;
  m_os[i++] = 0;
  m_os[i++] = 0;

  // we've copied cipher_os one final time, so get rid of it to make space on heap...
  free(cipher_os); cipher_os = NULL;  // does this lead to fragmentation of the heap? eep. i wonder how good my mallocator is.

  // hash using SHA-1
  // re-use h_pid_oct variable to save space...
  if( sha1Reset(&param) ) { CPputs( "FAIL" ); goto cleanup; }
  if( sha1Update(&param, (byte *) m_os, M_OS_SIZE ) ) { CPputs( "FAIL" ); goto cleanup; }
  if( sha1Digest(&param, h_pid_oct) ) { CPputs( "FAIL" ); goto cleanup; }
  if( sha1Reset(&param) ) { CPputs( "FAIL" ); goto cleanup; }

  // get rid of variables we don't need anymore
  free(m_os); m_os = NULL;

  // pad the digest.
  m_os = calloc(MODULUS_LEN / 8, 1);
  if( m_os == NULL ) { CPputs( "FAIL" ); goto cleanup; }
  if( GenPkcs1Padding( m_os, MODULUS_LEN / 8, h_pid_oct ) != 0 ) {
    CPputs( "FAIL" ); goto cleanup;
  }
  mpnzero(&m);
  if(mpnsetbin(&m, (byte *) m_os, MODULUS_LEN / 8) != 0) { CPputs( "FAIL" ); goto cleanup; }
  free( m_os ); m_os = NULL;
  // message is now in m as an mpnumber, m_os is gone

  // generate blinding factor
  // B = rm^e mod n
  rsakpInit(&keypair);

  if( mpnsetbin(&keypair.e, pkey->e, 4) != 0 ) { CPputs( "FAIL" ); goto cleanup; }
  if( mpnsetbin(&keypair.dp, pkey->dp, 64) != 0) { CPputs( "FAIL" ); goto cleanup; }
  if( mpnsetbin(&keypair.dq, pkey->dq, 64) != 0) { CPputs( "FAIL" ); goto cleanup; }
  if( mpnsetbin(&keypair.qi, pkey->qi, 64) != 0) { CPputs( "FAIL" ); goto cleanup; }

  if( mpbsetbin(&keypair.n, pkey->n, 128) != 0) { CPputs( "FAIL" ); goto cleanup; }
  if( mpbsetbin(&keypair.p, pkey->p, 64) != 0) { CPputs( "FAIL" ); goto cleanup; }
  if( mpbsetbin(&keypair.q, pkey->q, 64) != 0) { CPputs( "FAIL" ); goto cleanup; }

  mpnzero(&B);
  if(rsapub(&keypair.n, &keypair.e, &rm, &B)) { CPputs("FAIL"); goto cleanup; }

  // blind the data
  // mblind = B * m mod N
  mpnzero(&mblind);
  mpbnmulmod(&keypair.n, &B, &m, &mblind); // oooh this function doesn't even provide error checking :( how much does that suck??

  mpnfree(&B); // clear up blinding precursors
  mpnfree(&m);

  // generate secret blinding factor rb
  mpnzero(&rb);
  if( getRandom( rb_os ) != 0 ) { CPputs( "FAIL" ); CPputc( ASCII_EOF ); return; }
  if(mpnsetbin(&rb, (byte *) rb_os, (size_t) 16) != 0) { CPputs( "FAIL" ); goto cleanup; }

  // generate blinding factor Bprime = rb^e mod N
  mpnzero(&B);
  if(rsapub(&keypair.n, &keypair.e, &rb, &B)) { CPputs("FAIL"); goto cleanup; }

  // blind the data again
  // mSecBlind = Bprime * mblind mod N
  mpnzero(&mSecBlind);
  mpbnmulmod(&keypair.n, &B, &mblind, &mSecBlind);
  mpnfree(&B);
  mpnfree(&mblind);

  // s = mSecBlind^d mod n
  mpnzero(&cipher);

  if (rsapricrt(&keypair.n, &keypair.p, &keypair.q, &keypair.dp, &keypair.dq, &keypair.qi, &mSecBlind, &cipher )) {
    CPputs("FAIL");
    goto cleanup;
  }
  mpnfree(&rn);
  mpnfree(&rm);
  mpnfree(&pid);
  mpnfree(&m);    // clean up all precursors

  // compute M' = S^e mod N
  mpnzero(&m);
  if(rsapub(&keypair.n, &keypair.e, &cipher, &m)) { CPputs("FAIL"); goto cleanup; }

  // verify that M' == m
  if( !mpeq(mSecBlind.size, mSecBlind.data, m.data) ) {
    mpzero( cipher.size, cipher.data ); // do a wipe and a FAIL
    CPputs("FAIL"); goto cleanup;  // i suppose just one or the other would do....
  }
  // free up the comparison factors m and mSecBlind
  mpnfree(&m);
  mpnfree(&mSecBlind);

  // now we need to unblind the data locally...
  // compute the multiplicative inverse of rb
  mpnzero(&B);
  mpninv(&B, &rb, (mpnumber *) &keypair.n);

  // now perform the unblinding operation
  mpbnmulmod(&keypair.n, &B, &cipher, &mblind);
  // the unblinded data to transmit to the AQS is now in mblind

  // finally we are done and can free up all intermediate variables
  mpnfree(&B);
  mpnfree(&cipher);
  mpnfree(&rb);
  rsakpFree(&keypair);

  // now output the data to the AQS
  cipher_os = calloc(MP_WORDS_TO_BYTES(mblind.size),1);
  if( cipher_os == NULL ) { CPputs( "FAIL" ); goto cleanup; }
  if( i2osp( cipher_os, MP_WORDS_TO_BYTES(mblind.size), mblind.data, mblind.size ) != 0 ) {
    CPputs( "FAIL" );
    free( cipher_os ); cipher_os = NULL;
    goto cleanup;
  }
  memset(&writer, 0, sizeof(writer));
  chalBufUpdate(cipher_os, MP_WORDS_TO_BYTES(mblind.size));
  base64_writer( &writer, cipher_os, MP_WORDS_TO_BYTES(mblind.size), NULL );
  base64_finish_write(&writer, NULL );
  free( cipher_os ); cipher_os = NULL;
  mpnfree(&mblind);

  chalBuffFlush();

 cleanup: // dealloc anything that could have been alloc'd...
  CPputc( ASCII_EOF );
  free( m_os ); m_os = NULL;
  free( cipher_os ); cipher_os = NULL;
  free( *kHandle ); *kHandle = NULL;
  mpnfree(&rb);
  mpnfree(&rn);
  mpnfree(&rm);
  mpnfree(&pid);
  mpnfree(&m);
  mpnfree(&cipher);
  mpnfree(&mblind);
  mpnfree(&mSecBlind);
  mpnfree(&B);
  rsakpFree(&keypair);
  return;
}

// this function outptus the public key specified in *data
// this is a wrapper function: checks on validity of key
// index are implemented in outputPublicKey
void doPkey(char *data, int datLen) {
  unsigned int *kPtr = NULL;
  unsigned int **kHandle = &kPtr;
  unsigned int len = 0;

  if(b64decode(data, (void **)kHandle, &len)) { // per ET
    free( *kHandle ); *kHandle = NULL;
    return;
  }
  if( len != 2 ) {
    free( *kHandle ); *kHandle = NULL;
    return;
  }
  outputPublicKey((**kHandle) & 0xFFFF);
  free( *kHandle ); *kHandle = NULL;

  return;
}

void sendTime() {
  unsigned long timesecs = time(NULL);
  struct writer_cb_parm_s writer;

  memset(&writer, 0, sizeof(writer));
  CPputs( "TIME" );
  base64_writer( &writer, &timesecs, sizeof(time), NULL );
  base64_finish_write(&writer, NULL );
  CPputc( ASCII_EOF );
}

void sendFail() {
  // for now this is silent. failures communicate information...so don't indicate a failure.
}

void outputVersion() {
  unsigned short vers[3] = {0, 0, 0};
  struct writer_cb_parm_s writer;

  memset(&writer, 0, sizeof(writer));
  vers[2] = MAJOR_VERSION;  // major version
  vers[1] = MINOR_VERSION;  // minor verion

  CPputs( "VRSR" );
  base64_writer( &writer, vers, sizeof(vers), NULL );
  base64_finish_write(&writer, NULL );
  CPputc( ASCII_EOF );
}

void outputSN() {
  struct machDataInFlash *mdat = MACHDATABASE;
  struct writer_cb_parm_s writer;

  memset(&writer, 0, sizeof(writer));

  CPputs( "SNUM" );
  base64_writer( &writer, mdat->SN, 16, NULL );
  base64_finish_write(&writer, NULL );
  CPputc( ASCII_EOF );
}

void outputCurrentOK() {
  unsigned long OKnum;
  struct writer_cb_parm_s writer;

  OKnum = getOKnum();
  memset(&writer, 0, sizeof(writer));
  CPputs( "CKEY" );

  base64_writer( &writer, &OKnum, sizeof(OKnum), NULL );
  base64_finish_write(&writer, NULL );
  CPputc( ASCII_EOF );
}

void outputHWVersion() {
  struct machDataInFlash *mdat = MACHDATABASE;
  struct writer_cb_parm_s writer;

  memset(&writer, 0, sizeof(writer));

  CPputs( "HVRS" );
  base64_writer( &writer, mdat->HWVER, 16, NULL );
  base64_finish_write(&writer, NULL );
  CPputc( ASCII_EOF );
}

#if RAND_ADVL_DBG
#warning printf("WARNING: RAND_ADVL_DBG is enabled, PNRG pattern leakage is possible!\n");
void testRandom() {
  octet rand[16];
  struct writer_cb_parm_s writer;

  memset(&writer, 0, sizeof(writer));
  if(getRandom(rand)) {
    CPputs( "RAND FAILED.\n" );
    CPputc( ASCII_EOF );
    return;
  }
  CPputs( "RAND" );
  base64_writer( &writer, rand, sizeof(rand), NULL );
  base64_finish_write(&writer, NULL );
  CPputc( ASCII_EOF );

}

void printADC() {
  unsigned short adcv = 0;
  struct writer_cb_parm_s writer;
  memset(&writer, 0, sizeof(writer));

  /* Clear the corespondent DA bit */
  adcv = ADC_RandValue();

  //adcv = 12;
  CPputs( "ADCV" );
  base64_writer( &writer, &adcv, sizeof(adcv), NULL );
  base64_finish_write(&writer, NULL );
  CPputc( ASCII_EOF );
}
#endif


// eeprom-specific functions.
#define I2C_FILE_NAME "/dev/i2c-0"
#define EEPROM_ADDR (0xA2)
#define EEPROM_BYTES (16384)
static int read_from_eeprom(int file, int addr, char *bytes, int size) {
    static struct i2c_rdwr_ioctl_data packets;
    static struct i2c_msg messages[1];
    char outbuf[2];
    int bytes_at_a_time = 64;
    int reg = 0;

    while(size) {
        // On the last loop around, the bytes_at_a_time value might be
        // greater than size.  Clamp it.
        if(bytes_at_a_time > size)
            bytes_at_a_time = size;

        // Start by resetting the read address to what it ought to be.
        outbuf[0] = (reg>>8)&0x3f;
        outbuf[1] = (reg   )&0xff;

        messages[0].addr  = addr;
        messages[0].flags = 0;
        messages[0].len   = sizeof(outbuf);
        messages[0].buf   = outbuf;

        packets.msgs = messages;
        packets.nmsgs = 1;
        if(ioctl(file, I2C_RDWR, &packets) < 0) {
            perror("Unable to set register");
            return 1;
        }

        messages[0].addr    = addr;
        messages[0].flags   = I2C_M_RD;
        messages[0].len     = bytes_at_a_time;
        messages[0].buf     = bytes;

        packets.msgs        = messages;
        packets.nmsgs       = 1;

        if(ioctl(file, I2C_RDWR, &packets) < 0) {
            char err[128];
            snprintf(err, sizeof(err), "Unable to read %d bytes from register %d",
                    bytes_at_a_time, reg);
            perror(err);
            return 1;
        }

        bytes += bytes_at_a_time;
        size  -= bytes_at_a_time;
        reg   += bytes_at_a_time;
    }

    return 0;
}

// see authentication spec doc for these magic numbers
#define CHAL_DATLEN  29
#define CHUP_DATLEN  29
#define AUTH_DATLEN  384
#define DLK0_DATLEN  4
#define DLK1_DATLEN  4
#define PKEY_DATLEN  4
#define ALRM_DATLEN  8

#define MAXLEN  384

/*************************************************************************/

void crypto(char *keyfile_name) {
  char cmd[4];
  char *data = NULL;
  unsigned int expectedLen = 0;
  unsigned int index = 0;
  unsigned int datIndex = 0;
  ParserState state = PARSE_CMD;
  char c;
  unsigned int authRatio;
  int authDiff;
  struct machDataInFlash mdf;
  struct privKeyInFlash pkf[MAXKEYS];

  // If the user specified a keyfile, read the keys from that file.
  // Otherwise, read them from the eeprom.
  if(keyfile_name && *keyfile_name) {
    FILE *keyfile;
    keyfile = fopen(keyfile_name, "rb");
    if( keyfile == NULL ) {
        printf( "can't open keyfile, quitting.\n" );
        exit(0);
    }
    fread(&pkf, sizeof(struct privKeyInFlash), MAXKEYS, keyfile);
    fread(&mdf, sizeof(struct machDataInFlash), 1, keyfile);
    fclose(keyfile);
  }
  else {
        unsigned char bytes[16384];
        int addr = EEPROM_ADDR;
        int i2c_file;

        // Open a connection to the I2C userspace control file.
        if ((i2c_file = open(I2C_FILE_NAME, O_RDWR)) < 0) {
            perror("Unable to open i2c control file");
            exit(1);
        }

        // Read data from the eeprom into the buffer *bytes.
        if(read_from_eeprom(i2c_file, addr, bytes, sizeof(bytes))) {
            fprintf(stderr, "Unable to read from keyfile\n");
            exit(1);
        }

        int privKeyBytes = sizeof(struct privKeyInFlash)*MAXKEYS;
	//        int privKeyBytes = PRIVKEY_REC_SIZE * MAXKEYS;  // privkey records are padded!
        memcpy(&pkf, bytes, privKeyBytes);
        memcpy(&mdf, bytes+privKeyBytes, sizeof(struct machDataInFlash));

        close(i2c_file);
    }
  
  MACHDATABASE = &mdf;
  KEYBASE = &(pkf[0]);

  lastAuthTime = 0;
  powerTimer = 0;

  index = 0;
  while(1) {
    // manage the authorization count
    if( (time(NULL) - lastAuthTime) > AUTH_INTERVAL_SECS ) {
      // grab the ratio, because we can sleep for a very long time before we update
      // this netx line of code is always guaranteed to be greater than 1
      // by virtue of the if statement above
      authRatio = (time(NULL) - lastAuthTime) / AUTH_INTERVAL_SECS;

      // update the lastAuthTime
      lastAuthTime = time(NULL);

      // make sure we don't try to subtract too much from authCount
      if( authRatio > authCount )
	authRatio = authCount;
      // if authCount > 0 then subtract out the authRatio...
      if( authCount > 0 ) {
	authCount -= authRatio;
      }
      if( authCount > AUTH_MAX_AUTHS )  // just some paranoia
	authCount = AUTH_MAX_AUTHS;
    }

#if POLLED_MODE
    // first check the state of the reset request
    if( GPIO_ReadInputDataBit(GPIO_POWERSWITCH) ) {
      // this is the reset request active code path:
      // during reset, we ignore all serial traffic from processor
      // to prevent timing attacks, etc. hence the polled serial implementation
      if( powerState == 0 ) {  // if we are powered down...
	cmdPowerUp();  // then power up
	while( GPIO_ReadInputDataBit(GPIO_POWERSWITCH) )
	  ;  // wait until button released...
	wait_ms(50); // debounce time, 50 ms
	continue;
      } else {  // if we are powered up...
	cmdPowerDown(); // then power down
	while( GPIO_ReadInputDataBit(GPIO_POWERSWITCH) )
	  ;  // wait until button released...
	wait_ms(50); // debounce time, 50 ms
	continue;
      }
    } else { // parse input serial stream
#endif

      // check & maintain the user present pin
      userPresent = 1; // this pin is meaningless in this implementation...

      // code path for when there is no reset request button push:
      
      // At this point, insert a check that verifies battery voltage
      // and line voltage; if neither are higher than 0.7V, then shut
      // the system down, and keep it in shut down
      // replace the commented code with a call to the check function
        //      if( (powerState == 1)/* this is where the voltage check ands in && ((GPIO0->PD & 0x20) == 0) */ ) {
	// if UVLO is triggered while we are in a powered on state,
	// force the machine into a hard-powered down state!
        //	cmdPowerDown();
        //      }

      // grab a character
      
      c = CPgetc();
      powerTimer = time(NULL); // update the power-down timer
      if( c == '!' ) { // synchronize the stream to '!' character
	CPputc('?'); // rise and shine, let the host know we are awake now.
	//	printf( "." ); fflush(stdout);
	goto resetNoStop;
      } else {
	// was power management code here
	//        continue; // go to the top of loop, check for reset req, etc.
      }

      // the only way we get here is if c has something in it.
      switch( state ) {
      case PARSE_CMD:
        if( index > 3 || index < 0 ) { // this should never happen
          goto abortParse;
        }
        cmd[index] = c;
        index++;
        if( index == 4 ) {
          // parse the command
	  expectedLen = 0;  // invariant: expectedLen is 0 unless otherwise spec'd by cmd
	  datIndex = 0;
#if 0
	  {
	    char cmd2[5];
	    int kk;
	    for( kk = 0; kk < 4; kk ++ )
	      cmd2[kk] = cmd[kk];
	    cmd2[kk] = '\0';
	    printf( "%s", cmd2 );
	    fflush(stdout);
	  }
#endif
          if( 0 == strncmp("CHAL", cmd, 4) ) {  // CHAL packet
            state = PARSE_DAT;
            expectedLen = CHAL_DATLEN;
          } else if( 0 == strncmp("CHUP", cmd, 4 ) ) { // CHUP packet
	    state = PARSE_DAT;
	    expectedLen = CHUP_DATLEN;
	  } else if( 0 == strncmp("AUTH", cmd, 4)) { // AUTH packet
            state = PARSE_DAT;
            expectedLen = AUTH_DATLEN;
          } else if( 0 == strncmp("DLK0", cmd, 4)) {
            state = PARSE_DAT;
            expectedLen = DLK0_DATLEN;
          } else if( 0 == strncmp("DLK1", cmd, 4)) {
            state = PARSE_DAT;
            expectedLen = DLK1_DATLEN;
          } else if( 0 == strncmp("WIPE", cmd, 4)) {
	    state = PARSE_WIPE;
	    cmd[0] = '\0'; cmd[1] = '\0'; cmd[2] = '\0'; cmd[3] = '\0';
	    index = 0;
	    CPputs( "WARNING: UNLOCK STAGE 1 PASSED.\n" );
	    CPputc( ASCII_EOF );
          } else if( 0 == strncmp("SURE", cmd, 4)) {
	    CPputs( "UNLOCK STAGE 2 FAILED.\n" );
	    CPputc( ASCII_EOF );
	    goto abortParse;  // we should never get SURE without a previous WIPE
          } else if( 0 == strncmp("PKEY", cmd, 4)) {
	    printf( "pkey\n" );
            state = PARSE_DAT;
            expectedLen = PKEY_DATLEN;
          } else if( 0 == strncmp("PIDX", cmd, 4)) {
            state = PARSE_DAT;
            expectedLen = PKEY_DATLEN;
          } else if( 0 == strncmp("VERS", cmd, 4)) {
	    outputVersion();
	    goto resetParse;
          } else if( 0 == strncmp("HWVR", cmd, 4)) {
	    outputHWVersion();
	    goto resetParse;
          } else if( 0 == strncmp("SNUM", cmd, 4)) {
	    outputSN();
	    goto resetParse;
          } else if( 0 == strncmp("CKEY", cmd, 4)) {
	    outputCurrentOK();
	    goto resetParse;
          } else if( 0 == strncmp("ALRM", cmd, 4)) {
            state = PARSE_DAT;
            expectedLen = ALRM_DATLEN;
          } else if( 0 == strncmp("DOWN", cmd, 4)) {
	    printf( "Issuing /sbin/poweroff command, system going down...\n" );
	    system("/sbin/poweroff");
            // power down the chumby
            // cmdPowerDown();
            goto resetParse;
          } else if( 0 == strncmp("RSET", cmd, 4)) {
            // reset the chumby
            // cmdReset();
            goto resetParse;
          } else if( 0 == strncmp("TIME", cmd, 4)) {
	    sendTime();
	    goto resetParse;
#if RAND_ADVL_DBG
	  } else if( 0 == strncmp("RAND", cmd, 4)) {
	    testRandom();
	    goto resetParse;
          } else if( 0 == strncmp("ADVL", cmd, 4)) {
            printADC();
            goto resetParse;
#endif
	  } else {
            goto abortParse;
          }
	  // here we should have a command, and the state should have moved
	  if( state == PARSE_CMD )
	    goto abortParse; // if not, the parser messed up. you can't look for a command twice without going to reset.

	  datIndex = 0; // yeah, I know i set it to 0 up there too. gotta love patches.
	  if( expectedLen != 0 ) { // allocate a data buffer if the expectedLen is not 0
	    if( expectedLen > MAXLEN )
	      goto abortParse;

	    data = calloc((size_t) expectedLen + 1, sizeof(unsigned char)); // gotta have the null terminator so its +1
	    if( data == NULL ) {
	      sendFail();
	      goto resetParse;
	    }
	  }
        } // end command parsing

        break;

      case PARSE_DAT:
	if( datIndex < expectedLen ) {
	  data[datIndex] = c;
	  datIndex++;
	} else {
          data[datIndex] = '\0'; // cap the command here, where we hit our expected length...
	  state = PARSE_END;
	}
        break;
      case PARSE_END:
	//	printf( "parse_end\n" );
	if( c != ASCII_EOF ) {
	  //	  printf( "not ascii_eof %d\n", (int) c );
	  goto abortParse;
	}
	// ok, we had a well-formed input string. Let's do something with it now.
	if( 0 == strncmp("CHAL", cmd, 4) ) {  // CHAL packet
	  doChal(data, datIndex, CHAL_NOUSER);  
	} else if( 0 == strncmp("CHUP", cmd, 4 )) {
	  if( userPresent ) {
	    doChal(data, datIndex, CHAL_REQUSER);  
	    userPresent = 0; // don't forget to remove it!!!
	  } else { 
	    CPputs( "USER\n" );  // indicate that the user was not present at time of transaction request
	    CPputc( ASCII_EOF );
	  }
	} else if( 0 == strncmp("DLK0", cmd, 4)) {
	  keyLen = 0; // per ET
	  if(b64decode(data, (void **)keyHandle, &keyLen)) { // per ET
	    free( *keyHandle ); *keyHandle = NULL;  // key handle got malloc'd...
	    goto abortParse;
	  }
	  if( keyLen != 2 ) {
	    free( *keyHandle ); *keyHandle = NULL; // key handle got malloc'd...
	    goto abortParse;
	  }
	  keyCandidate = **keyHandle;
	  free( *keyHandle ); *keyHandle = NULL;
	  state = PARSE_CMD;
	  index = 0;
	  datIndex = 0;
	  expectedLen = 0;
	  cmd[0] = '\0'; cmd[1] = '\0'; cmd[2] = '\0'; cmd[3] = '\0';
	  lastWasDLK0 = 1;
	  free(data); data = NULL;
//	  setStopMode();
	  continue;  // this is important because it prevents a resetParse at the bottom of clause
	} else if( 0 == strncmp("DLK1", cmd, 4)) {
	  if( !lastWasDLK0 )
	    goto abortParse;
	  keyLen = 0;  // per ET
	  if(b64decode(data, (void **)keyHandle, &keyLen))
	    goto abortParse;  // per ET
	  if( keyLen != 2 ) {
	    free( *keyHandle ); *keyHandle = NULL; // key handle got malloc'd...
	    goto abortParse;
	  }
	  if( keyCandidate != **keyHandle ) {
	    free( *keyHandle ); *keyHandle = NULL;
	    goto abortParse;
	  }
	  lastWasDLK0 = 0;
	  // now do the erasure...
	  // eraseKey(keyCandidate);
	  free( *keyHandle ); *keyHandle = NULL;
	  goto resetParse;
	} else if( 0 == strncmp("PKEY", cmd, 4)) {
	  printf( "pkey2\n" );
	  doPkey(data, datIndex);
	} else if( 0 == strncmp("PIDX", cmd, 4)) {
	  doPidx(data, datIndex);
	} else {
	  goto resetParse;
	}
	// clean up.
	free(data); data = NULL;// just to be sure; memory leaks are very bad.
	goto resetParse;
	break;   // unreachable, but we leave it here just in case we edit later on
      case PARSE_WIPE:
        if( index > 3 || index < 0 ) { // this should never happen
          goto abortParse;
        }
        cmd[index] = c;
        index++;
        if( (index == 4) && (0 == strncmp("SURE", cmd, 4)) ) {
	  // this is coded in-line...
	  // this used to be a key wiping routine, not supported in this port
	  CPputc( ASCII_EOF );
	  goto resetParse;
	} else if (index >= 4) { // per ET
	  goto abortParse;
	}
	break;
      default:
      abortParse:
      resetParse:
	// setStopMode();
      resetNoStop:
        // kill and clear
        state = PARSE_CMD;
        index = 0;
	datIndex = 0;
        expectedLen = 0;
        cmd[0] = '\0'; cmd[1] = '\0'; cmd[2] = '\0'; cmd[3] = '\0';
	lastWasDLK0 = 0;
	keyCandidate = 0xFFFFFFFF;
        free(data); data = NULL;
      } // switch
#if POLLED_MODE
    } // else on the parse
#endif
  } // close of the while(1)

} // main()
