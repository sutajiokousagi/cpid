/*
  Cryptoprocessor code. Compliant to spec version 1.3.

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

#include "71x_lib.h"

#define JTAG_DEBUG 0

#define UART2_Rx_Pin (0x0001<<13)   /*  TQFP 64: pin N° 63 , TQFP 144 pin N° 143 */
#define UART2_Tx_Pin (0x0001<<14)   /*  TQFP 64: pin N° 64 , TQFP 144 pin N° 144 */
#define CHUMBY_RESET_Pin (0x0001 << 13)  /* BGA pin D6, port 1.13 */
#define CHUMBY_RESET_Bit (13)
#define CHUMBY_PowerOn_Pin (0x0001 << 15)
#define CHUMBY_PowerOn_Bit (15)
#define Osc_On_Pin (0x0001 << 10)
#define Osc_On_Bit (10)

#define MAJOR_VERSION 4
#define MINOR_VERSION 4
// version 3.0: corresponds to spec version 1.2.
// version 3.2: changed orientation of power switch on initial reset.
// version 3.3: updated for v1.5 hardware, reset orientation of power switch
// version 4.1: changed to be spec version 1.3.1 compliant
// version 4.2: changed to be spec version 1.3.2 complaint, stripped out ADVL and RAND reporting.
// version 4.3: changed to reflect 16 MHz crystal operation, as well as fix of bug 266
// version 4.4: changed to add support for 5V UVLO reset monitor

#define RAND_ADVL_DBG 0    // turn off debug output for RAND and ADVL

#include "beecrypt/sha1.h"
#include "beecrypt/aes.h"
#include "beecrypt/rsa.h"
#include "beecrypt/fips186.h"
#include "beecrypt/entropy.h"

#include "common.h"

#define POLLED_MODE 0

// patch for the most retarded firmware bug ever shipped in a microcontroller
unsigned long RAM_WMS_and_Wait[13] = {
  // set WMS mask -- initiate write to FLASH
  0xE3A00440,  // MOV R0, #0x40000000
  0xE3800940,  // ORR R0, R0, #0x100000
  0xE3A01440,  // MOV R1, #0x40000000
  0xE3811940,  // ORR R1, R1, #0x100000
  0xE5911000,  // LDR R1, [R1, #0x0]
  0xE3911480,  // ORRS R1, R1, #0x80000000
  0xE5801000,  // STR R1, [R0, #0x0]

  // wait for FLASH write to finish
  0xE3A00440, // MOV R0, #0x40000000
  0xE3800940, // ORR R0, R0, #0x100000
  0xE5900000, // LDR R0, [R0, #0]
  0xE3100016, // TST R0, #0x16
  0x1AFFFFFA, // BNE PC - 5 instrucions
  0xE1A0F00E, // MOV PC, LR
};

unsigned char powerState = 0;  // off

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

typedef unsigned char UINT8;


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

/*******************************************************************************
* Function Name  : FLASH_WordWrite
* Description    : Writes a Word in the Flash.
* Input 1        : Address of the Destination.
* Input 2        : Word to program at Address.
* Return         : None.
*******************************************************************************/
// I have to add this function because the stupid chip needs to run the
// polling wait function for flash write completion out of RAM!!!!
void FLASH_WordRAMWrite(u32 XtargetAdd, u32 Xdata)
{
  void (*ramfunc)(void) = (void(*)(void))RAM_WMS_and_Wait;

  /* Wait until another operation going on is completed */
  FLASH_WaitForLastTask();
  /* Set the Word Programming bit 'WPG' in the CR0 Reg */
  FLASHR->CR0 |= FLASH_WPG_Mask;
  /* Load the destination address in AR */
  FLASHR->AR   = XtargetAdd;
  /* Load DATA to be programmed in DR0 */
  FLASHR->DR0  = Xdata;
  /* Set the Write Mode Start bit 'WMS' in the CR0 Reg to Start Write Operation */
  (ramfunc)();
}

void setRunMode() {
  RCCU_RCLKSourceConfig ( RCCU_CLOCK2 );
  XTI_LineConfig(XTI_Line14, DISABLE); // disable interrupt on UART Rx

  GPIO_BitWrite(GPIO0, 10, 1); // OSC_OE, enable oscillator
  GPIO_BitWrite(GPIO0, 0, 1); // OSC_OE, enable oscillator -> for v1.5 and above

  RCCU->CFR |= RCCU_Div2_Mask; // divide xtal down to 8 MHz
  RCCU_PLL1Config(RCCU_PLL1_Mul_12, RCCU_Div_2); // now multiply up to 48 MHz

  while( !(RCCU->CFR & RCCU_PLL1_LOCK) ) // wait for PLL to lock before moving on!!
    ;
  RCCU_RCLKSourceConfig ( RCCU_PLL1_Output );

  /*  Re-Enable Rx */
  UART_OnOffConfig(UART2, ENABLE);
  /*  Disable FIFOs */
  UART_FifoConfig (UART2, DISABLE);
  /*  Reset the UART_RxFIFO */
  UART_FifoReset  (UART2 , UART_RxFIFO);
  /*  Reset the UART_TxFIFO */
  UART_FifoReset  (UART2 , UART_TxFIFO);
  /*  Disable Loop Back */
  UART_LoopBackConfig(UART2 , DISABLE);
                                         /* Configure the UART0 as following:
                                            - Baudrate = 9600 Bps
                                            - No parity
                                            - 8 data bits
                                            - 1 stop bit */
  UART_Config(UART2,38400,UART_NO_PARITY,UART_1_StopBits,UARTM_8D);

  UART_RxConfig(UART2 ,ENABLE);

  GPIO_Config(GPIO0, UART2_Tx_Pin, GPIO_AF_PP);  // re-enable UART outputs
  GPIO_Config(GPIO0, UART2_Rx_Pin, GPIO_IN_TRI_CMOS);

  powerTimer = RTC_CounterValue(); // give ourselves a new lease on life to get characters

  CPputc('?'); // rise and shine, let the host know we are awake now.

}

void setStopMode() {
  while( !(UART2->SR & UART_TxEmpty) )
    ; // wait for any transmitting characters to go out

#if !(JTAG_DEBUG)
  UART_RxConfig(UART2, DISABLE);  // kill the UART Rx until clocks come back...

  // disable external output to MX21 (leakage path)
  GPIO_Config(GPIO0,0xFBFF, GPIO_IN_TRI_CMOS);
  GPIO_Config(GPIO0,0x0000, GPIO_AF_PP);

  // set up the interrupts to wake up again
  /* Set Line 14 edge -- UART2 */
  XTI_LineModeConfig(XTI_Line14, XTI_RisingEdge);
  //  XTI_LineModeConfig(XTI_Line14, XTI_FallingEdge); // can't use this
  // because you get spurious "falling edge" interrupts as things power down

  // slow down the clocks
  RCCU_RCLKSourceConfig ( RCCU_CLOCK2_16 );
  RCCU_RCLKSourceConfig ( RCCU_RTC_CLOCK );

  // don't stop the external oscillator
  GPIO_BitWrite(GPIO0, 10, 1); // OSC_OE, enable oscillator
  GPIO_BitWrite(GPIO0, 0, 1); // OSC_OE, enable oscillator -> for v1.5 and above

  /* Enable the External interrupts on line 15 */
  XTI_LineConfig(XTI_Line14, ENABLE);
#endif
}

void setHardStopMode() {
  while( !(UART2->SR & UART_TxEmpty) )
    ; // wait for any transmitting characters to go out
#if !(JTAG_DEBUG)
  UART_RxConfig(UART2, DISABLE);  // kill the UART Rx until clocks come back...

  // disable external output to MX21 (leakage path)
  GPIO_Config(GPIO0,0xFBFF, GPIO_IN_TRI_CMOS);
  GPIO_Config(GPIO0,0x0000, GPIO_AF_PP);

  // set up the interrupts to wake up again
  /* Set Line 14 edge -- UART2 */
  XTI_LineModeConfig(XTI_Line14, XTI_RisingEdge);
  //  XTI_LineModeConfig(XTI_Line14, XTI_FallingEdge); // can't use this
  // because you get spurious "falling edge" interrupts as things power down

  // slow down the clocks
  RCCU_RCLKSourceConfig ( RCCU_CLOCK2_16 );
  RCCU_RCLKSourceConfig ( RCCU_RTC_CLOCK );

  // do stop the external oscillator
  GPIO_BitWrite(GPIO0, 10, 0); // OSC_OE, disable oscillator
  GPIO_BitWrite(GPIO0, 0, 0); // OSC_OE, disable oscillator -> for v1.5 and above

  /* Enable the External interrupts on line 15 */
  XTI_LineConfig(XTI_Line14, ENABLE);
#endif
}

int CPputs( char *str ) {
  int i = 0;
  while( str[i] != '\0' ) {
    UART_ByteSend(UART2, (u8 *)&(str[i++]));
  }
  return (i);
}

int CPputc( char c ) {
  UART_ByteSend(UART2, (u8 *)&c);
  return (1);
}

/****
   This function creates a random number
   by doing a SHA-1 digest on an entropy pool that is flavored
   by randomness gathered from a noisy A/D converter
   and made time-variant by looking at the RTC output
****/

int getRandom( octet *rand ) {  // should be a 16-octet string for the return value
  struct machDataInFlash *machDat;
  octet *entropySeed;
  u16 adcVal = ADC12_ConversionValue( ADC12_CHANNEL3 );
  sha1Param param;
  unsigned long curTime = RTC_CounterValue();
  int i;

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

  if(b64decode(data, (void **)kHandle, &len)) { // per ET
    free( *kHandle );
    return;
  }
  if( len != 2 ) {
    free( *kHandle );
    return;
  }
  x = **kHandle;
  pkey = setKey(x);
  free( *kHandle );
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
void doChal(char *data, int datLen) {
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

  if( authCount >= AUTH_MAX_AUTHS ) { // fail if auth count is too high
    CPputs( "AUTHCOUNT?\n" );
    CPputc( ASCII_EOF );
    return;
  }
  authCount++;
  // ok now do the challenge
  i = 0;
  while( i < datLen ) {
    if( data[i] == '\n' )
      data[i] = '\0';
    i++;
  }

  len = 0; // per ET
  if(b64decode(data, (void **)kHandle, &len)) { // per ET
    free( *kHandle );
    return;
  }
  if( len != 2 ) {
    free( *kHandle );
    return;
  }
  x = (unsigned short) **kHandle;
  free( *kHandle );
  if( x >= MAXKEYS ) { // fixed ge/gtr bug
    CPputs( "FAIL" );
    CPputc( ASCII_EOF );
    return;
  }
  pkey = setKey(x);
  if( pkey == NULL ) { CPputs( "FAIL" ); goto cleanup; }

  len = 0; // per ET
  if(b64decode(&(data[5]), (void **)kHandle, &len)) { // per ET
    free( *kHandle );
    return;
  }
  if( len != 16 ) {
    free( *kHandle );
    return;
  }
  mpnzero(&rn);
  if(mpnsetbin(&rn, (byte *) *kHandle, (size_t) len) != 0) {
    CPputs( "FAIL" );
    free( *kHandle );
    goto cleanup;
  }
  free( *kHandle );

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
      if( (i - 2) % 16 == 0 ) {
	if( getRandom( rand_oct ) != 0 ) { CPputs( "FAIL" ); CPputc( ASCII_EOF ); return; }
	j = 0;
      }
      m_os[i] = rand_oct[j++];
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
  free(m_os); // clear out the temp buffer

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
    free( cipher_os );
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
  m_os[i++] = 0;
  m_os[i++] = 0;

  memset(&writer, 0, sizeof(writer));
  base64_writer( &writer, m_os, SIGM_OS_SIZE, NULL );
  base64_finish_write(&writer, NULL );
  free( m_os );

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
  free(cipher_os);  // does this lead to fragmentation of the heap? eep. i wonder how good my mallocator is.

  // hash using SHA-1
  // re-use h_pid_oct variable to save space...
  if( sha1Reset(&param) ) { CPputs( "FAIL" ); goto cleanup; }
  if( sha1Update(&param, (byte *) m_os, M_OS_SIZE ) ) { CPputs( "FAIL" ); goto cleanup; }
  if( sha1Digest(&param, h_pid_oct) ) { CPputs( "FAIL" ); goto cleanup; }
  if( sha1Reset(&param) ) { CPputs( "FAIL" ); goto cleanup; }

  // get rid of variables we don't need anymore
  free(m_os);

  // pad the digest.
  m_os = calloc(MODULUS_LEN / 8, 1);
  if( m_os == NULL ) { CPputs( "FAIL" ); goto cleanup; }
  if( GenPkcs1Padding( m_os, MODULUS_LEN / 8, h_pid_oct ) != 0 ) {
    CPputs( "FAIL" ); goto cleanup;
  }
  mpnzero(&m);
  if(mpnsetbin(&m, (byte *) m_os, MODULUS_LEN / 8) != 0) { CPputs( "FAIL" ); goto cleanup; }
  free( m_os );
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
    free( cipher_os );
    goto cleanup;
  }
  memset(&writer, 0, sizeof(writer));
  base64_writer( &writer, cipher_os, MP_WORDS_TO_BYTES(mblind.size), NULL );
  base64_finish_write(&writer, NULL );
  free( cipher_os );
  mpnfree(&mblind);

 cleanup: // dealloc anything that could have been alloc'd...
  CPputc( ASCII_EOF );
  free( m_os );
  free( cipher_os );
  free( *kHandle );
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
    free( *kHandle );
    return;
  }
  if( len != 2 ) {
    free( *kHandle );
    return;
  }
  outputPublicKey(**kHandle);
  free( *kHandle );

  return;
}

/*
  Sets the wake-up alarm time
 */
void doAlarm(char *data, int datLen) {
  unsigned int *kPtr = NULL;
  unsigned int **kHandle = &kPtr;
  unsigned int len = 0;

  unsigned int alarmOffset = 0;
  unsigned int curTime = 0;

  if(b64decode(data, (void **)kHandle, &len)) { // per ET
    free( *kHandle );
    return;
  }
  if( len != 4 ) {
    free( *kHandle );
    return;
  }
  alarmOffset = **kHandle;
  free( *kHandle );

  curTime = RTC_CounterValue();
  if( (alarmOffset + curTime) < curTime ) {
    // we overflow; don't set the alarm and send a warning message
    CPputs( "OVFW\n" );
    CPputc( ASCII_EOF );
    return;
  }
  RTC_AlarmConfig(alarmOffset + curTime);
  // the interrupt response was already setup by init(); initial alarm setting is all F's
  CPputs( "ASET\n" );
  CPputc( ASCII_EOF );
  return;
}

/*
   erases an owner key specified by keyNum
*/
void eraseKey(unsigned int keyNum) {
  struct machDataInFlash *mdat = MACHDATABASE;
  int i;
  int error = 0;
  u32 writeAddr = 0;

  // this should erase the key pair enumerated by index keyNum
  if( keyNum >= NUM_OK ) {  // per ET
    CPputs( "INVALID KEY RANGE.\n" );
    CPputc( ASCII_EOF );
    return;
  }

  writeAddr = (u32) mdat->OK;
  writeAddr += 16 * keyNum;
  writeAddr -= FLASHBASE;

  // erase the key by writing all 0's over it
  for( i = 0; i < OK_SIZE; i += 4 ) {
    FLASH_WordRAMWrite(writeAddr + i, 0x0);
  }
  // verify it got erased, if not, let the user know!! very bad to have silent failure here.
  for( i = 0; i < OK_SIZE; i++ ) {  // per ET
    FLASH_WaitForLastTask();
    if( mdat->OK[keyNum][i] != 0x0 )
      error = 1;
  }
  if( error ) {
    CPputs( "KEY WAS NOT ERASED. PLEASE TRY AGAIN.\n" );
    CPputc( ASCII_EOF );
  }
}

/*************************************************************************/
// this function attempts to wait the number of ms specified by the passed arg

void wait_ms(unsigned int var)
{
  u32 i;
  u32 j;
  u32 loops_per_ms;
  u32 clocks_per_loop = 6;  // assume about 6 clocks per loop
  // calibrated with time optimizations OFF

  loops_per_ms = (RCCU_FrequencyValue(RCCU_MCLK) / clocks_per_loop) / 1000; // stopped here.

  for( i=0;i<=var;i++) {
    for( j = 0; j < loops_per_ms; j++ ) {
       ; // do nothing
    }
  }
}

/*************************************************************************/
// init all the hardware, call once on boot
void init() {

  RCCU_RCLKSourceConfig ( RCCU_CLOCK2 ); // start with solid clock.

  // units that we will use:
  // FLASH read/write -- store ADC calibration data, as well as other constants
  // hardware timer (for delays), 1ms resolution -- maybe just use polling on the RTC
  // ADC (for voltage sensing)

  // during normal operation, downclock system to ~4.8 MHz to save power
  // during crypto operation, upclock system to ~48 MHz for better performance

  // eventually, we need the WDT running too...

  // turn off peripherals we don't use
  APB_ClockConfig( APB1, DISABLE, USB_Periph );
  APB_ClockConfig( APB1, DISABLE, UART0_Periph );
  APB_ClockConfig( APB1, DISABLE, UART1_Periph );
  APB_ClockConfig( APB1, DISABLE, UART3_Periph );
  APB_ClockConfig( APB1, DISABLE, I2C0_Periph );
  APB_ClockConfig( APB1, DISABLE, I2C1_Periph );
  APB_ClockConfig( APB1, DISABLE, CAN_Periph );
  APB_ClockConfig( APB1, DISABLE, HDLC_Periph );
  APB_ClockConfig( APB1, DISABLE, BSPI0_Periph );
  APB_ClockConfig( APB1, DISABLE, BSPI1_Periph );
  APB_ClockConfig( APB2, DISABLE, TIM0_Periph );
  APB_ClockConfig( APB2, DISABLE, TIM1_Periph ); // don't use it, use XTI
  APB_ClockConfig( APB2, DISABLE, TIM2_Periph );
  APB_ClockConfig( APB2, DISABLE, TIM3_Periph );

  RCCU->PER = 0;    // save power, no EMI or USB interface
  PCU->PLL2CR |= 7; // PLL 2 off to save power

  // 48 MHz run mode
  RCCU->CFR |= RCCU_Div2_Mask; // divide xtal down to 8 MHz
  RCCU_PLL1Config(RCCU_PLL1_Mul_12, RCCU_Div_2); // now multiply up to 48 MHz
  while( !(RCCU->CFR & RCCU_PLL1_LOCK) ) // wait for PLL to lock before moving on!!
    ;

  RCCU_RCLKSourceConfig ( RCCU_PLL1_Output );

  //RCCU->CFR &= ~RCCU_Div2_Mask; // run at 12 MHz straight-up in this mode
  //RCCU_RCLKSourceConfig ( RCCU_CLOCK2 );

  /* GPIO peripheral configuration -------------------------------------------*/
  // port 0 pins
  /*
  P0.0 -- OSC_OE (output) (v1.5+ hardware)
  P0.1 -- NC
  P0.2 -- NC
  P0.3 -- NC
  P0.4 -- NC
  P0.5 -- input, +5V UVLO -- just a note, not yet configured in the code
  P0.6 -- NC
  P0.7 -- NC
  P0.8 -- NC
  P0.9 -- BOOT0
  P0.10 -- OSC_OE (output)
  P0.11 -- BOOT1
  P0.12 -- NC
  P0.13 -- MX21_TO_STR7 (UART2 input)
  P0.14 -- STR7_TO_MX21 (UART2 output)
  P0.15 -- CHUMBY_RESET_REQ (WAKEUP)

  GPIO input mask:  1011 1011 1111 1110
  GPIO output mask: 0000 0100 0000 0001
  GPIO AF_PP mask:  0100 0000 0000 0000
  */
  GPIO_Config(GPIO0,0xBBFE, GPIO_IN_TRI_CMOS);
  GPIO_Config(GPIO0,0x0401, GPIO_OUT_PP);
  GPIO_Config(GPIO0,0x4000, GPIO_AF_PP);
  GPIO_BitWrite(GPIO0, 10, 1); // OSC_OE, enable oscillator
  GPIO_BitWrite(GPIO0, 0, 1); // OSC_OE, enable oscillator --> for v1.5 hardware and above
  // port 1 pins
  /*
  P1.0 -- NC
  P1.1 -- NC
  P1.2 -- 33V_SENSE (ADC input 2)
  P1.3 -- noise input (ADC input 3)
  P1.4 -- NC
  P1.5 -- CHUMBY_RESET_REQ (Timer 1: Input capture B)
  P1.6 -- NC
  P1.7 -- SETEC_ASTRONOMY (input)
  P1.8 -- NC
  P1.9 -- NC
  P1.10 -- NC
  P1.11 -- NC
  P1.12 -- NC
  P1.13 -- CHUMBY_RESET (output)
  P1.14 -- CHUMBY_RESET_REQ (input)
  P1.15 -- CHUMBY_ON (output)

  GPIO input mask:  0001 1111 1111 0011
  GPIO output mask: 1010 0000 0000 0000
  analog input:     0000 0000 0000 1100
  */
  GPIO_Config(GPIO1,0x1FF3,GPIO_IN_TRI_CMOS);
  GPIO_Config(GPIO1,0xA000,GPIO_OUT_PP);
  GPIO_Config(GPIO1,0x000C,GPIO_HI_AIN_TRI);
  GPIO_BitWrite(GPIO1, 15, 0); // chumby off
  powerState = 0;
  GPIO_BitWrite(GPIO1, 13, 0); // chumby in reset

  /*  Configure the GPIO pins */  // aint broke dont fix it
  GPIO_Config(GPIO0, UART2_Tx_Pin, GPIO_AF_PP);
  GPIO_Config(GPIO0, UART2_Rx_Pin, GPIO_IN_TRI_CMOS);

  /*  Initialize the FLASH ---------------------------------------------------*/
  FLASH_Init ();
  // all parameters stored in B1F1 and B1F0!
  // 8k blocks each--define memory map...
  /*
     parameters include:
     RSA private keys
     RSA public keys
     serial numbers
     random number seeds
     ADC calibration data
  */

  /* UART peripheral configuration -------------------------------------------*/

  /*  Configure the UART X */
  /*  Turn UART2 on */
  UART_OnOffConfig(UART2, ENABLE);
  /*  Disable FIFOs */
  UART_FifoConfig (UART2, DISABLE);
  /*  Reset the UART_RxFIFO */
  UART_FifoReset  (UART2 , UART_RxFIFO);
  /*  Reset the UART_TxFIFO */
  UART_FifoReset  (UART2 , UART_TxFIFO);
  /*  Disable Loop Back */
  UART_LoopBackConfig(UART2 , DISABLE);
                                         /* Configure the UART0 as following:
                                            - Baudrate = 9600 Bps
                                            - No parity
                                            - 8 data bits
                                            - 1 stop bit */
  UART_Config(UART2,38400,UART_NO_PARITY,UART_1_StopBits,UARTM_8D);
  /*  Enable Rx */
  UART_RxConfig(UART2 ,ENABLE);


  /*  RTC init ---------------------------------------------------------------*/
  /*  Configure RTC prescaler */
  RTC_PrescalerConfig ( 32768 );   // 1 second basic clock

  /*  Clear Pending Flags */
  RTC_FlagClear ( RTC_OWIR );
  RTC_FlagClear ( RTC_AIR  );
  RTC_FlagClear ( RTC_SIR  );
  RTC_FlagClear ( RTC_GIR  );

  /* Timer init -------------------------------------------------------------*/
#if 0 // don't use this anymore, use the XTI
  /*  Initialize the Timer */
  TIM_Init ( TIM1 );

  /*  Configure the TIM Prescaler */
  TIM_PrescalerConfig ( TIM1, 0x1 );
  /* TODO: write remainder of code for ICAP of reset pulse */

  TIM_ICAPModeConfig( TIM1, TIM_CHANNEL_B, TIM_RISING );

  /*  Enable the IRQ0 for timer 1 */
  EIC_IRQChannelConfig( T1TIMI_IRQChannel, ENABLE );
  EIC_IRQChannelPriorityConfig( T1TIMI_IRQChannel, 1);
  EIC_IRQConfig( ENABLE );

  TIM1->CR2 |= TIM_ICBIE_Mask;
#endif

  /* EIC peripheral configuration --------------------------------------------*/

#if 0  // we are going to do this polled.
  /* Configure the EIC channel interrupt */
  EIC_IRQChannelPriorityConfig(UART2_IRQChannel, 1);
  EIC_IRQChannelConfig(UART2_IRQChannel, ENABLE);
  EIC_IRQConfig(ENABLE);

  UART_ItConfig(UART2,UART_RxBufFull, ENABLE);
#endif

  /*  Enable RTC IRQ channel */
  EIC_IRQChannelConfig( RTC_IRQChannel, ENABLE );
  EIC_IRQChannelPriorityConfig( RTC_IRQChannel, 1);
  EIC_IRQConfig( ENABLE );

  /*  Enable Alarm Interrupt */
  RTC_ITConfig( RTC_AIT, ENABLE );
  RTC_ITConfig( RTC_GIT, ENABLE );


  // don't use the ADC, it's too flakey
  /* ADC init ---------------------------------------------------------------*/
  /*  Initialize the conveter register. */
  ADC12_Init();
  /*  Configure the prescaler register using the configured PCLK with
   a sampling frequency=1000Hz */
  //  ADC12_PrescalerConfig(1000);
  ADC12_PrescalerConfig(1000);  // init for max noise

  /*  Select the round-robin conversion mode */
  ADC12_ModeConfig (ADC12_ROUND);

  /* Select the Channel 2 to be converted, because we use it as a RNG seeds */
  ADC12_ChannelSelect(ADC12_CHANNEL3);

  /* the 3.3V line should be powered down now (0V)--if not, tough luck. */
  ADC12_ConversionStart();
  //  ADCzeroCode = ADC12_ConversionAverage( ADC12_CHANNEL3, 32); // 32 samples is all the time we have

  /* XTI init ---------------------------------------------------------------*/
  XTI_Init();

  /* Set Line 15 edge -- WAKEUP pin */
  XTI_LineModeConfig(XTI_Line15, XTI_RisingEdge);
  /* Enable the External interrupts on line 15 */
  XTI_LineConfig(XTI_Line15, ENABLE);
  /* Set the XTI mode */
  XTI_ModeConfig(XTI_Interrupt, ENABLE);

  /* Configure the XTI IRQ channel -----------------------------------------*/
  /*  Set the XTI IRQ Channel priority to 1*/
  EIC_IRQChannelPriorityConfig(XTI_IRQChannel,1);
  /* Enable XTI IRQ Interrupts */
  EIC_IRQChannelConfig(XTI_IRQChannel,ENABLE);
  /* Enable IRQ interrupts on EIC */
  EIC_IRQConfig(ENABLE);

  return;

}

void cmdPowerDown() { // power down the chumby
  GPIO_BitWrite(GPIO1, 13, 0); // chumby in reset
  GPIO_BitWrite(GPIO1, 15, 0); // chumby off
  powerState = 0;
  // TODO: put myself (the CP) into a deep sleep mode
  setHardStopMode();
}

void cmdPowerUp() {
  GPIO_BitWrite(GPIO1, 13, 0); // chumby in reset
  GPIO_BitWrite(GPIO1, 15, 1); // chumby powered up
  powerState = 1;
  GPIO_BitWrite(GPIO0, 10, 1); // OSC_OE, enable oscillator
  GPIO_BitWrite(GPIO0, 0, 1); // OSC_OE, enable oscillator --> for v1.5A hardware and above

  // TODO: check 3.3V power status here...
  // actually, the ADC is so flakey you can't use it for this application.
  //  wait_ms(800);  // according to Table 11 in MX21 datasheet

  wait_ms(500); // really, it just kills me to wait 800 ms.
  // I think the datasheet is full of it. I give you half a second, bitch!

  GPIO_BitWrite(GPIO1, 13, 1); // chumby out of reset
}

void cmdReset() {
  GPIO_BitWrite(GPIO1, 13, 0); // chumby in reset
  wait_ms(500);  // wait half a second to let in soak in
  GPIO_BitWrite(GPIO1, 13, 1); // chumby out of reset
}

void sendTime() {
  unsigned long time = RTC_CounterValue();
  struct writer_cb_parm_s writer;

  memset(&writer, 0, sizeof(writer));
  CPputs( "TIME" );
  base64_writer( &writer, &time, sizeof(time), NULL );
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
  adcv = ADC12_ConversionValue( ADC12_CHANNEL3 );

  //adcv = 12;
  CPputs( "ADCV" );
  base64_writer( &writer, &adcv, sizeof(adcv), NULL );
  base64_finish_write(&writer, NULL );
  CPputc( ASCII_EOF );
}
#endif

// see authentication spec doc for these magic numbers
#define CHAL_DATLEN  29
#define AUTH_DATLEN  384
#define DLK0_DATLEN  4
#define DLK1_DATLEN  4
#define PKEY_DATLEN  4
#define ALRM_DATLEN  8

#define MAXLEN  384

/*************************************************************************/

int main(void) {
  char cmd[4];
  char *data = NULL;
  unsigned int expectedLen = 0;
  unsigned int index = 0;
  unsigned int datIndex = 0;
  ParserState state = PARSE_CMD;
  char c;
  unsigned int authRatio;

#ifdef DEBUG
  debug();
#endif

  init();  // init all the hardware
  // chumby is off and in reset after init()

  lastAuthTime = 0;
  powerTimer = 0;
  wait_ms(100); // to let JTAG debuggers be happy...
  cmdPowerDown(); // this line flips between version 1.4 and 1.5 of hardware
  // the chumby should appear "off" when first plugged in

  // TODO: REWORK ABORT MECHANISM TO NOT LEAK INTERNAL STATE DUE TO TIMING ATTACKS
  index = 0;
  while(1) {
    // manage the authorization count
    if( (RTC_CounterValue() - lastAuthTime) > AUTH_INTERVAL_SECS ) {
      // grab the ratio, because we can sleep for a very long time before we update
      // this netx line of code is always guaranteed to be greater than 1
      // by virtue of the if statement above
      authRatio = (RTC_CounterValue() - lastAuthTime) / AUTH_INTERVAL_SECS;

      // update the lastAuthTime
      lastAuthTime = RTC_CounterValue();

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
    if( (GPIO1->PD & 0x4000) ) {
      // this is the reset request active code path:
      // during reset, we ignore all serial traffic from processor
      // to prevent timing attacks, etc. hence the polled serial implementation
      if( powerState == 0 ) {  // if we are powered down...
	cmdPowerUp();  // then power up
	while( (GPIO1->PD & 0x4000) )
	  ;  // wait until button released...
	wait_ms(50); // debounce time, 50 ms
	continue;
      } else {  // if we are powered up...
	cmdPowerDown(); // then power down
	while( (GPIO1->PD & 0x4000) )
	  ;  // wait until button released...
	wait_ms(50); // debounce time, 50 ms
	continue;
      }
    } else { // parse input serial stream
#endif
      // code path for when there is no reset request button push:
      
      // check if the +5V UVLO has triggered while powered on
      // of course, we don't care about UVLO if we're powered off!!
      if( (powerState == 1) && ((GPIO0->PD & 0x20) == 0) ) {
	// if UVLO is triggered while we are in a powered on state,
	// force the machine into a hard-powered down state!
	cmdPowerDown();
      }

      // grab a character
      if(UART_FlagStatus(UART2) & UART_RxBufFull) {
        UART_ByteReceive(UART2, (u8 *) &c, 0xFF);
	powerTimer = RTC_CounterValue(); // update the power-down timer
        if( c == '!' ) { // synchronize the stream to '!' character
	  CPputc('?'); // rise and shine, let the host know we are awake now.
          goto resetNoStop;
        }
      } else {
	// manage power
	if( (RTC_CounterValue() - powerTimer) > PWDWN_TIMEOUT ) {
	  powerTimer = RTC_CounterValue();
	  if( powerState == 0 )
	    setHardStopMode(); // turn off the ext. oscillator too
	  else
	    setStopMode(); // go to sleep to save power
	}
        continue; // go to the top of loop, check for reset req, etc.
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
          if( 0 == strncmp("CHAL", cmd, 4) ) {  // CHAL packet
            state = PARSE_DAT;
            expectedLen = CHAL_DATLEN;
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
            // power down the chumby
            cmdPowerDown();
            goto resetParse;
          } else if( 0 == strncmp("RSET", cmd, 4)) {
            // reset the chumby
            cmdReset();
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
	if( c != ASCII_EOF )
	  goto abortParse;
	// ok, we had a well-formed input string. Let's do something with it now.
	if( 0 == strncmp("CHAL", cmd, 4) ) {  // CHAL packet
	  doChal(data, datIndex);
	} else if( 0 == strncmp("DLK0", cmd, 4)) {
	  keyLen = 0; // per ET
	  if(b64decode(data, (void **)keyHandle, &keyLen)) { // per ET
	    free( *keyHandle );  // key handle got malloc'd...
	    goto abortParse;
	  }
	  if( keyLen != 2 ) {
	    free( *keyHandle );  // key handle got malloc'd...
	    goto abortParse;
	  }
	  keyCandidate = **keyHandle;
	  free( *keyHandle );
	  state = PARSE_CMD;
	  index = 0;
	  datIndex = 0;
	  expectedLen = 0;
	  cmd[0] = '\0'; cmd[1] = '\0'; cmd[2] = '\0'; cmd[3] = '\0';
	  lastWasDLK0 = 1;
	  free(data);
	  setStopMode();
	  continue;  // this is important because it prevents a resetParse at the bottom of clause
	} else if( 0 == strncmp("DLK1", cmd, 4)) {
	  if( !lastWasDLK0 )
	    goto abortParse;
	  keyLen = 0;  // per ET
	  if(b64decode(data, (void **)keyHandle, &keyLen))
	    goto abortParse;  // per ET
	  if( keyLen != 2 ) {
	    free( *keyHandle );  // key handle got malloc'd...
	    goto abortParse;
	  }
	  if( keyCandidate != **keyHandle ) {
	    free( *keyHandle );
	    goto abortParse;
	  }
	  lastWasDLK0 = 0;
	  // now do the erasure...
	  eraseKey(keyCandidate);
	  free( *keyHandle );
	  goto resetParse;
	} else if( 0 == strncmp("PKEY", cmd, 4)) {
	  doPkey(data, datIndex);
	} else if( 0 == strncmp("PIDX", cmd, 4)) {
	  doPidx(data, datIndex);
	} else if( 0 == strncmp("ALRM", cmd, 4)) {
	  doAlarm(data, datIndex);
	} else {
	  goto resetParse;
	}
	// clean up.
	free(data); // just to be sure; memory leaks are very bad.
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
      	  if( (GPIO1->PD & 0x0080) == 0 ) {  // test test test!!! set to == for production
	    // SETEC_ASTRONOMY IS ASSERTED!
	    CPputs( "UNLOCK STAGE 2 SUCCESS. TOO MANY SECRETS.\n" );
	    FLASH_WordRAMWrite(0xC0000, 0); // call this to load in flashing firmware
	    FLASH_WritePrConfig (FLASH_B1F0,DISABLE) ;
	    FLASH_SectorErase (FLASH_B1F0);
	    FLASH_WritePrConfig (FLASH_B1F1,DISABLE) ;
	    FLASH_SectorErase (FLASH_B1F1);
	    CPputs( "NO MORE SECRETS.\n" );
	    FLASH_WaitForLastTask();
	    wait_ms(1000);
	    cmdReset();  // reset the host CPU
	  } else {
	    CPputs( "SETEC ASTRONOMY is not asserted. Aborting.\n" );
	  }
	  CPputc( ASCII_EOF );
	  goto resetParse;
	} else if (index >= 4) { // per ET
	  goto abortParse;
	}
	break;
      default:
      abortParse:
      resetParse:
	setStopMode();
      resetNoStop:
        // kill and clear
        state = PARSE_CMD;
        index = 0;
	datIndex = 0;
        expectedLen = 0;
        cmd[0] = '\0'; cmd[1] = '\0'; cmd[2] = '\0'; cmd[3] = '\0';
	lastWasDLK0 = 0;
	keyCandidate = 0xFFFFFFFF;
        free(data);
      } // switch
#if POLLED_MODE
    } // else on the parse
#endif
  } // close of the while(1)

} // main()

/******************* (C) COPYRIGHT 2003 STMicroelectronics *****END OF FILE****/
