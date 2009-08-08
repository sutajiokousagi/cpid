#include <unistd.h>

/* size of a private key:
PKI_N:0:  256 hex digits = 1024 bits
PKI_E:0:  8   hex digits = 32 bits
PKI_I:0:  32  hex digits = 128 bits
PKI_P:0:  128 hex digits = 512 bits
PKI_Q:0:  128 hex digits = 512 bits
PKI_DP:0: 128 hex digits = 512 bits
PKI_DQ:0: 128 hex digits = 512 bits
PKI_QI:0: 128 hex digits = 512 bits

Total size: 7328 bits = 472 bytes
Pad to 512 bytes/record

Size of EEPROM: 16 kbytes

Need to store:
- private keys (local only)
- machine data record (local only)
  - id
  - sn
  - hwversion
  - owner keys
  - AQS public keys
  - some entropy seeds

- block encrypted to server private key:
  - 128-bit super-secret AES key (16 bytes)
  - 128-bit GUID (16 bytes)
  - 128-bit Serial number (16 bytes)
  - 128-bit version (16 bytes)
  - for each private key: 149 bytes each
    - 1-byte key ID index plus 128-bit(16b) guid
    - public key 1024-bit(128b) N
    - public key 32-bit(4b) E

*/
#define RAND_ADVL_DBG 0    // remember to turn off debug output for RAND and ADVL for production
#define DEBUG_SETEC   0    // remember to turn off SETEC debugging for production

#define DEFAULT_IO_PIPE "/tmp/.cpid"

typedef unsigned char UINT8;
typedef unsigned char octet;

// this is very much hard-coded for 1024 bit keys.
// this is intentional, as memory layout assumptions
// are intimately connected with key size, and this is
// not obvious...so this is to prevent potential bugs
// when I forget about this and diddle with keylength
// without carefully checking/rewriting the code.
// in other words, I'm forcing myself to reconsider
// everything if I change key sizes.
struct privKeyInFlash {
  octet  i[16];  // PID
  octet  p[64];
  octet  q[64];
  octet  dp[64];
  octet  dq[64];
  octet  qi[64];
  octet  n[128];
  octet  e[4];
  octet  created[4];
  octet  padding[40]; // pad to 512 byte record length
};

#define MAXKEYS 21
struct privKeyInFlash *KEYBASE;
#define KEYRECSIZE 0x200
//#define KEYMINBOUND (unsigned long)(*KEYBASE))
//#define KEYMAXBOUND (unsigned long)(*KEYBASE + sizeof(struct privKeyInFlash) * MAXKEYS))
#define NUM_OK  28  // chumby can exchange hands or have passwords lost 28 times...
#define OK_SIZE 16

struct machDataInFlash {  // this is machine specific data
  octet  ID[16];     // this is a unique GUID
  octet  SN[16];     // device serial number
  octet  HWVER[16];  // hardware version number (for the chumby core)
  octet  OK[NUM_OK][16]; // many owner keys

  octet  AQSn[256];  // AQS public keys
  octet  AQSe[4];
  octet  entropySeed[16][16]; // 128 bit seeds for entropy, unique per box, randomly selected
};
/*
  estimated size:
  16 + 16 + 16*128 + 256 + 4 + 16*16 bytes = 2596 bytes
  so reserve min. 4096 bytes for this region in overall layout planning
*/
struct machDataInFlash *MACHDATABASE;
#define MACHDATAEND  (MACHDATABASE + sizeof(machDataInFlash))

/* data used by the writer callbacks */
struct writer_cb_parm_s {
  int wrote_begin;
  int did_finish;

  struct {
    int idx;
    int quad_count;
    unsigned char radbuf[4];
  } base64;

};

struct pubKeyVer3Pkt {
  octet version; // should be 3
  octet created[4];
  octet validFor[2];
  octet pkAlg;
  octet nSize[2];
  octet n[128];
  octet eSize[2];
  octet e[4];
};

// defined in makePackets
int base64_writer (void *cb_value, const void *buffer, size_t count, char *pem_name);
int base64_finish_write (struct writer_cb_parm_s *parm, char *pem_name);

int outputPublicKey(unsigned int keyNumber);
struct privKeyInFlash *setKey(unsigned int keyNumber);
int b64decode(const char* s, void** datap, size_t* lenp);

// defined in crypto
int getRandom( octet *rand );
unsigned int getOKnum();
void doPidx(char *data, int datLen);
int GenPkcs1Padding(UINT8 *buf, int len, UINT8 *hashVal);
void doChal(char *data, int datLen, char userType);
void doPkey(char *data, int datLen);
void doAlarm(char *data, int datLen);
void eraseKey(unsigned int keyNum);
void sendTime();
void sendFail();
void outputVersion();
void outputSN();
void outputCurrentOK();
void outputHWVersion();
#if RAND_ADVL_DBG
void testRandom();
void printADC();
#endif
void crypto(char *keyfile);

// defined in hal
int CPputs( char *str );
int CPputc( char c );
void eraseKey(unsigned int keyNum);
void wait_ms(unsigned int var);
unsigned short ADC_RandValue();

#define ASCII_EOF 0x0D
#define AUTH_INTERVAL_SECS 90  // 90 seconds ... once per 90-second leak is OK with user present button!
#define AUTH_MAX_AUTHS  15  // up to 15 auth tries -- then the leak counter starts

#define PWDWN_TIMEOUT   5  // seconds to powerdown timeout

#define USER_TIMEOUT  60     // users have 60 seconds from button push to running a CHUP command

#define CHAL_NOUSER  0       // these define values are passed through to the protocol
#define CHAL_REQUSER 1       // so don't change them arbitrarily or you break the protocol!


