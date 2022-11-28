#include <stdio.h>
#include <iostream>
#include <string>
#include <ostream>

#define RESET "\033[0m"
#define BRED "\033[1m\033[31m"     /* Bold Red */
#define BGREEN "\033[1m\033[32m"   /* Bold Green */
#define BYELLOW "\033[1m\033[33m"  /* Bold Yellow */
#define BBLUE "\033[1m\033[34m"    /* Bold Blue */
#define BMAGENTA "\033[1m\033[35m" /* Bold Magenta */
#define BCYAN "\033[1m\033[36m"    /* Bold Cyan */

#define WORD32 unsigned int
#define BYTE unsigned char

#define ROUNDS 4

#define ROT2(x) (((x) << 2) | ((x) >> 6))

#define G0(a, b) (ROT2((BYTE)((a) + (b))))
#define G1(a, b) (ROT2((BYTE)((a) + (b) + 1)))

using namespace std;

/* Found keys */
unsigned long K0[] = {};
unsigned long K1[] = {};
unsigned long K2[] = {};
unsigned long K3[] = {};
unsigned long K4[] = {};
unsigned long K5[] = {};

static WORD32 pack32(BYTE *b)
{ /* pack 4 bytes into a 32-bit Word */
    return (WORD32)b[3] | ((WORD32)b[2] << 8) | ((WORD32)b[1] << 16) | ((WORD32)b[0] << 24);
}

static void unpack32(WORD32 a, BYTE *b)
{ /* unpack bytes from a 32-bit word */
    b[0] = (BYTE)(a >> 24);
    b[1] = (BYTE)(a >> 16);
    b[2] = (BYTE)(a >> 8);
    b[3] = (BYTE)a;
}

WORD32 f(WORD32 input)
{
    BYTE x[4], y[4];
    unpack32(input, x);
    y[1] = G1(x[1] ^ x[0], x[2] ^ x[3]);
    y[0] = G0(x[0], y[1]);
    y[2] = G0(y[1], x[2] ^ x[3]);
    y[3] = G1(y[2], x[3]);
    return pack32(y);
}

void encrypt(BYTE data[8], WORD32 key[6])
{
    WORD32 left, right, temp;

    left = pack32(&data[0]) ^ key[4];
    right = left ^ pack32(&data[4]) ^ key[5];

    for (int i = 0; i < ROUNDS; i++)
    {
        temp = right;
        right = left ^ f(right ^ key[i]);
        left = temp;
    }

    left ^= right;

    unpack32(right, &data[0]);
    unpack32(left, &data[4]);
}

void decrypt(BYTE data[8], WORD32 key[6])
{
    WORD32 left, right, temp;

    right = pack32(&data[0]);
    left = right ^ pack32(&data[4]);

    for (int i = 0; i < ROUNDS; i++)
    {
        temp = left;
        left = right ^ f(left ^ key[ROUNDS - 1 - i]);
        right = temp;
    }

    right ^= left;

    left ^= key[4];
    right ^= key[5];
    unpack32(left, &data[0]);
    unpack32(right, &data[4]);
}

int main(int argc, char **argv)
{
    BYTE data[8];

    BYTE ciphertext[8];
  
    argc--; argv++;

    /* Get plaintext for encryption */
    for (int i = 0; i < 8; i++)
        sscanf(argv[i], "%hhx", &data[i]);

    /* Get ciphertext for checking */
    int p = 0;
    for (int j = 8; j < 16; j++){
        sscanf(argv[j], "%hhx", &ciphertext[p]);
        p++;
    }

    cout << BGREEN << "[PLAINTEXT INPUT]:       " << RESET;
    for (int i = 0; i < 8; i++)
        cout << BGREEN << hex << (int) data[i] << RESET;
    cout << "\n";

    cout << BCYAN << "[CIPHERTEXT INPUT]:      " << RESET;
    for (int i = 0; i < 8; i++)
        cout << BCYAN << hex << (int) ciphertext[i] << RESET;
    cout << "\n";

    int max = 0;

    /* Main loop where all keys are checked */
    for (int k0 = 0; k0 < sizeof(K0)/sizeof(*K0); k0++)
    {
        for (int k1 = 0; k1 < sizeof(K1)/sizeof(*K1); k1++)
        {
            for (int k2 = 0; k2 < sizeof(K2)/sizeof(*K2); k2++)
            {
                for (int k3 = 0; k3 < sizeof(K3)/sizeof(*K3); k3++)
                {
                    for (int k4 = 0; k4 < sizeof(K4)/sizeof(*K4); k4++)
                    {
                        for (int k5 = 0; k5 < sizeof(K5)/sizeof(*K5); k5++)
                        {
                            int counter = 0;

                            WORD32 key[6] = {K0[k0], K1[k1], K2[k2], K3[k3], K4[k4], K5[k5]};
                            encrypt(data, key);

                            for(int i = 0; i < 8; i++){
                                if(ciphertext[i] == data[i]){
                                    if(counter > max){
                                        cout << counter << "\n";
                                        max = counter;

                                        cout << BYELLOW << "[CIPHERTEXT CALCULATED]: " << RESET;
                                        for(int m = 0; m < 8; m++){
                                            cout << (int) data[m];
                                        }
                                        cout << "\n";

                                        cout << BRED << "[CIPHERTEXT IN USE]:     " << RESET;
                                        for(int m = 0; m < 8; m++){
                                            cout << (int) ciphertext[m];
                                        }
                                        cout << "\n";
                                        
                                        cout << BBLUE << "[KEY IN USE]:            " << RESET;
                                        for(int m = 0; m < 6; m++){
                                            cout << (int) key[m] << " ";
                                        }
                                        cout << "\n";
                                    }
                                    counter++;
                                }
                            }

                            if(counter == 8){
                                cout << "\a";
                            }else{
                                continue;
                            }

                            cout << BMAGENTA << "[CIPHERTEXT ENCRYPTED]:  " << RESET;
                            for (int i = 0; i < 8; i++)
                                cout << BMAGENTA << hex << (int) data[i] << RESET;
                            cout << "\n";

                            decrypt(data, key);

                            cout << BCYAN << "[PLAINTEXT DECRYPTED]:   " << RESET;
                            for (int i = 0; i < 8; i++)
                                cout << BCYAN << hex << (int) data[i] << RESET;
                            cout << "\n";

                            cout << BRED << "[KEY IN USE]:            " << RESET;
                            for (int i = 0; i < 6; i++)
                                cout << BRED << "0x" << hex << (int) key[i] << " " << RESET;
                            cout << "\n";

                            cout << BYELLOW << "[KEY INDEXES]:           " << RESET;
                            cout << BYELLOW << dec << k0 << " " << k1 << " " << k2 << " " << k3 << " " << k4 << " " << k5 << " " << RESET;

                            cout << "\n\n";
                        }
                    }
                }
            }
        }
    }
    return 0;
}
