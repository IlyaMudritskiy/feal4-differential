#include <iostream>

#define MAX_CHOSEN_PAIRS 12

/* Define colours for colored output */
#define RESET   "\033[0m"
#define BRED     "\033[1m\033[31m"      /* Bold Red */
#define BGREEN   "\033[1m\033[32m"      /* Bold Green */
#define BYELLOW  "\033[1m\033[33m"      /* Bold Yellow */
#define BBLUE    "\033[1m\033[34m"      /* Bold Blue */
#define BMAGENTA "\033[1m\033[35m"      /* Bold Magenta */
#define BCYAN    "\033[1m\033[36m"      /* Bold Cyan */

using namespace std;

typedef unsigned long long ull;
typedef unsigned uint;
typedef unsigned char byt;

/* Array for key */
uint key[6];

/* Array for storing key candidates temporarily */
const int tmpkeys_num = 4;
ull tmp[tmpkeys_num];

/* 
Arrays for storing key candidates on each step.
Recommended amount of plaintext-ciphertext pairs is 12.
For these keys function "contains" check for duplicates and only unique keys are stored.
*/
ull k3_candidates[4] = {}; 
ull k2_candidates[16] = {};
ull k1_candidates[16] = {};

// Plaintext0
ull plaintext0[MAX_CHOSEN_PAIRS] = {};

// Base values without XOR
ull ciphertext0[MAX_CHOSEN_PAIRS] = {};

// K3
ull ciphertext1_3[MAX_CHOSEN_PAIRS] = {};

// K2
ull ciphertext1_2[MAX_CHOSEN_PAIRS] = {};

// K1
ull ciphertext1_1[MAX_CHOSEN_PAIRS] = {};

/* Checks for duplicate keys inside main loop */
bool contains(ull *arr, ull val, int size){
	for(int i = 0; i < size; i++){
		if(arr[i] == val){
			return true;
		}
	return false;
	}
}

/* After each round (K3, K2, ...) restores plaintexts to their original values */
void reset_ciphers(){
	ull cipher0[MAX_CHOSEN_PAIRS] = {8834553205828878318, 6082196074026541370, 11591137174107162581, 17265430127583613179, 7210736699715502002, 6449420496972245365, 4739710030990184805, 13566658884631887446, 16481949226486595164, 13083205611118652472, 3875996477926958360, 755362347803990147};
	ull cipher1_3[MAX_CHOSEN_PAIRS] = {17120773296355035297, 4533672156975471214, 4384369603723162209, 9987505273401208419, 6638025095776104773, 4828539196429685473, 13049538813474464422, 11689611409902419486, 9636339151753796804, 7011526402097422222, 2110155980153736309, 14857078142595607332};
	ull cipher1_2[MAX_CHOSEN_PAIRS] = {3134638356582453261, 709013979822590525, 10414699114497048015, 3363188764259517586, 4476401037084410947, 10035801302831661697, 1460090017179026701, 3046527303097055814, 17239230010452855816, 13304226594339579202, 4450983804732293450, 4590742813733182962};
	ull cipher1_1[MAX_CHOSEN_PAIRS] = {4833211267481802819, 11423719876761726162, 9031170619566735225, 14854073504649387314, 7729285096587876174, 2756282412057797713, 15682581863627712573, 7982663737908706731, 12745242669948210763, 3503832923747996228, 11906383222856494808, 8077358737858071758};

	for(int i = 0; i < MAX_CHOSEN_PAIRS; i++){
		ciphertext0[i] = cipher0[i];
		ciphertext1_1[i] = cipher1_1[i];
		ciphertext1_2[i] = cipher1_2[i];
		ciphertext1_3[i] = cipher1_3[i];
	}
}

uint getLeftHalf(ull x)
{
	return x >> 32;
}

uint getRightHalf(ull x)
{
	return x & 0xFFFFFFFFULL;
}

ull getCombinedHalves(uint a, uint b){
	return (ull(a)<<32) | (ull(b) & 0xFFFFFFFFULL);
}

byt g(byt a, byt b, byt x){
	byt tmp = a + b + x;
	return ( tmp << 2 ) | ( tmp >> 6 );
}

uint f(uint input){

	byt x[4], y[4];
	for(int i=0; i<4; i++){
		x[3-i] = byt(input & 0xFF);
		input >>= 8;
	}

	y[1] = g(x[0]^x[1], x[2]^x[3], 1);
	y[0] = g(x[0], y[1], 0);
	y[2] = g(x[2]^x[3], y[1], 0);
	y[3] = g(x[3], y[2], 1);

	uint output=0;
	for(int i=0; i<4; i++)
		output += (uint(y[i])<<(8*(3-i)));

	return output;
}

void decryptLastOperation(ull *cipher1)
{
    for(int i = 0; i < MAX_CHOSEN_PAIRS; i++)
    {
        uint cipherLeft0 = getLeftHalf(ciphertext0[i]);
        uint cipherRight0 = getRightHalf(ciphertext0[i]) ^ cipherLeft0;
        uint cipherLeft1 = getLeftHalf(cipher1[i]);
        uint cipherRight1 = getRightHalf(cipher1[i]) ^ cipherLeft1; 
        
        ciphertext0[i] = getCombinedHalves(cipherLeft0, cipherRight0); 
        cipher1[i] = getCombinedHalves(cipherLeft1, cipherRight1);
    }
}

ull * crackHighestRound(uint differential, ull *cipher1)
{
	for(int k = 0; k < 4; k++){
		tmp[k] = 0;
	}
	cout << BGREEN <<  "[STARTED]" << RESET << "     crackHighestRound" << endl;
	ull result[tmpkeys_num];
	int count = 0;    
    for(uint tmpKey = 0x00000000U; tmpKey <= 0xFFFFFFFFU; tmpKey++)
    {
		if(tmpKey == 0xFFFFFFFFu){
			cout << BRED << "{FAILED}" << RESET << "    crackHighestRound\n\n";
    		return 0;
		}
        int score = 0;
        for(int i = 0; i < MAX_CHOSEN_PAIRS; i++)
        {
            uint cipherRight0 = getRightHalf(ciphertext0[i]);
            uint cipherLeft0 = getLeftHalf(ciphertext0[i]);
            uint cipherRight1 = getRightHalf(cipher1[i]);
            uint cipherLeft1 = getLeftHalf(cipher1[i]);
			
            uint cipherLeft = cipherLeft0 ^ cipherLeft1;
            uint fOutDiffActual = cipherLeft ^ differential;

            uint fInput0 = cipherRight0 ^ tmpKey;
            uint fInput1 = cipherRight1 ^ tmpKey;
            uint fOut0 = f(fInput0);
            uint fOut1 = f(fInput1);
            uint fOutDiffComputed = fOut0 ^ fOut1;

			if (fOutDiffActual == fOutDiffComputed) {
				score++; 
				cout << '\a';
			} else {
				break;
			}
        }

        if (score == MAX_CHOSEN_PAIRS)
        {
			if(contains(result, tmpKey, 8)){
				cout << BGREEN << "[FINISHED]" << RESET << "    crackHighestRound" << endl;
				return result;
			}
			cout << BYELLOW << "[TMP KEY]" << RESET << "  -> " << hex << tmpKey << endl;
			tmp[count] = tmpKey;
			count++;

			if (count == tmpkeys_num){
				cout << BGREEN << "[FINISHED]" << RESET << "    crackHighestRound" << endl;
				return result;
			}	
        }
    }
    cout << BRED << "{FAILED}" << RESET << "    crackHighestRound" << endl;
    return 0;
}

void decryptHighestRound(uint crackedKey, ull *cipher1)
{
    for(int i = 0; i < MAX_CHOSEN_PAIRS; i++)
    {
        uint cipherLeft0 = getRightHalf(ciphertext0[i]);
        uint cipherLeft1 = getRightHalf(cipher1[i]);
        uint cipherRight0 = f(cipherLeft0 ^ crackedKey) ^ getLeftHalf(ciphertext0[i]);
        uint cipherRight1 = f(cipherLeft1 ^ crackedKey) ^ getLeftHalf(cipher1[i]);
        ciphertext0[i] = getCombinedHalves(cipherLeft0, cipherRight0);
        cipher1[i] = getCombinedHalves(cipherLeft1, cipherRight1);
    }
}

int main(int argc, char **argv){

	uint roundStartTime;
	uint roundEndTime;
	int count;

	cout << BGREEN << "[STARTED]" << RESET << "     #====-- FEAL4 Analysis --====#\n\n";

	uint startTime = time(NULL);

	/* Round 4 K3 */
	cout << BGREEN << "[STARTED]" << RESET << "     #---- Round 4: To find K3 ----#\n";
	decryptLastOperation(ciphertext1_3);
	roundStartTime = time(NULL);
	crackHighestRound(0x02000000U, ciphertext1_3);
	roundEndTime = time(NULL);
	for(int i = 0; i < 4; i++){
		k3_candidates[i] = tmp[i];
		cout << BBLUE << "[K3 Candid]" << RESET << "   " << hex << k3_candidates[i] << "\n";
	}
	cout << BGREEN << "[FINISHED]" << RESET << "    #---- Round 4: To find K3 (" << dec << roundEndTime - roundStartTime << " sec) ----#\n\n";

	/* Round 3 K2 */
	count = 0;
	for(int i = 0; i < 4; i++){
		cout << BGREEN << "[STARTED]" << RESET << "     #---- Round 3: To find K2 ----#" << endl;
		cout << BCYAN << "[K3 Used]" << RESET << "---> " << hex << k3_candidates[i] << endl;

		reset_ciphers();
		decryptLastOperation(ciphertext1_2);
		decryptHighestRound(k3_candidates[i], ciphertext1_2);
		roundStartTime = time(NULL);
		crackHighestRound(0x02000000U, ciphertext1_2);
		roundEndTime = time(NULL);
		// Filling array with all possible K2 values
		for(int j = 0; j < 4; j++){
			k2_candidates[count] = tmp[j];
			count++;
		}
		cout << BGREEN << "[FINISHED]" << RESET << "    #==Round 3: To find K2 (" << dec << roundEndTime - roundStartTime << " sec)==#\n\n";
		reset_ciphers();
	}

	for(int a = 0; a < 16; a++){
		cout << BBLUE << "[K2 Candid]" << RESET << "   " << hex << k2_candidates[a] << "\n";
	}

    // Round 2 K1
	count = 0;

	int l = 0;
	int m = 0;
	while(l < 4){
		while(m < 16){
			if(m % 4 == 0 && m != 0){
				l++;
			}
			cout << BGREEN << "[STARTED]" << RESET << "     #---- Round 2: To find K1 ----#" << endl;
			cout << BCYAN << "[L]" << RESET << "        -> " << dec << l << endl;
			cout << BMAGENTA << "[K3]" << RESET << "       -> " << hex << k3_candidates[l] << endl;
			cout << BCYAN << "[M]" << RESET << "        -> " << dec << m << endl;
			cout << BMAGENTA << "[K2]" << RESET << "       -> " << hex << k2_candidates[m] << endl;
			reset_ciphers();
			decryptLastOperation(ciphertext1_1);
			decryptHighestRound(k3_candidates[l], ciphertext1_1); // K3
			decryptHighestRound(k2_candidates[m], ciphertext1_1); // K2

			roundStartTime = time(NULL);
			crackHighestRound(0x02000000U, ciphertext1_1);
			roundEndTime = time(NULL);
			for(int k = 0; k < 4; k++){
				k1_candidates[count] = tmp[k];
				count++;
			}
			cout << BGREEN << "[FINISHED]" << RESET << "    #==Round 2: To find K1 (" << dec << roundEndTime - roundStartTime << " sec)==#\n\n";
		
			m++;
		}
		l++;
	}

	for(int z = 0; z < 16; z++){
		cout << BBLUE << "[K1 Candid]" << RESET << "   " << hex << k1_candidates[z] << "\n";
	}

    // Round 1

	ull k0[16] = {};
	ull k4[16] = {};
	ull k5[16] = {};

	int count2 = 0;

	reset_ciphers();

	for(int i = 0; i < 16; i++){
		cout << BGREEN << "[STARTED]" << RESET << "     #---- Round 1: To find K0, K4, K5 ----#" << endl;
		decryptHighestRound(k1_candidates[i], ciphertext0);

		roundStartTime = time(NULL);

		uint crackedKey0 = 0;
		uint crackedKey4 = 0;
		uint crackedKey5 = 0;

		for (uint tmpK0 = 0; tmpK0 < 0xFFFFFFFFL; tmpK0++)
		{
			uint tmpK4 = 0;
			uint tmpK5 = 0;

			for (int z = 0; z < MAX_CHOSEN_PAIRS; z++)
			{
				uint plainLeft0 = getLeftHalf(plaintext0[z]);
				uint plainRight0 = getRightHalf(plaintext0[z]);
				uint cipherLeft0 = getLeftHalf(ciphertext0[z]);
				uint cipherRight0 = getRightHalf(ciphertext0[z]);

				uint temp = f(cipherRight0 ^ tmpK0) ^ cipherLeft0;
				if (tmpK4 == 0){
					tmpK4 = temp ^ plainLeft0;
					tmpK5 = temp ^ cipherRight0 ^ plainRight0;
				}
				else if (((temp ^ plainLeft0) != tmpK4) || ((temp ^ cipherRight0 ^ plainRight0) != tmpK5))
				{
					tmpK4 = 0;
					tmpK5 = 0;
					// break;
				}
			}
			if (tmpK4 != 0)
			{
				cout << "\a";
				k0[count2] = tmpK0;
				k4[count2] = tmpK4;
				k5[count2] = tmpK5;
				cout << BYELLOW << "[K0]" << RESET << "       "<< hex << k0[count2] << endl;
				cout << BBLUE << "[K4]" << RESET << "       "<< hex << k4[count2] << endl;
				cout << BMAGENTA << "[K5]" << RESET << "       "<< hex << k5[count2] << "\n\n";
				count2++;
			}
		}
		for(int k = 0; k < 16; k++){
			cout << BYELLOW  << "[K0]" << RESET << "       "<< hex << k0[k] << endl;
			cout << BBLUE    << "[K4]" << RESET << "       "<< hex << k4[k] << endl;
			cout << BMAGENTA << "[K5]" << RESET << "       "<< hex << k5[k] << "\n\n";
		}
		uint endTime = time(NULL);
		cout << "Total time taken = " << dec << int(endTime - startTime) << " seconds\n";
	}
    cout << BGREEN << "[FINISHED]" << RESET << " -> FEAL4 Analysis" << endl;
    return 0;
}
