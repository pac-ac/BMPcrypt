#include <iostream>

/*
 * Functions and variables named with '_D' to denote orgin from decryption header.
*/

constexpr unsigned char TOTAL_KEY_COL_D = 44;
constexpr unsigned char HEX_VAL_D = 16;
constexpr unsigned char RCON_COL_D = 10;
constexpr unsigned char BLOCK_VAL_D = 4;


//reverse s_box for decryption
constexpr unsigned char s_box_rev_D[HEX_VAL_D][HEX_VAL_D] = {
	{0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb},
	{0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb},
	{0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e},
	{0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25},
	{0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92},
	{0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84},
	{0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06},
	{0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b},
	{0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73},
	{0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e},
	{0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b},
	{0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4},
	{0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f},
	{0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef},
	{0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61},
	{0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d}
	};

//constant for producing round keys
constexpr unsigned char rcon_D[BLOCK_VAL_D][RCON_COL_D] = {
	{0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36},
	
	{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
};


//contains ciphertext and encrypted message
unsigned char block_D[BLOCK_VAL_D][BLOCK_VAL_D] = {
	{},
	{},
	{},
	{}
};

//original cipher key
unsigned char cipherKey_D[BLOCK_VAL_D][BLOCK_VAL_D] = {
	{},
	{},
	{},
	{}
};

//contains current round key for decryption
unsigned char roundKey_D[BLOCK_VAL_D][BLOCK_VAL_D] = {
	{},
	{},
	{},
	{}
};


unsigned char totalKeys[BLOCK_VAL_D][TOTAL_KEY_COL_D] = {
	{},
	{},
	{},
	{}
};

//contains previous round key to produce new one
unsigned char oldRoundKey_D[BLOCK_VAL_D][BLOCK_VAL_D] = {
	{},
	{},
	{},
	{}
};



void keyAssign_D(bool mode) {
	
	if (mode) {
		for (int i = 0; i < BLOCK_VAL_D; i++) {
			for (int j = 0; j < BLOCK_VAL_D; j++) {
				roundKey_D[i][j] = cipherKey_D[i][j];
			}
		}
	
	} else {
		for (int i = 0; i < BLOCK_VAL_D; i++) {
			for (int j = 0; j < BLOCK_VAL_D; j++) {
				oldRoundKey_D[i][j] = roundKey_D[i][j];
			}
		
		}
	}

}


//***************************************************************

			//SUB_BYTES TRANSFORMATION



void SUB_BYTES_REV_D() {

        unsigned char decimal = 0;

        //s_box row number
        unsigned char hexQuo = 0;

        //s_box column number
        unsigned char hexRem = 0;

        for (int col = 0; col < BLOCK_VAL_D; col++) {
                for (int row = 0; row < BLOCK_VAL_D; row++) {

                        decimal = block_D[col][row];
                        hexRem = decimal % HEX_VAL_D;
                        hexQuo = decimal / HEX_VAL_D;

                        block_D[col][row] = s_box_rev_D[hexQuo][hexRem];

                }
        }
}



//***************************************************************

			//SHIFT_ROWS TRANSFORMATION

void SHIFT_ROWS_REV_D() {
	
	unsigned char temp_val0 = 0;
	unsigned char temp_val1 = 0;
	unsigned char temp_val2 = 0;
	
	//second row

	temp_val0 = block_D[1][3];     // 1 2 3 4 <-- initial state
	
	block_D[1][3] = block_D[1][2]; // 1 2 3 3
	block_D[1][2] = block_D[1][1]; // 1 2 2 3
	block_D[1][1] = block_D[1][0]; // 1 1 2 3
	block_D[1][0] = temp_val0;     //(4)1 2 3 <-- 4th value in row
		
	//third row

	temp_val0 = block_D[2][3];     // 1 2 3 4 <-- initial state
	temp_val1 = block_D[2][2];
	
	block_D[2][3] = block_D[2][1]; // 1 2 3 2
	block_D[2][2] = block_D[2][0]; // 1 2 1 2
	block_D[2][1] = temp_val0;     // 1(4)1 2 <-- 4th value in row
	block_D[2][0] = temp_val1;     //(3)4 1 2 <-- 3rd value in row

	//fourth row

	temp_val0 = block_D[3][3];     // 1 2 3 4 <-- initial state
	temp_val1 = block_D[3][2];
	temp_val2 = block_D[3][1];
	
	block_D[3][3] = block_D[3][0]; // 1 2 3 1
	block_D[3][2] = temp_val0;     // 1 2(4)1 <-- 4th value in row
	block_D[3][1] = temp_val1;     // 1(3)4 1 <-- 3rd value in row
	block_D[3][0] = temp_val2;     //(2)3 4 1 <-- 2nd value in row

}

//***************************************************************
		
		//MIX_COLUMNS TRANSFORMATION
		
void MIX_COLUMNS_REV_D() {
        
	constexpr unsigned char fixedMatrix[BLOCK_VAL_D][BLOCK_VAL_D] = {
                {0x0e, 0x0b, 0x0d, 0x09},
                {0x09, 0x0e, 0x0b, 0x0d},
                {0x0d, 0x09, 0x0e, 0x0b},
                {0x0b, 0x0d, 0x09, 0x0e}
        };

        unsigned int xArr[BLOCK_VAL_D];
        unsigned int xBlock[BLOCK_VAL_D];
	bool bitCheck = 0;

	unsigned int matrixMultiply = 0;
	unsigned int hexCheck = 0;
	unsigned int result = 0;


	for (int col = 0; col < BLOCK_VAL_D; col++) {
		
		for (int row = 0; row < BLOCK_VAL_D; row++) {
		
			for (int i = 0; i < BLOCK_VAL_D; i++) {
				
				//iterate through all 4 rows of fixedMatrix
				//for every 1 column in block_D
				matrixMultiply = fixedMatrix[row][i];
				hexCheck = block_D[i][col];

				//reset xor value
				result = 0;

				//functional finite field multiplication in GF(2^8)
				while (matrixMultiply != 0 && hexCheck != 0) {
					
					result ^= (matrixMultiply*(hexCheck & 1));
					
					bitCheck = matrixMultiply & 0x80;
					matrixMultiply = (matrixMultiply << 1) ^ (0x11b * (bitCheck % 0x80));
					hexCheck >>= 1;

				}
				xArr[i] = result;
			}
			//xor each result to find final decrypted byte
			xBlock[row] = xArr[0] ^ xArr[1] ^ xArr[2] ^ xArr[3];
		}
		//assign decrypted bytes to each column
		block_D[0][col] = xBlock[0];
		block_D[1][col] = xBlock[1];
		block_D[2][col] = xBlock[2];
		block_D[3][col] = xBlock[3];
	}
}

//***************************************************************

			//ADD_ROUND_KEY

void ADD_ROUND_KEY_REV_D() {
	
	for (int col = 0; col < BLOCK_VAL_D; col++) {
		for (int row = 0; row < BLOCK_VAL_D; row++) {
			
			//xor block value by corresponding roundKey value
			block_D[col][row] ^= roundKey_D[col][row];
		}
	}
}

//***************************************************************

		//KEY SCHEDULE TRANSFORMATIONS


void ROT_WORD_D() {
	
	unsigned char temp_val = oldRoundKey_D[0][3];
					        //rot word
	roundKey_D[0][0] = oldRoundKey_D[1][3]; //1 -> 2
	roundKey_D[1][0] = oldRoundKey_D[2][3]; //2 -> 3
	roundKey_D[2][0] = oldRoundKey_D[3][3];	//3 -> 4
	roundKey_D[3][0] = temp_val;		//4 -> 1

}



void KEY_SUB_BYTES_D() {

        unsigned char decimal = 0;

        //s_box row number
        unsigned char hexQuo = 0;

        //s_box column number
        unsigned char hexRem = 0;

        for (int row = 0; row < BLOCK_VAL_D; row++) {

                decimal = roundKey_D[row][0];
                hexRem = decimal % HEX_VAL_D;
                hexQuo = decimal / HEX_VAL_D;

                roundKey_D[row][0] = s_box_rev_D[hexQuo][hexRem];

        }
}



void FIRST_XOR_KEY_D(int index) {

	//xor by round constant and column 4 positions previous
	roundKey_D[0][0] ^= rcon_D[0][index] ^ oldRoundKey_D[0][0];
	roundKey_D[1][0] ^= rcon_D[1][index] ^ oldRoundKey_D[1][0];
	roundKey_D[2][0] ^= rcon_D[2][index] ^ oldRoundKey_D[2][0];
	roundKey_D[3][0] ^= rcon_D[3][index] ^ oldRoundKey_D[3][0];

}



void XOR_KEY_D() {

	//new coloumn = xor previous column and column 4 positions previous (previous to current)
	for (int i = 1; i < BLOCK_VAL_D; i++) {
		roundKey_D[0][i] = roundKey_D[0][i - 1] ^ oldRoundKey_D[0][i];
		roundKey_D[1][i] = roundKey_D[1][i - 1] ^ oldRoundKey_D[1][i];
		roundKey_D[2][i] = roundKey_D[2][i - 1] ^ oldRoundKey_D[2][i];
		roundKey_D[3][i] = roundKey_D[3][i - 1] ^ oldRoundKey_D[3][i];
	}
}



//***************************************************************
