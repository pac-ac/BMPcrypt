#include <iostream>

/*
 * Functions and variables named with '_E' to denote orgin from encryption header.
*/

constexpr unsigned char HEX_VAL_E = 16;
constexpr unsigned char BLOCK_VAL_E = 4;

//table used for SUB_BYTES transformation
constexpr unsigned char s_box_E[HEX_VAL_E][HEX_VAL_E] = {
	{0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
	{0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
	{0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
	{0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
	{0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
	{0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
	{0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
	{0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
	{0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
	{0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
	{0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
	{0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
	{0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
	{0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
	{0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
	{0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}
	};


//constant for producing round keys
constexpr unsigned char rcon_E[BLOCK_VAL_E][10] = {
	{0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36},
	
	{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
};


//contains plaintext and encrypted message
unsigned char block_E[BLOCK_VAL_E][BLOCK_VAL_E] = {
	{},
	{},
	{},
	{}
};

//original cipher key
unsigned char cipherKey_E[BLOCK_VAL_E][BLOCK_VAL_E] = {
	{},
	{},
	{},
	{}
};

//contains current round key for encryption
unsigned char roundKey_E[BLOCK_VAL_E][BLOCK_VAL_E] = {
	{},
	{},
	{},
	{}
};

//contains previous round key to produce new one
unsigned char oldRoundKey_E[BLOCK_VAL_E][BLOCK_VAL_E] = {
	{},
	{},
	{},
	{}
};



void keyAssign_E(bool mode) {
	
	if (mode) {
		for (int i = 0; i < BLOCK_VAL_E; i++) {
			for (int j = 0; j < BLOCK_VAL_E; j++) {
				roundKey_E[i][j] = cipherKey_E[i][j];
			}
		}
	
	} else {
		for (int i = 0; i < BLOCK_VAL_E; i++) {
			for (int j = 0; j < BLOCK_VAL_E; j++) {
				oldRoundKey_E[i][j] = roundKey_E[i][j];
			}	
		}
	}
}


//***************************************************************

			//SUB_BYTES TRANSFORMATION

void SUB_BYTES_E() {

	unsigned char decimal = 0;
	
	//s_box row number
	unsigned char hexQuo = 0;
	
	//s_box column number
	unsigned char hexRem = 0;

	for (int col = 0; col < BLOCK_VAL_E; col++) {
		for (int row = 0; row < BLOCK_VAL_E; row++) {
			
			decimal = block_E[col][row];
			hexRem = decimal % HEX_VAL_E;
			hexQuo = decimal / HEX_VAL_E;

			block_E[col][row] = s_box_E[hexQuo][hexRem];
		
		}
	}
}



//***************************************************************

			//SHIFT_ROWS TRANSFORMATION

void SHIFT_ROWS_E() {
	
	unsigned char temp_val0 = 0;
	unsigned char temp_val1 = 0;
	unsigned char temp_val2 = 0;
	
	//second row

	temp_val0 = block_E[1][0];   // 1 2 3 4 <-- initial state
	
	block_E[1][0] = block_E[1][1]; // 2 2 3 4
	block_E[1][1] = block_E[1][2]; // 2 3 3 4
	block_E[1][2] = block_E[1][3]; // 2 3 4 4
	block_E[1][3] = temp_val0;   // 2 3 4(1)<-- 1st value in row
		
	//third row

	temp_val0 = block_E[2][0];   // 1 2 3 4 <-- initial state
	temp_val1 = block_E[2][1];
	
	block_E[2][0] = block_E[2][2]; // 3 2 3 4
	block_E[2][1] = block_E[2][3]; // 3 4 3 4
	block_E[2][2] = temp_val0;   // 3 4(1)4 <-- 1st value in row
	block_E[2][3] = temp_val1;   // 3 4 1(2)<-- 2nd value in row

	//fourth row

	temp_val0 = block_E[3][0];   // 1 2 3 4 <-- initial state
	temp_val1 = block_E[3][1];
	temp_val2 = block_E[3][2];
	
	block_E[3][0] = block_E[3][3]; // 4 2 3 4
	block_E[3][1] = temp_val0;   // 4(1)3 4 <-- 1st value in row
	block_E[3][2] = temp_val1;   // 4 1(2)4 <-- 2nd value in row
	block_E[3][3] = temp_val2;   // 4 1 2(3)<-- 3rd value in row

}

//***************************************************************
		
		//MIX_COLUMNS TRANSFORMATION
		
void MIX_COLUMNS_E() {
	
	constexpr unsigned char fixedMatrix[BLOCK_VAL_E][BLOCK_VAL_E] = {
		{0x02, 0x03, 0x01, 0x01},
		{0x01, 0x02, 0x03, 0x01},
		{0x01, 0x01, 0x02, 0x03},
		{0x03, 0x01, 0x01, 0x02}
	};

	unsigned int xArr[BLOCK_VAL_E];
	unsigned int xBlock[BLOCK_VAL_E];
	bool threeCheck = 0;
	bool bitCheck = 0;

	for (int col = 0; col < BLOCK_VAL_E; col++ ) {
		
		//each iteration of col is a new column to calculate

		for (int i = 0; i < BLOCK_VAL_E; i++) {
			for (int row = 0; row < BLOCK_VAL_E; row++) {
			
				//fixedMatrix != 0x03 -> !threeCheck
				threeCheck = BLOCK_VAL_E % fixedMatrix[i][row];

				//since we only have to multiply by 2 and 3, a full implementation of multiplication in GF(2^8) 
				//is not needed here, though it will be used in the inverse function (aes_decode.h -> MIX_COLUMNS_REV_D)

				//multiplication | x * 1 = x | x * 2 = 2x | x * 3 = 2x ^ x
				xArr[row] = (block_E[row][col] * (fixedMatrix[i][row] - threeCheck)) ^ (block_E[row][col] * threeCheck);	
			}

			xBlock[i] = xArr[0] ^ xArr[1] ^ xArr[2] ^ xArr[3];
			bitCheck =  (xBlock[i] >> 8) & 1; //xBlock <= 8 bits -> !bitCheck -> xBlock = final value
						    	  //if (bitCheck) xor by irreducible polynomial in GF(2^8)
						    	  //(x^8 + x^4 + x^3 + x + 1)
			xBlock[i] ^= (0x11b * bitCheck);  //final value
		}
	
	//assign column values
	block_E[0][col] = xBlock[0];
	block_E[1][col] = xBlock[1];
	block_E[2][col] = xBlock[2];
	block_E[3][col] = xBlock[3];

	}
}

//***************************************************************

			//ADD_ROUND_KEY

void ADD_ROUND_KEY_E() {
	
	for (int col = 0; col < BLOCK_VAL_E; col++) {
		for (int row = 0; row < BLOCK_VAL_E; row++) {
			
			//xor block value by corresponding roundKey value
			block_E[col][row] ^= roundKey_E[col][row];
		}
	}
}

//***************************************************************

		//KEY SCHEDULE TRANSFORMATIONS


void ROT_WORD_E() {
	
	unsigned char temp_val = oldRoundKey_E[0][3];
					        //rot word
	roundKey_E[0][0] = oldRoundKey_E[1][3]; //1 -> 2
	roundKey_E[1][0] = oldRoundKey_E[2][3]; //2 -> 3
	roundKey_E[2][0] = oldRoundKey_E[3][3];	//3 -> 4
	roundKey_E[3][0] = temp_val;		//4 -> 1

}



void KEY_SUB_BYTES_E() {

	unsigned char decimal = 0;
	
	//s_box row number
	unsigned char hexQuo = 0;
	
	//s_box column number
	unsigned char hexRem = 0;

	for (int row = 0; row < BLOCK_VAL_E; row++) {
			
		decimal = roundKey_E[row][0];
		hexRem = decimal % HEX_VAL_E;
		hexQuo = decimal / HEX_VAL_E;

		roundKey_E[row][0] = s_box_E[hexQuo][hexRem];
	
	}
}



void FIRST_XOR_KEY_E(int index) {

	//xor by round constant and column 4 positions previous
	roundKey_E[0][0] ^= rcon_E[0][index] ^ oldRoundKey_E[0][0];
	roundKey_E[1][0] ^= rcon_E[1][index] ^ oldRoundKey_E[1][0];
	roundKey_E[2][0] ^= rcon_E[2][index] ^ oldRoundKey_E[2][0];
	roundKey_E[3][0] ^= rcon_E[3][index] ^ oldRoundKey_E[3][0];

}



void XOR_KEY_E() {

	//new coloumn = xor previous column and column 4 positions previous (previous to current)
	for (int i = 1; i < BLOCK_VAL_E; i++) {
		roundKey_E[0][i] = roundKey_E[0][i - 1] ^ oldRoundKey_E[0][i];
		roundKey_E[1][i] = roundKey_E[1][i - 1] ^ oldRoundKey_E[1][i];
		roundKey_E[2][i] = roundKey_E[2][i - 1] ^ oldRoundKey_E[2][i];
		roundKey_E[3][i] = roundKey_E[3][i - 1] ^ oldRoundKey_E[3][i];
	}
}



//***************************************************************
