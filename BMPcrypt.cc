#include <iostream>
#include <fstream>
#include <cstring>
#include "misc/input.h"
#include "misc/prng.h"
#include "aes/aes_encode.h"
#include "aes/aes_decode.h"

/*

This program reads data from BMP images to use during the 
encryption and decryption of text files.


*/

constexpr int ROUNDS128 = 10;

//block used to hold plain/ciphertext values
unsigned char block[BLOCK_VAL_E][BLOCK_VAL_E] = {
        {},
        {},
        {},
        {}
};

//initialization vector for PCBC mode
unsigned char block_PCBC[BLOCK_VAL_E][BLOCK_VAL_E] = {
        {},
        {},
        {},
        {}
};

unsigned char new_block_PCBC[BLOCK_VAL_E][BLOCK_VAL_E] = {
        {},
        {},
        {},
        {}
};

//cipherkey used to hold values from bmp key
unsigned char cipherKey[BLOCK_VAL_E][BLOCK_VAL_E] = {
        {},
        {},
        {},
        {}
};

void bmpTrans(unsigned int val, bool mode) {

	//convert to base 3
	//max val = 25, in base 3 (+100) = 321
	val = ternaryTrans(val) + 100;

	//# of times these transformations will be applied	
	unsigned int transNum = (val / 100);

	//both one and ten determine which transformation
	unsigned int tenNum = (val % 100) / 10;
	unsigned int oneNum = val % 100;

	if (!mode) {
		for (int i = 0; i < transNum; i++) {
			
			switch(tenNum) {
				case 1:
					MIX_COLUMNS_E();
					break;
				case 2:
					SHIFT_ROWS_E();
					break;
				default:
					break;
			}

			switch(oneNum) {
				case 1:
					MIX_COLUMNS_E();
					break;
				case 2:
					SHIFT_ROWS_E();
					break;
				default:
					break;
			}
		}
	} else {
		//reverse for decryption
		for (int i = 0; i < transNum; i++) {
			
			switch(oneNum) {
				case 1:
					MIX_COLUMNS_REV_D();
					break;
				case 2:
					SHIFT_ROWS_REV_D();
					break;
				default:
					break;
			}

			switch(tenNum) {
				case 1:
					MIX_COLUMNS_REV_D();
					break;
				case 2:
					SHIFT_ROWS_REV_D();
					break;
				default:
					break;
			}
		}
	}
}

void AES_128_ENCRYPT(uint64_t &bmpNum,
		std::vector<unsigned char> R,
                std::vector<unsigned char> G,
                std::vector<unsigned char> B) {
        
	memcpy(roundKey_E, cipherKey, sizeof(roundKey_E));

	//get bmpNum information
	unsigned char pixelVal = 0;
	
	switch(bmpNum % 3) {
		
		case 0:
			pixelVal = R[bmpNum % R.size()];
			break;
		case 1:
			pixelVal = G[bmpNum % G.size()];
			break;
		default:
			pixelVal = B[bmpNum % B.size()];
	}
	unsigned int bmpTriVal = pixelVal / 10;
	unsigned int bmpOne = pixelVal % 10;
			
	//decide round for transformations
	unsigned int bmpRound = bmpOne + (1 * (bmpOne == 9) );
	
        //transformation for initial round using cipherKey
        ADD_ROUND_KEY_E();

        for (int roundNum = 0; roundNum < ROUNDS128; roundNum++) {

                memcpy(oldRoundKey_E, roundKey_E, sizeof(oldRoundKey_E));

                ROT_WORD_E();
                KEY_SUB_BYTES_E();
                FIRST_XOR_KEY_E(roundNum);
                XOR_KEY_E();
		
		//xor key with BMP vals
		keyGen(bmpNum, roundKey_E, R, G, B);
                        
		switch(roundNum) {

                        case 9:
                                //transformations for final round
                                SUB_BYTES_E();
                                SHIFT_ROWS_E();
                                ADD_ROUND_KEY_E();
				
				addBmp(bmpNum, roundNum, 0, block_E, R, G, B);
                                
				if (bmpRound == ROUNDS128) {
					//extra transformations
                                	bmpTrans(bmpTriVal, 0);
				}
				
				break;
			
                        default:

                                //main transformations for 9 main rounds
                                SUB_BYTES_E();
                                SHIFT_ROWS_E();
                                MIX_COLUMNS_E();
                                ADD_ROUND_KEY_E();
					
				addBmp(bmpNum, roundNum, 0, block_E, R, G, B);
				
				if (bmpRound == roundNum) {
					//extra transformations
                                	bmpTrans(bmpTriVal, 0);
				}
				

				break;
                }
        }
}

void AES_128_DECRYPT(uint64_t &bmpNum, 
		std::vector<unsigned char> R,
                std::vector<unsigned char> G,
                std::vector<unsigned char> B) {
	
        memcpy(roundKey_E, cipherKey, sizeof(roundKey_E));
        unsigned int keyScheduleIndex = 0;
	
	//get bmpNum information
	unsigned char pixelVal = 0;

	switch(bmpNum % 3) {
		
		case 0:
			pixelVal = R[bmpNum % R.size()];
			break;
		case 1:
			pixelVal = G[bmpNum % G.size()];
			break;
		default:
			pixelVal = B[bmpNum % B.size()];
	}
	unsigned int bmpTriVal = pixelVal / 10;
	unsigned int bmpOne = pixelVal % 10;
	
	//decide round for transformations
	unsigned int bmpRound = bmpOne + (1 * (bmpOne == 9));
	

        //recreate key schedule of initial encryption to use
        //roundKeys in inverse transformations
        
	for (int keyNum = 0; keyNum < ROUNDS128 + 1; keyNum++) {

		keyScheduleIndex = keyNum * BLOCK_VAL_E;

		//recreate each individual block
		for (int i = 0; i < BLOCK_VAL_E; i++) {

                	totalKeys[0][keyScheduleIndex + i] = roundKey_E[0][i];
                	totalKeys[1][keyScheduleIndex + i] = roundKey_E[1][i];
                	totalKeys[2][keyScheduleIndex + i] = roundKey_E[2][i];
                	totalKeys[3][keyScheduleIndex + i] = roundKey_E[3][i];
		}

		if (keyNum < ROUNDS128) {
		
			memcpy(oldRoundKey_E, roundKey_E, sizeof(oldRoundKey_E));
                	
			ROT_WORD_E();
                	KEY_SUB_BYTES_E();
                	FIRST_XOR_KEY_E(keyNum);
                	XOR_KEY_E();
		
			//xor key with BMP vals
			keyGen(bmpNum, roundKey_E, R, G, B);
			
			//addBmp increments by 1 during encryption
			bmpNum++;
		}

        }
        //starting decryption with last round key
        memcpy(roundKey_D, roundKey_E, sizeof(roundKey_D));
				

	//this is the first round possibility, inverse of last round from enryption	
	if (bmpRound == ROUNDS128) {

		//extra transformations
                bmpTrans(bmpTriVal, 1);
	}
	
	addBmp(bmpNum, 0, 1, block_D, R, G, B);


	//inverse bmpRound num
	//first possible round completed at this point, 9 rounds left, 0 through 8
	bmpRound = 8 - bmpRound;

        //transformation for initial round using last roundKey starting at 40 in totalKeys
        ADD_ROUND_KEY_REV_D();
        SHIFT_ROWS_REV_D();
        SUB_BYTES_REV_D();
        
	//start of the next inverse block at 36
        unsigned int columnCount = 36;

        for (int roundNum = 0; roundNum < ROUNDS128; roundNum++) {

                for (int j = 0; j < BLOCK_VAL_D; j++) {

                        roundKey_D[0][j] = totalKeys[0][columnCount+j];
                        roundKey_D[1][j] = totalKeys[1][columnCount+j];
                        roundKey_D[2][j] = totalKeys[2][columnCount+j];
                        roundKey_D[3][j] = totalKeys[3][columnCount+j];

                }
                columnCount -= BLOCK_VAL_D;

                switch(roundNum) {

                        //every transformation done in reverse with 
                        //the appropriate roundKey used   
                        case 9:
                                //transformations for final round       
                                ADD_ROUND_KEY_REV_D();

                                break;

                        default:
				
				if (bmpRound == roundNum) {
					
					//extra transformations
                			bmpTrans(bmpTriVal, 1);
				}
                                
				//main transformations for 9 main rounds	
				addBmp(bmpNum, roundNum + 1, 1, block_D, R, G, B);
				
				ADD_ROUND_KEY_REV_D();
                                MIX_COLUMNS_REV_D();
                                SHIFT_ROWS_REV_D();
                                SUB_BYTES_REV_D();

                                break;
                }
        }
}

void blockAssign(std::vector<unsigned char> textForBlock, unsigned int textPositionStart, 
		unsigned char block_X[BLOCK_VAL_E][BLOCK_VAL_D]) {

        //assigns next 16 chars of text file to new block
        for (int row = 0; row < BLOCK_VAL_E; row++) {
                for (int col = 0; col < BLOCK_VAL_D; col++) {

                        if (textPositionStart <= textForBlock.size()) {
                                block_X[row][col] = textForBlock[textPositionStart];
                                textPositionStart++;
                        } else {
                                block_X[row][col] = 0;
                        }
                }
        }
}

void ReadBMP(char *filename, std::vector<unsigned char> &redV, std::vector<unsigned char> &greenV, std::vector<unsigned char> &blueV, 
		int *width, int *height, bool mode) {

    FILE *f;

    if (mode == 0) {
    	f = fopen(filename, "rb");
    } else {
    	f = fopen(filename, "r+b");
    }

    if (!f || f == NULL) {
    	throw "Error while opening this file.";
    }    

    unsigned char bmpInfo[54];
    
    //read from 54 byte header
    fread(bmpInfo, sizeof(unsigned char), 54, f);

    //extract image height and width from header
    int widthVal = *(int*)&bmpInfo[18];
    int heightVal = *(int*)&bmpInfo[22];

    *width = widthVal;
    *height = heightVal;

    int row_padded = (3 * (*width) + 3) & (~3);
    unsigned char *data = new unsigned char[row_padded];
    unsigned char tmp;
	
    //read data from image to use during encryption
    if (mode == 0) {
	    for (int i = 0; i < (*height); i++) {	
		
		fread(data, sizeof(unsigned char), row_padded, f);
        
		for (int j = 0; j < 3 * (*width); j += 3) {
            
	    		//Convert (B, G, R) to (R, G, B)
            		tmp = data[j];
            		data[j] = data[j+2];
            		data[j+2] = tmp;

	    		//add RGB values to respective vectors
	    		redV.push_back(data[j]); 
	    		greenV.push_back(data[j + 1]); 
	    		blueV.push_back(data[j + 2]); 
        	}
	    }

    //overwrite image with zeros after encryption	    
    } else {
	    
	    for (int i = 0; i < (*height); i++) {

                fwrite(data, sizeof(unsigned char), row_padded, f);

                for (int j = 0; j < 3 * (*width); j += 3) {

                        data[j] =   0;
                        data[j+1] = 0;
                        data[j+2] = 0;

                        redV.push_back(data[j]);
                        greenV.push_back(data[j + 1]);
                        blueV.push_back(data[j + 2]);
                }
	    }
    }

    delete[] data;
    fclose(f);    
}



int main(int argc, char* argv[]) {

	if (argc < 5) {
	
		std::cerr << "Must execute with proper args.\n\n";
	
		std::cerr << "Encrypt example: './BMPcrypt 1 image.bmp plain.txt output.txt'\n";
		std::cerr << "Decrypt example: './BMPcrypt 0 image.bmp cipher.txt output.txt'\n";
	}

	std::vector<unsigned char> redV;
	std::vector<unsigned char> greenV;
	std::vector<unsigned char> blueV;
	
	int width, height;
	char *bmpFile = argv[2];

	//attempt to read BMP file data
	try {
		ReadBMP(bmpFile, redV, greenV, blueV, &width, &height, 0);
	} catch (...) {
		std::cout << "Error while opening BMP file." << '\n';
		return 1;
	}

	const unsigned int pixelCount = width * height;

	int redE = 0;
	int greenE = 0;
	int blueE = 0;
	int emptyE = 0;

	for (int i = 0; i < pixelCount; i++) {
                
		if (redV[i] == 0) {
                	redE++;
               	}
               	if (greenV[i] == 0) {
                        greenE++;
               	}
               	if (blueV[i] == 0) {
                        blueE++;
		}
		if (redV[i] == 0 && greenV[i] == 0 && blueV[i] == 0) {
			emptyE++;
		}
        }

	unsigned int textIndex = 0;
	unsigned int textBlockCounter = 0;
	unsigned int widthIndex = 0;
	unsigned char layerPixelVal = 0;
	uint32_t layerPixelCount = 0;
        
	//starting position in BMP image
	uint64_t imagePos = redE ^ greenE ^ blueE;
	imagePos = randGen(imagePos, (emptyE % 65535) ) % pixelCount;
	
	//layers of encryption for first block to ensure all values in image are used
	unsigned int layers = (pixelCount / 50) + 1;

	//value to count to determine future number of layers
	switch (imagePos % 3) {
		case 0:
			layerPixelVal = redV[ randGen(layers, redV[imagePos]) % pixelCount];
			break;
		case 1:
			layerPixelVal = greenV[ randGen(layers, greenV[imagePos]) % pixelCount];
			break;
		case 2:
			layerPixelVal = blueV[ randGen(layers, blueV[imagePos]) % pixelCount];
			break;
		default:
			layerPixelVal = 0;
	}
	
	//ask user to encrypt or decrypt
	bool cryptMode = std::stoi(argv[1]);

	//generate initial cipherKey and IV
	keyInit(imagePos, cipherKey, redV, greenV, blueV);
	keyInit(imagePos, block_PCBC, redV, greenV, blueV);
	

	if (cryptMode) {
		
		//***********************************************************************
        	//ENCRYPTION    
		
		char *plainFile = argv[3];
		char *outputFile = argv[4];

		textIndex = 0;
		widthIndex = 0;
		
        	//get plaintext file data for encryption
        	std::ifstream inPlain(plainFile, std::ios::in | std::ios::binary);
        	std::vector<unsigned char> plainText((std::istreambuf_iterator<char>(inPlain)),
                        std::istreambuf_iterator<char>());

        	if (!inPlain) {
                	std::cerr << "\nCannot open file for encryption. (File likely does not exist.)" << '\n';
                	return 1;
        	}

        	inPlain.close();

        	const int plainFileSize = (plainText.size() / HEX_VAL_E) + 1;
        	std::cout << "Blocks in file: " << plainFileSize << '\n';
		
        	std::cout << "\nEncrypting...\n" << '\n';
        	std::ofstream outEncrypt;

		int textBlockCounter = 0;



		for (int textBlock = 0; textBlock < plainFileSize; textBlock++) {

                	//assign next 16 characters of plaintext data to block
                	blockAssign(plainText, textIndex, block_E);
			
			//save plaintext
			memcpy(new_block_PCBC, block_E, sizeof(new_block_PCBC));
			
			//xor plaintext by previous (ciphertext ^ plaintext) block or by IV
			add_PCBC(block_E, block_PCBC);


			//set to zero if more blocks than rows of pixels
			//adds different # of layers of encryption for very large files
			if (textBlockCounter > height) {
				textBlockCounter = 0;
			}
			
			//get pixel data for layers
			for (widthIndex = (width*textBlockCounter); widthIndex < (width*(textBlockCounter+1)); widthIndex++) {
                		if (redV[widthIndex] == layerPixelVal) {
                			layerPixelCount++;
               			}
                		if (greenV[widthIndex] == layerPixelVal) {
                			layerPixelCount++;
               			}
                		if (blueV[widthIndex] == layerPixelVal) {
                			layerPixelCount++;
               			}
			}
			textBlockCounter++;
			
						
			
			//encrypt block with layers of aes
			for (int e = 0; e < layers; e++) {
					
				AES_128_ENCRYPT(imagePos, redV, greenV, blueV);
			}

			
			
			//save (ciphertext ^ plaintext) for next block
			add_PCBC(new_block_PCBC, block_E);
			memcpy(block_PCBC, new_block_PCBC, sizeof(block_PCBC));

			//create/write file containing encrypted message
                	outEncrypt.open(outputFile, std::ios::out | std::ios::binary | std::ios::app);
                	if (!outEncrypt) {
                        	std::cerr << "Cannot write/create ciphertext file." << '\n';
                        	return 1;
                	}
                	//append to encrypted file
			outEncrypt.write((char*)&block_E[0][0], HEX_VAL_E);
                	outEncrypt.close();
                
                	textIndex += HEX_VAL_E;

			//reset layers when all values have been used after first encryption loop
			layers = (layerPixelCount % HEX_VAL_E) + 1;
        	}

	} else {

		//***********************************************************************
        	//DECRYPTION

		char *cipherFile = argv[3];
		char *outputFile = argv[4];
		
		textIndex = 0;
		widthIndex = 0;

        	//get ciphertext file data for decryption       
        	std::ifstream outPlain(cipherFile, std::ios::in | std::ios::binary);
        	std::vector<unsigned char> cipherText((std::istreambuf_iterator<char>(outPlain)),
                        std::istreambuf_iterator<char>());

        	if (!outPlain) {
                	std::cerr << "\nCannot open file for encryption. (File likely does not exist.)" << '\n';
			return 1;
        	}

		//delete[] cipherFile;
        	outPlain.close();

        	const int cipherFileSize = (cipherText.size() / HEX_VAL_E) + 1;
        	std::cout << "Blocks in file: " << cipherFileSize << '\n';

        	std::cout << "\nDecrypting...\n" << '\n';
        	std::ofstream outDecrypt;

		uint64_t tempImagePos = imagePos;

		for (int cipherTextBlock = 0; cipherTextBlock < cipherFileSize; cipherTextBlock++) {	
			
			//assign next 16 characters of ciphertext data to block
                	blockAssign(cipherText, textIndex, block_D);

			
			//save ciphertext before decryption	
			memcpy(new_block_PCBC, block_D, sizeof(new_block_PCBC));
			
			
			//set to zero if more blocks than rows of pixels
			if (textBlockCounter > height) {
				textBlockCounter = 0;
			}

			//get pixel data for layers
			for (widthIndex = (width*textBlockCounter); widthIndex < (width*(textBlockCounter+1)); widthIndex++) {
                		if (redV[widthIndex] == layerPixelVal) {
                			layerPixelCount++;
               			}
                		if (greenV[widthIndex] == layerPixelVal) {
                			layerPixelCount++;
               			}
                		if (blueV[widthIndex] == layerPixelVal) {
                			layerPixelCount++;
               			}
			}
			textBlockCounter++;
			


			//decrypt layers of aes for original block	
			for (int d = 0; d < layers; d++) {
			
				//determine the appropriate values to pass per layer
				//imagePos increments 50 each layer	
				tempImagePos = imagePos + (50 * ( (layers - 1) - d));

				AES_128_DECRYPT(tempImagePos, redV, greenV, blueV);	
                	}
			//set orginal variable to current value
			imagePos += 50 * layers;
		

			
			//xor to get plaintext
			add_PCBC(block_D, block_PCBC);

			//xor plaintext by ciphertext
			add_PCBC(new_block_PCBC, block_D);

			//save data for next block
			memcpy(block_PCBC, new_block_PCBC, sizeof(block_PCBC));
			
			
			//create/write file containing encrypted message
                	outDecrypt.open(outputFile, std::ios::out | std::ios::binary | std::ios::app);
                	if (!outDecrypt) {
                        	std::cerr << "Cannot write/create plaintext file." << '\n';
                        	return 1;
                	}
                	//append to decrypted file
                	outDecrypt.write((char*)&block_D[0][0], HEX_VAL_D);
                	outDecrypt.close();
                	
                	textIndex += HEX_VAL_D;
			
			//reset layers when all values have been used after first decryption loop
			layers = (layerPixelCount % HEX_VAL_D) + 1;
        	}
	}

	//overwrite image with zeros
	ReadBMP(bmpFile, redV, greenV, blueV, &width, &height, 1);
	ReadBMP(bmpFile, redV, greenV, blueV, &width, &height, 1);

	std::cout << "\nFinished." << '\n';

	return 0;
}
