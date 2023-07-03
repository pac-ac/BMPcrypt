# BMPcrypt

BMPcrypt is a cryptographic algorithm based on AES-128 in PCBC mode. It uses the data from BMP images to encrypt and decrypt data in text files. There is also a second program to pseudo-randomly and deterministically generate such data, and save it as a BMP image using SDL2. The BMP image will act as a key for the encrpytion, once you encrypt or decrypt a file with the BMP image, the BMP image will be overwritten with 0's.
