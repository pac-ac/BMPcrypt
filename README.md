# BMPcrypt

BMPcrypt is a cryptographic algorithm based on AES-128 in PCBC mode. It uses the data from BMP images to encrypt and decrypt data in text files. There is also a second program to pseudo-randomly and deterministically generate such data, and save it as a BMP image using SDL2. The BMP image will act as a key for the encryption, once you encrypt or decrypt a file with the BMP image, the BMP image will be overwritten with 0's.


To compile the executables (with g++ and the SDL2 library) just do 'sudo make BMPcrypt'.
Output files will have an extra block of junk data that I was too lazy to remove, sorry.


This project is old, and was used as an educational experience, as well as just something I thought would be interesting to do. 
Don't use crypto algorithms for any serious data protection until they have been properly analyzed and tested to be secure by experts.
