#include <iostream>
#include <string>
#include <cstdint>

/*
 
This file includes functions to take in user input
for both programs.


When organizing this repo I ended up just using
a lot of command line arguments instead so there are 
now quite a few functions here that are just useless.


*/

unsigned int dimensionIn(std::string outMessage) {

	unsigned int sizeNum;

        std::cout << "Enter value for " << outMessage << ": ";
        std::cin >> sizeNum;

        while (sizeNum < 144 || std::cin.fail() || std::isdigit(!sizeNum)) {
                std::cin.clear();
                std::cin.ignore(256, '\n');
                std::cout << "Invalid option (less than 144): ";
                std::cin >> sizeNum;
        }

	return sizeNum;
}

uint16_t iterNumIn() {

	uint16_t iterNum;
	
	std::cout << "Generate extra pixels in range of unint16_t: ";
	std::cin >> iterNum;

	while (iterNum < 1 || std::cin.fail()) {
		std::cin.clear();
		std::cin.ignore(256, '\n');
		std::cout << "Invalid option (outside of range 1 to 2^32 - 1): ";
		std::cin >> iterNum;
	}

	return iterNum;
}

uint64_t seedIn(std::string outMessage) {
	
	uint64_t seedType;

	std::cout << "\nEnter seed number for " << outMessage << " value: ";
	std::cin >> seedType;

	while (seedType < 1 || std::isdigit(!seedType) || std::cin.fail()) {
		std::cin.clear();
		std::cin.ignore(256, '\n');
		std::cout << "Must enter valid # in range of uint64_t: ";
		std::cin >> seedType;
	}

	return seedType;
}

uint16_t iterateIn() {
	
	uint16_t iterateNum;

	std::cout << "Enter number of iterations for this value: ";
	std::cin >> iterateNum;
		
	while (iterateNum < 1 || iterateNum > 65535 || std::cin.fail()) {
		std::cin.clear();
		std::cin.ignore(256, '\n');
		std::cout << "Must enter valid # in range of uint16_t: ";
		std::cin >> iterateNum;
	}

	return iterateNum;
}

std::string fileIn() {

	std::string file;
	std::cout << "Enter BMP file name: ";
	getline(std::cin, file);

	return file;
}


int cryptIn() {
	
	int cryptNum;

	std::cout << "Encrypt message(0) or decrypt message(1): ";
	std::cin >> cryptNum;

	while (cryptNum > 1 || cryptNum < 0 || std::cin.fail()) {
		std::cin.clear();
		std::cin.ignore(256, '\n');
		std::cout << "Invalid option (not 0 or 1): ";
		std::cin >> cryptNum;
	}

	return cryptNum;
}
