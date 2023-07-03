#sudo apt install libsdl2-dev


BMPcrypt:
	g++ BMPkey.cc -lSDL2 -o BMPkey
	g++ BMPcrypt.cc -o BMPcrypt

clean:
	rm -rf BMPcrypt BMPkey
