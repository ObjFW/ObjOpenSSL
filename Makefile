all:
	objfw-compile --lib 0.0 -o objopenssl *.m -lssl -lcrypto -lz -g -Wall
