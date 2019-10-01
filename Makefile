CC=g++
CFLAGS=-Wall -Werror
LIBS=-lcrypto
all: encode decode
encode: main_encode.o encodeAllFile.o
	$(CC) $(CFLAGS) $? -o $@ $(LIBS)
decode: main_decode.o decodeAllFile.o
	$(CC) $(CFLAGS) $? -o $@ $(LIBS)
.cpp.o:
	$(CC) $(CFLAGS) -c $*.cpp
clean:
	rm -rf *.o encode decode *_decode.* *encode.*
