all:
	gcc -g -Wall ssl.c test.c -o test -lcrypto -lssl
clean:
	rm -rf *.dSYM test
