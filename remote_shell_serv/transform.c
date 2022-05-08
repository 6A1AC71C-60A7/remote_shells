
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

#define ROTR(x, n) ( ((x) << (n)) | ((x) >> (8 - (n))) )
#define ROTL(x, n) ( ((x) >> (n)) | ((x) << (8 - (n))) )

///TODO: Include the (de/en)crypt functions from the lib

__always_inline
static void encrypt(char* plaintext, unsigned long nbytes, unsigned long key)
{
	const unsigned char* const bkey = (unsigned char*)&key;

	for (unsigned int i = 0 ; i < nbytes ; i++)
	{
		char key_c = bkey[i & (sizeof(key) - 1)];

		plaintext[i] ^= key_c;
		plaintext[i] = ~plaintext[i];
	//	plaintext[i] = ROTR(plaintext[i], i & (sizeof(key) - 1));
		plaintext[i] += key_c;
	}
}

__always_inline
static void decrypt(char* ciphertext, unsigned long nbytes, unsigned long key)
{
	const unsigned char* const bkey = (unsigned char*)&key;

	for (unsigned int i = 0 ; i < nbytes ; i++)
	{
		char key_c = bkey[i & (sizeof(key) - 1)];

		ciphertext[i] -= key_c;
	//	ciphertext[i] = ROTL(ciphertext[i], i & (sizeof(key) - 1));
		ciphertext[i] = ~ciphertext[i];
		ciphertext[i] ^= key_c;
	}
}

#define BUFFSZ 0x1000

__always_inline
static void display_usage()
{
	fprintf(stderr, "USAGE: < -e | -d > < key >\n");
}

int main(int ac, const char* av[])
{
	if (ac != 3
	|| *av[1] != '-'
	|| (av[1][1] != 'e' && av[1][1] != 'd')
	|| av[1][2])
	{
		display_usage();
		return 1;
	}

	typedef void (*const f_t)(char*, unsigned long, unsigned long);

	const f_t f = av[1][1] == 'e' ? &encrypt : &decrypt;
	const unsigned long key = (unsigned long)strtol(av[2], NULL, 0);

	char buff[BUFFSZ] = {0};
	long nread;

	while ((nread = read(STDIN_FILENO, buff, BUFFSZ)) > 0)
	{
		f(buff, nread, key);
		write(STDOUT_FILENO, buff, nread);
	}

	return 0;
}
