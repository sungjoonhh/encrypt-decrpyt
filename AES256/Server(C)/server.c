#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<sys/types.h>
#include<signal.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<unistd.h>
#include<sys/wait.h>
#include <unistd.h>
#include <time.h>


#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#define MAXLINE 514

void z_handler();// 시그널 처리 함수
static char base64_table[] = {
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
	'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
	'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
	'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
	'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/', '\0'
};

static char base64_pad = '=';

unsigned char *base64_encode(const unsigned char *str, int length, int *ret_length) {
	const unsigned char *current = str;
	int i = 0;
	unsigned char *result = (unsigned char *)malloc(((length + 3 - length % 3) * 4 / 3 + 1) * sizeof(char));

	while (length > 2) { /* keep going until we have less than 24 bits */
		result[i++] = base64_table[current[0] >> 2];
		result[i++] = base64_table[((current[0] & 0x03) << 4) + (current[1] >> 4)];
		result[i++] = base64_table[((current[1] & 0x0f) << 2) + (current[2] >> 6)];
		result[i++] = base64_table[current[2] & 0x3f];

		current += 3;
		length -= 3; /* we just handle 3 octets of data */
	}

	/* now deal with the tail end of things */
	if (length != 0) {
		result[i++] = base64_table[current[0] >> 2];
		if (length > 1) {
			result[i++] = base64_table[((current[0] & 0x03) << 4) + (current[1] >> 4)];
			result[i++] = base64_table[(current[1] & 0x0f) << 2];
			result[i++] = base64_pad;
		}
		else {
			result[i++] = base64_table[(current[0] & 0x03) << 4];
			result[i++] = base64_pad;
			result[i++] = base64_pad;
		}
	}
	if (ret_length) {
		*ret_length = i;
	}
	result[i] = '\0';
	return result;
}

/* as above, but backwards. :) */
unsigned char *base64_decode(const unsigned char *str, int length, int *ret_length) {
	const unsigned char *current = str;
	int ch, i = 0, j = 0, k;
	/* this sucks for threaded environments */
	static short reverse_table[256];
	static int table_built;
	unsigned char *result;

	if (++table_built == 1) {
		char *chp;
		for (ch = 0; ch < 256; ch++) {
			chp = strchr(base64_table, ch);
			if (chp) {
				reverse_table[ch] = chp - base64_table;
			}
			else {
				reverse_table[ch] = -1;
			}
		}
	}

	result = (unsigned char *)malloc(length + 1);
	if (result == NULL) {
		return NULL;
	}

	/* run through the whole string, converting as we go */
	while ((ch = *current++) != '\0') {
		if (ch == base64_pad) break;

		/* When Base64 gets POSTed, all pluses are interpreted as spaces.
		This line changes them back.  It's not exactly the Base64 spec,
		but it is completely compatible with it (the spec says that
		spaces are invalid).  This will also save many people considerable
		headache.  - Turadg Aleahmad <turadg@wise.berkeley.edu>
		*/

		if (ch == ' ') ch = '+';

		ch = reverse_table[ch];
		if (ch < 0) continue;

		switch (i % 4) {
		case 0:
			result[j] = ch << 2;
			break;
		case 1:
			result[j++] |= ch >> 4;
			result[j] = (ch & 0x0f) << 4;
			break;
		case 2:
			result[j++] |= ch >> 2;
			result[j] = (ch & 0x03) << 6;
			break;
		case 3:
			result[j++] |= ch;
			break;
		}
		i++;
	}

	k = j;
	/* mop things up if we ended on a boundary */
	if (ch == base64_pad) {
		switch (i % 4) {
		case 0:
		case 1:
			free(result);
			return NULL;
		case 2:
			k++;
		case 3:
			result[k++] = 0;
		}
	}
	if (ret_length) {
		*ret_length = j;
	}
	result[k] = '\0';
	return result;
}

void handleErrors(void)
{
  ERR_print_errors_fp(stderr);
  abort();
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext)
{
	EVP_CIPHER_CTX *ctx;

	int len = 0;

	int ciphertext_len;

	/* Create and initialise the context */
	if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

	/* Initialise the encryption operation. IMPORTANT - ensure you use a key
	* and IV size appropriate for your cipher
	* In this example we are using 256 bit AES (i.e. a 256 bit key). The
	* IV size for *most* modes is the same as the block size. For AES this
	* is 128 bits */
	if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
		handleErrors();

	/* Provide the message to be encrypted, and obtain the encrypted output.
	* EVP_EncryptUpdate can be called multiple times if necessary
	*/
	if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
		handleErrors();
	ciphertext_len = len;

	/* Finalise the encryption. Further ciphertext bytes may be written at
	* this stage.
	*/
	if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
	ciphertext_len += len;

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return ciphertext_len;
}


int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext)
{
	EVP_CIPHER_CTX *ctx;

	int len;

	int plaintext_len;

	/* Create and initialise the context */
	if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

	/* Initialise the decryption operation. IMPORTANT - ensure you use a key
	* and IV size appropriate for your cipher
	* In this example we are using 256 bit AES (i.e. a 256 bit key). The
	* IV size for *most* modes is the same as the block size. For AES this
	* is 128 bits */
	if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
		handleErrors();

	/* Provide the message to be decrypted, and obtain the plaintext output.
	* EVP_DecryptUpdate can be called multiple times if necessary
	*/
	if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
		handleErrors();
	plaintext_len = len;

	/* Finalise the decryption. Further plaintext bytes may be written at
	* this stage.
	*/
	if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
	plaintext_len += len;

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return plaintext_len;
}


int main(int argc, char *argv[])
{

		/* A 256 bit key */
	unsigned char *key = (unsigned char *)"01234567890123456789012345678901";

	/* A 128 bit IV */
	unsigned char *iv = (unsigned char *)"0123456789012345";
  int server_sock;
  int client_sock;
  int clntlen;
  int num;
	int encoding_num = 0;
	int decoding_num = 1;
  char sendline[MAXLINE];
  char recvline[MAXLINE];
  char key_compare[MAXLINE];
  int size;
  pid_t fork_ret;
  struct sockaddr_in client_addr;
  struct sockaddr_in server_addr;
  int state;
  struct sigaction act;
  act.sa_handler = z_handler;

  unsigned char ciphertext[MAXLINE];
  unsigned char plaintext[MAXLINE];
  /* Buffer for the decrypted text */
  unsigned char decryptedtext[MAXLINE];

  int decryptedtext_len, ciphertext_len;
  int encryptedtext_len, plaintext_len;
	char* test2;
	char* test3;
  /* Initialise the library */
  ERR_load_crypto_strings();
  OpenSSL_add_all_algorithms();
  OPENSSL_config(NULL);

  if(argc!=2)
  {
    printf("Usage : %s PORT \n", argv[0]);
    exit(0);
  }
  // 소켓 생성
  if((server_sock = socket(PF_INET, SOCK_STREAM, 0)) <0)
  {
    printf("Server : can't open stream socket. \n");
    exit(0);
  }
  // 소켓 주소 구조체에 주소 세팅
  bzero((char *)&server_addr, sizeof(server_addr)); // 소켓 주소 구조체 초기화
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  server_addr.sin_port = htons(atoi(argv[1]));

  sigaction(SIGCHLD, &act, 0);

  // 소켓에 서버 주소 연결
  if(bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
  {
    printf("Server : can't bind local address.\n");
    exit(0);
  }
  printf("Server started. \nWaiting for client.. \n");
  listen(server_sock, 1);

  // 클라이언트의 연결요청 수락
  clntlen = sizeof(client_addr);
  if((client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &clntlen)) <0)
  {
    printf("Server : failed in accepting. \n");
    exit(0);
  }



  if((fork_ret = fork()) > 0)
  {
    // 부모 프로세스는 키보드 입력을 클라이언트로 송신

    while(fgets(sendline, MAXLINE, stdin)!=NULL)
    {
			sendline[strlen(sendline)] = '\0';
			size = strlen(sendline);
			printf("\n--------------  S  E  N  D  ----------------\n\n");
			printf("SEND DATA : %s\n\n",sendline);
		if(size!=0){
	  ciphertext_len = encrypt(sendline, strlen(sendline), key, iv, ciphertext);
		ciphertext[ciphertext_len] = '\0';

		printf("AES256 ( SEND DATA ) : %s \n\n",ciphertext);
		test2 = base64_encode((unsigned char *)ciphertext, ciphertext_len,&encoding_num);
		printf("BASE64ENCODING ( AES256 ( SEND DATA ) ) : %s \n\n",test2);

      if(write(client_sock, test2, strlen(test2)) == size)
      {
        printf("Error in write. \n");
      }
			//memset(sendline,0x00,MAXLINE);
			//memset(test2,0x00,MAXLINE);
			//memset(ciphertext,0x00,MAXLINE);
    	}
		}
  }
  else if(fork_ret == 0)
  {
    // 자식 프로세스는 클라이언트로부터 수신된 메시지를 화면에 출력
    while(1)
    {
			memset(recvline,0x00,MAXLINE);
      if((size = read(client_sock, recvline, MAXLINE)) < 0)
      {
        printf("Error if read. \n");
        close(client_sock);
        exit(0);
      }
			//recvline[strlen(recvline)] = '\0';
			memset(plaintext,0x00,MAXLINE);
			printf("--------------  R E C E I V E  -------------\n\n");
      printf("BASE64ENCODING ( AES256 ( RECEIVE DATA ) ) : %s\n\n", recvline); // 화면 출력
			test3 = base64_decode((unsigned char *)recvline, strlen(recvline),&decoding_num);
			printf(" AES256 ( RECEIVE DATA ) : %s\n\n", test3); // 화면 출력
			plaintext_len = decrypt(test3, decoding_num, key, iv, plaintext);
			plaintext[plaintext_len] = '\0';
      printf("RECEIVE DATA : %s\n\n", plaintext); // 화면 출력

    }
  }
  close(server_sock);
  close(client_sock);

  return 0;
}





void z_handler()
{
  int state;
  waitpid(-1, &state, WNOHANG);
  exit(0);

  return ;
}
