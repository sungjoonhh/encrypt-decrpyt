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
#define MAXLINE 512

void z_handler();// 시그널 처리 함수
unsigned long long power(unsigned long long a, unsigned long long b, unsigned long long mod);

char *escapechar = "exit"; // 종료 문자열

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




int main(int argc, char *argv[])
{
  int server_sock;
  int client_sock;
  int clntlen;
  int num;
  char sendline[MAXLINE];
  char recvline[MAXLINE];
  char key_compare[MAXLINE];
  char *sendline123;
  int size;
	int encoding_size=0;
  pid_t fork_ret;
  struct sockaddr_in client_addr;
  struct sockaddr_in server_addr;
  int state;
  struct sigaction act;
  act.sa_handler = z_handler;
	unsigned long long random_prime,random_integer,myPublic_key,your_Public_key,myPrivacy_key,last_key,your_lastKey;
	char your_base64_lastKey[MAXLINE];
	char compare_key[MAXLINE];
	char *compare_key2;
  char* filename ="password.txt";
  FILE *fp;
  int mode = R_OK | W_OK;

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







	//여기서 diffie_hellman 알고리즘 적용

    if(access(filename,mode)!=0){
			srand(time(NULL));
		myPrivacy_key = rand()%100;
    //소수값인 p를 받아 온다.
    read(client_sock, recvline, MAXLINE);
    random_prime = atoll(recvline);		//atoll : (char[] -> int)
    printf("your prime : %lld\n\n",random_prime);

    //정수값인 g를 받아 온다.
    memset(recvline,0,sizeof(recvline));
    read(client_sock, recvline, MAXLINE);
    random_integer = atoll(recvline);
    printf("your integer : %lld\n\n",random_integer);

    myPublic_key = power(random_integer,myPrivacy_key,random_prime);
    printf("myPrivacy_key is %lld, my Public_keyis %lld\n",myPrivacy_key,myPublic_key );
    //나의 공개키를 보낸다.
	   sprintf(sendline,"%lld",myPublic_key);
     size = strlen(sendline);
    write(client_sock,sendline,strlen(sendline));
    //memset(sendline,0,MAXLINE);

    //상대방의 공개키를 받아 온다.
    memset(recvline,0,sizeof(recvline));
    read(client_sock, recvline, MAXLINE);
    your_Public_key = atoll(recvline);
    printf("your publickey : %lld\n\n",your_Public_key);
    last_key = power(your_Public_key,myPrivacy_key,random_prime);
    printf("최종: %lld\n",last_key);

    fp = fopen(filename,"a");
    fprintf(fp,"%lld",last_key);
    fclose(fp);
    }
    else
    {
      printf("키 파일 이미 존재 \n");
      printf("키를 기다린다\n");
			memset(recvline,0,sizeof(recvline));
      read(client_sock, recvline, MAXLINE);
			memcpy(your_base64_lastKey,recvline,sizeof(recvline));
      //your_base64_lastKey = atoll(recvline);

      printf("키를 받았으며 비교한다\n");
      fp = fopen(filename,"r");
      fgets(key_compare,MAXLINE,fp);
      last_key = atoll(key_compare);
			//base64로 전송온다. 그래서 lld 가 아닌 %s로 받아와야 한다.
      printf("텍스트에 저장된 값 : %lld, 받아온 키 값: %s \n",last_key,your_base64_lastKey);
			sprintf(compare_key,"%lld",last_key);
			compare_key2 = base64_encode((unsigned char *)compare_key, strlen(compare_key), &encoding_size);
			printf("디코딩된 키값 : %s\n\n",compare_key);

      if(strcmp(compare_key2,your_base64_lastKey)){
				printf("%d\n\n",strcmp(compare_key2,your_base64_lastKey));
        printf("키 값이 다르다\n");
				printf("나의 키는 %s, 너의 키는 %s \n",compare_key2,your_base64_lastKey);
        printf("---------연결 종료-------------\n");

      }
      else{
        printf("키 값이 같다\n");
				printf("%d\n\n",strcmp(compare_key2,your_base64_lastKey));
				printf("나의 키는 %s, 너의 키는 %s \n",compare_key2,your_base64_lastKey);
      }
      fclose(fp);
    }













  if((fork_ret = fork()) > 0)
  {
    // 부모 프로세스는 키보드 입력을 클라이언트로 송신
    while(fgets(sendline, MAXLINE, stdin)!=NULL)
    {
      size = strlen(sendline);
      if(write(client_sock, sendline, strlen(sendline)) != size)
      {
        printf("Error in write. \n");
      }
      if(strstr(sendline, escapechar) != NULL) // 종료 문자열 입력시 처리
      {
        printf("Good bye.\n");
        close(client_sock);
        while(1);    //자식프로세서가 죽을때까지 블로킹
      }
    }
  }
  else if(fork_ret == 0)
  {
    // 자식 프로세스는 클라이언트로부터 수신된 메시지를 화면에 출력
    while(1)
    {
      if((size = read(client_sock, recvline, MAXLINE)) < 0)
      {
        printf("Error if read. \n");
        close(client_sock);
        exit(0);
      }
      recvline[size] = '\0';
      if(strstr(recvline, escapechar) != NULL) // 종료 문자열 입력시 처리
      {
        write(client_sock, escapechar, strlen(escapechar));
        break;
      }
      printf("%s\n", recvline); // 화면 출력
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
//암호화시 필요한 power 함수
unsigned long long power(unsigned long long a, unsigned long long b, unsigned long long mod)
{
	unsigned long long t;
	if (b == 1)
		return a;
	t = power(a, b / 2, mod);
	if (b % 2 == 0)
		return (t*t) % mod;
	else
		return (((t*t) % mod)*a) % mod;
}
