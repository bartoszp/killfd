#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <stddef.h>
#include <stdarg.h>

#include <sys/user.h>
#include <sys/syscall.h>

#define VMA_PERM_READ 1
#define VMA_PERM_EXECUTE 2

#define MAX_LINE_WIDTH 512

#ifdef __i386__
#define WORD_BYTES 4
unsigned char magic[] = {0xcd, 0x80};

#elif defined(__x86_64__)
#define WORD_BYTES 8
unsigned char magic[] = {0x0f, 0x05};
#endif

int flag_verbose = 0;


void verbose(char *fmt, ...) {
	va_list ap;

	va_start(ap, fmt);

	if (flag_verbose)
		vfprintf(stderr, fmt, ap);

	va_end(ap);
}

void error(int exit_code, char *fmt, ...) {
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);

	exit(exit_code);
}

unsigned char *find_syscall(int pid) {
	
	unsigned char *t;
	int a, fd, idx, i, seg, j;
	long long start, stop;
	char perm[5];
	int permissions;
	char line[MAX_LINE_WIDTH];
	long long peek_data;
	char filename[32];


	unsigned char data[2][WORD_BYTES];

	memset(data[0], 0, WORD_BYTES);
	memset(data[1], 0, WORD_BYTES);


	snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
	verbose("Opening process's maps file: %s\n", filename);

	fd = open(filename, O_RDONLY);
	if (fd < 0) 
		error(1, "Error when trying to open maps file: %s\n", filename);


	idx = 0;

	/* read full lines from the file which describes memory areas within a process
	   choose executable and readable memory areas and see if we can find machine code of a system call
	*/

	while (1) {

		if (read(fd, &line[idx], 1) != 1) {
			line[idx] = '\0';
			break;
		}

		if (line[idx] == '\n') {
			line[idx] = '\0';

			/* example line:
			   08048000-0804f000 r-xp 00000000 08:06 745429     /bin/cat
			*/
			verbose("Read line: %s\n", line);
			sscanf(line, "%lx-%lx %4c", &start, &stop, perm);
			perm[4] = '\0';

			permissions = 0;

			for (i = 0; i < 4; i++) {
				if (perm[i] == 'x')
					permissions |= VMA_PERM_EXECUTE;

				if (perm[i] == 'r')
					permissions |= VMA_PERM_READ;
			}

			verbose("start: %lx, stop: %lx, delta: %d; perm: %s, %d\n", start, stop, stop - start, perm, permissions);

			if (permissions == (VMA_PERM_EXECUTE | VMA_PERM_READ)) {

				verbose("Found readable and executable memory area\n");
				t = (unsigned char *) start;

				/*
				   read the contents of process (with given pid) memory so that we find machine code of int $0x80 (x86) or syscall (x86-64)
				   system call on Linux is int $0x80 for x86 platform, for which machine code is: 0xcd, 0x80
				   system call for x86-64 is: syscall; 0x0f, 0x05.

				   these two bytes are set at the top of this file and can be referenced by variable/array magic
				*/
				
				seg = 0;

				peek_data = ptrace(PTRACE_PEEKTEXT, pid, t, NULL);
				memcpy(data[seg], &peek_data, WORD_BYTES);

				j = 0;
				while (t < (unsigned char *) (stop - 1)) {

					if (j == (WORD_BYTES - 1)) {
						peek_data = ptrace(PTRACE_PEEKTEXT, pid, t + 1, NULL);
						memcpy(data[!seg], &peek_data, WORD_BYTES);

						if (data[seg][WORD_BYTES - 1] == magic[0] && data[!seg][0] == magic[1])
							return t;

						seg = !seg;
						j = 0;


					} else {
						if (data[seg][j] == magic[0] && data[seg][j + 1] == magic[1])
							return t;

						j++;
					}
					t++;
				}
			}

			idx = 0;
			continue;
		}

		idx++;

	}

	return NULL;
}

void usage(char **argv) {
	fprintf(stderr, "Usage: %s -p process_id file_descriptor_number\n", argv[0]);
	fprintf(stderr, "\n\n");
	fprintf(stderr, "This program closes a file descriptor/socket in a process <process_id>\n");
	exit(2);
}

int main (int argc, char **argv) {

        struct user_regs_struct orig_regs, new_regs;
        int pid = -1, status, last_status = 0;
        int data = 0, done = 0, i, *p, fd, ec;
        char c;
        unsigned char *t;
	long int file_desc_no;


        verbose("user_regs_struct size: %d\n", sizeof(struct user_regs_struct));

	while ((c = getopt (argc, argv, "vp:")) != -1)
		switch (c) {
			case 'p':
				pid = atoi(optarg);
				break;

			case 'v':

				flag_verbose = 1;
				break;

			case '?':
				if (optopt == 'p')
					error(1, "-p requires an argument (pid of the process)\n");
				break;
			default:
				abort ();
		}

	if (pid == -1 || (optind + 1 < argc) || (optind == argc)) {
		usage(argv);
	}

	if (optind < argc) {
		file_desc_no = atol(argv[optind]);
	}

        i = 0;

        if (1) {

		/* main code:
		   * ptrace attach to the given process; this will change the given process's state to 'sleep interruptible'
		   * save process's general registers 
		   * find machine code of a system call within readable and executable memory areas of process
		   * alter appriopriate registers, preparing the process to execute a system call; set process instruction pointer register to the address of system call 
		   * exec a single instruction, which means execute a system call in the context of the given process
		   * fetch registers to see the status of system call
		   * restore registers
		   * detach from the process
		*/

                //signal(SIGCHLD, &sig_chld);

		ec = ptrace(PTRACE_ATTACH, pid, 0, 0);
                verbose("ptrace attach: %d\n", ec);

		if (ec)
			error(1, "error in ptrace attach: %d to pid: %d; is the process running and are you allowed to attach to it?\n", ec, pid);



                while (1) {

                        data = 0;
			

			// XXX status == int?
                        wait(&status);
                        verbose("wait: %d, %x\n", status, status);

                        if (done) {
                                p = (int *) &orig_regs;

                                ec = ptrace(PTRACE_SETREGS, pid, 0, &orig_regs);
				verbose("setregs: %d\n", ec);

				if (ec)
					error(1, "ptrace setregs error: %d\n", ec);

				ec = ptrace(PTRACE_DETACH, pid, 0, SIGCONT);
                                verbose("detach(): %d\n", ec);

				if (ec) 
					error(1, "ptrace detach error: %d\n", ec);


                                exit(0);
                        }

                        if (WIFEXITED(status)) {
				error(1, "The process has terminated\n");
                        }

                        if (WIFSTOPPED(status)) {

                                verbose("Child received signal: %d\n", WSTOPSIG(status));
                                if (WSTOPSIG(status) != 5)
                                        data = WSTOPSIG(status);

                                p = (int *) &orig_regs;

				ec = ptrace(PTRACE_GETREGS, pid, 0, &orig_regs);
                                verbose("ptrace getregs: %d\n", ec);

				if (ec)
					error(1, "ptrace getregs error: %d\n", ec);

                                memcpy(&new_regs, &orig_regs, sizeof(orig_regs));

				t = find_syscall(pid);

				if (!t) 
					error(1, "Couldn't find system call machine code\n");
				

#ifdef __i386__
				new_regs.eax = SYS_close; // 6
				new_regs.ebx = file_desc_no;
				new_regs.eip = (long int) t;

#elif defined(__x86_64__)
                                new_regs.rax = SYS_close; // 3
                                new_regs.rdi = file_desc_no;
                                new_regs.rip = (long int) t;
#else

	#error "Valid and supported architectures are: x86, x86-64"
#endif
				ec = ptrace(PTRACE_SETREGS, pid, 0, &new_regs);
                                verbose("setregs: %d\n", ec);

				if (ec)
					error(1, "ptrace setregs error: %d\n", ec);

				ec = ptrace(PTRACE_SINGLESTEP, pid, 0, 0);
                                verbose("ptrace singlestep: %d\n", ec);

				if (ec)
					error(1, "ptrace singlestep error: %d\n", ec);

                                done = 1;


                        }

                        
                }

                verbose("This is the end\n");
        } 


}
