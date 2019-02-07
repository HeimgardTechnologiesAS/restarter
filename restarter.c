/*
 * restarter run a command and restart it on exit sivann at gmail.com 2015
 * 
 */

#include <sys/wait.h>			// before _POSIX__SOURCE to get WCOREDUMP

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <ctype.h>

#include <sys/select.h>
#include <sys/time.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <limits.h>
#include <syslog.h>

#ifndef __APPLE__
#include <sys/klog.h>
#include <sys/prctl.h>
#endif

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/utsname.h>

#include <restarter.h>


#define MAX_CMD_OUTPUT_LENGTH 1048576	/* maximum command output length * 
										 * (bytes) */
#define MAX_CMD_LENGTH 1048576	/* length of command & popen scripts *
								 * (bytes) */
#define TIMEOUT_KILL_SEC 3		/* If timed out command has been *
								 * unsuccessfully killed with SIGTERM, *
								 * wait that many seconds before SIGKILL */

/*
 * Globals 
 */
option_s options;

pid_t cmd_pid;					/* pid of execed command */
volatile sig_atomic_t cmd_exitstatus;	/* exit status of cmd_pid */
volatile sig_atomic_t cmd_exitstatus2;	/* actual exit status of cmd_pid */
char cmd_exitreason[128];
volatile sig_atomic_t want_exit = 0;

int nchildren = 0;				/* current number of forked children *
								 * processes */
int fastpolls = 0;				/* remaining number of fast poll cycles */
int popen_alarm_active = 0;		/* interrupted by alarm, for *
								 * expiring popen commands */
char logmsg[MAX_CMD_LENGTH];
char log_ident[256];
char exit_valid[64];
char pid_file[256];
int lock_fd;					/* file lock used to prevent agent to run
								 * * twice */
int main_pid;

char cmd[1024];					// command to run

int main(int argc, char *argv[]) {
	int opt;
	struct sigaction sa;

	char lock_agentname[128];

	/*
	 * Defaults 
	 */
	options.debug = 0;
	options.cmd_type = 'C';
	options.max_children = 1;
	options.syslog = 0;
	options.command_restart_period = 3;
	options.command_timeout = 0;
	options.run1 = 0;
	strlcpy(log_ident, argv[0], 128);
	pid_file[0] = 0;
	exit_valid[0] = 0;

	/*
	 * initialize in case options are missing from .ini 
	 */
	cmd[0] = 0;

	/*
	 * Parse Options 
	 */
	while ((opt = getopt(argc, argv, "m:i:r:t:hdc:slp:1e:")) != -1) {
		switch (opt) {
		case '1':
			options.run1++;
			break;
		case 'd':
			options.debug++;
			break;
		case 'l':
			options.syslog = 1;
			break;
		case 's':
			options.cmd_type = 'P';
			break;
		case 'm':
			options.max_children = atoi(optarg);
			if (options.max_children <= 0) {
				fprintf(stderr, "Invalid max_children specified (-r %s)\n",
						optarg);
				exit(2);
			}
			break;
		case 'r':
			options.command_restart_period = atoi(optarg);
			if (options.command_restart_period <= 0) {
				fprintf(stderr,
						"Invalid restart period specified (-r %s)\n",
						optarg);
				exit(2);
			}
			break;
		case 't':
			options.command_timeout = atoi(optarg);
			if (options.command_timeout <= 0) {
				fprintf(stderr, "Invalid timeout specified (-t %s)\n",
						optarg);
				exit(2);
			}
			break;
		case 'e':
			strlcpy(exit_valid, optarg, 64);
			break;
		case 'i':
			strlcpy(log_ident, optarg, 256);
			break;
		case 'p':
			strlcpy(pid_file, optarg, 256);
			break;
		case 'c':
			strlcpy(cmd, optarg, 512);
			break;
		case 'h':
			showUsage();
			exit(0);
			break;
		default:				/* '?' */
			showUsage();
			exit(EXIT_FAILURE);
		}
	}

	if (cmd[0] == 0) {
		showUsage();
		fprintf(stderr, "Command not specified (-c)\n");
		exit(1);
	}
	// Initialize syslog
	openlog(log_ident, LOG_PID | LOG_PERROR, LOG_LOCAL3);
	syslog(LOG_INFO, "Started by uid %d", getuid());

	/*
	 * Acquire lock to prevent agents to run simultaneously. Replace
	 * previous process if requested by commandline option. 
	 */
	strlcpy(lock_agentname, "restarter", 127);
	str_replace_char_inline(lock_agentname, '/', '-');



	// add signal handler to count child processes and limit parallel
	// commands (max_children)
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sa.sa_handler = sigchildhdl_Count;
	if (sigaction(SIGCHLD, &sa, NULL) == -1) {
		snprintf(logmsg, sizeof(logmsg), "main:sigaction:%s",
				 strerror(errno));
		syslog(LOG_ERR, "%s", logmsg);
	}

	if (options.run1) {
		if (!strlen(pid_file)) {
			showUsage();
			fprintf(stderr,
					"-1 requested but pid_file not specified (-p)\n");
			exit(2);
		}
		lock_or_act(pid_file, 0);
	}
	// setbuf(stdout,0);
	main_pid = getpid();
	signal(SIGUSR2, usr2_handler);
	mainloop();

	syslog(LOG_INFO, "After main loop, exiting");

	return 0;
}

void usr2_handler(int sig) {
	syslog(LOG_NOTICE, "Exiting on USR2:%d", sig);
	exit(0);
}


void mainloop() {
	// char cmd[256];
	unsigned long cmd_id = 0;

	while (1) {
		cmd_id++;
		if (options.debug) {
			printf("\n[%d]:Loop\n", getpid());
			printf("Executing: (%s)\n", cmd);
		}


		syslog(LOG_INFO, "Executing [%ld]: (%s)", cmd_id, cmd);
		runCommand(cmd, options.cmd_type, cmd_id, options.command_timeout);
		if (options.debug)
			printf("SLEEPING 1sec\n");
		deepSleep(1000);

		while (nchildren == options.max_children) {
			if (options.debug) {
				syslog(LOG_INFO,
					   "I have %d children, waiting for status change",
					   nchildren);
			}
			deepSleep(options.command_restart_period * 1000);
		}

	}


}

void deepSleep(unsigned long milisec) {
	struct timespec req;
	time_t sec = (int) (milisec / 1000);

	milisec = milisec - (sec * 1000);
	req.tv_sec = sec;
	req.tv_nsec = milisec * 1000000L;
	while (nanosleep(&req, &req) == -1) {
		if (errno == EINTR)
			continue;
		else {
			perror("deepSleep:nanosleeep");
		}

	}
}

/*
 * kill cmd_pid (for timeout) 
 */
void sigalarm_CommandKiller(int signum) {	/* parent SIGALRM handler */
	int r;

	r = kill(cmd_pid, SIGTERM);
	if (r != 0) {
		sprintf(logmsg, "[%d]:SIGALRM,signal:%d:kill error:%s\n", getpid(),
				signum, strerror(errno));
		syslog(LOG_ERR, "%s", logmsg);
		exit(errno);
	}

	deepSleep(TIMEOUT_KILL_SEC * 1000);

	/*
	 * if pid still exists, kill -9 
	 */
	if (kill(cmd_pid, 0))
		kill(cmd_pid, SIGKILL);

	if (options.debug) {
		fprintf(stderr, "[%d]:SIGALRM:sigalarm_CommandKiller:killed:%d\n",
				getpid(), cmd_pid);
	}

	/*
	 * We have set SIG_IGN on SIGCHLD, so no wait necessary 
	 */

	return;
}

void alarm_popen_handler() {	/* parent SIGALRM handler */
	popen_alarm_active = 1;
}


/*
 * runCommand: call a command via exec (cmd_type:C) or popen (cmd_type:P)
 * command_type: C,P - fork: - parent: returns , continues loop - child:
 * forks again: - parent waits for output, posts output via http, and
 * kills child on timeout - child execs <cmd> (C), or execs /bin/sh -c
 * <cmd> (P) command_type: 0 (not used any more) - fork: - parent:
 * returns , continues loop - child: calls cmd with popen, reads output,
 * posts, kills process group on timeout 
 */

void
runCommand(char *cmd, char cmd_type, unsigned long cmd_id, int timeout) {
	unsigned long int mypid, child_pid;
	char buf[MAX_CMD_OUTPUT_LENGTH];	// used to also hold
	// command output


	char *args[64];
	int r, pipefd[2];
	int message_chunk = 0;

	sigset_t signal_set;
	struct sigaction sa;

	if (options.debug) {
		printf("runCommand(%s,%c,%ld,%d)\n", cmd, cmd_type, cmd_id,
			   timeout);
	}
	// block sigchld signals so it stays blocked on child (signal handler
	// set in main())
	sigemptyset(&signal_set);
	sigaddset(&signal_set, SIGCHLD);
	if (sigprocmask(SIG_BLOCK, &signal_set, NULL) == -1) {
		sprintf(logmsg, "sigprocmask(block):%s", strerror(errno));
		syslog(LOG_ERR, "%s", logmsg);
	}

	if (!(child_pid = fork())) {
		// child
		char pname[64];
		struct rlimit limit;

		// signal(SIGCHLD, SIG_IGN);
		// no special handler for executed command
		if (cmd_type != 'P') {
			sa.sa_handler = SIG_IGN;
		} else if (cmd_type == 'P') {	// allow popen to handle its child 
			// 
			// and return correct exit status
			// on pclose()
			sa.sa_handler = SIG_DFL;
		}

		sigemptyset(&sa.sa_mask);
		sa.sa_flags = 0;
		if (sigaction(SIGCHLD, &sa, 0) == -1) {
			sprintf(logmsg, "sigaction (ign):%s", strerror(errno));
			syslog(LOG_ERR, "%s", logmsg);
		}

		/*
		 * Do not leave core files 
		 */
		getrlimit(RLIMIT_CORE, &limit);
		limit.rlim_cur = 0;
		setrlimit(RLIMIT_CORE, &limit);

		mypid = getpid();

		if (options.debug)
			printf
				("[%lu]:Child %lu born, cmd:%s, timeout:%d, cmd_type:%c\n",
				 mypid, child_pid, cmd, timeout, cmd_type);

		snprintf(pname, sizeof(pname), "restarter %c cmd %ld", cmd_type,
				 cmd_id);
		// prctl(PR_SET_NAME, "Test");

		/*
		 * Plain popen no longer used since it lacks good status
		 * reporting, timeout, stderr 
		 */
		if (cmd_type == 'C' || cmd_type == 'P') {	// exec
			int i = 0;
			unsigned int len = 0;
			char b[512];

			if (pipe(pipefd) == -1) {
				sprintf(logmsg, "pipe:%s", strerror(errno));
				syslog(LOG_ERR, "%s", logmsg);
				return;
			}

			cmd_exitstatus = -9999;
			cmd_exitreason[0] = 0;

			// signal handler, to get exit code of execed command

			sigemptyset(&sa.sa_mask);
			sa.sa_flags = 0;
			sa.sa_handler = sigchildhdl_GetExitStatus;
			if (sigaction(SIGCHLD, &sa, NULL) == -1) {
				sprintf(logmsg, "main:sigaction:%s", strerror(errno));
				syslog(LOG_ERR, "%s", logmsg);
			}
			// block sigchld signals so it stays blocked on child
			sigemptyset(&signal_set);
			sigaddset(&signal_set, SIGCHLD);
			if (sigprocmask(SIG_BLOCK, &signal_set, NULL) == -1) {
				sprintf(logmsg, "sigprocmask(block):%s", strerror(errno));
				syslog(LOG_ERR, "%s", logmsg);
			}

			if (!(cmd_pid = fork())) {
				// inside child, will be replaced by cmd via exec
				char *newcmd;

				sa.sa_handler = SIG_IGN;
				sigemptyset(&sa.sa_mask);
				sa.sa_flags = 0;
				if (sigaction(SIGCHLD, &sa, 0) == -1) {
					sprintf(logmsg, "sigaction (ign):%s", strerror(errno));
					syslog(LOG_ERR, "%s", logmsg);
				}

				newcmd = str_replace(cmd, "#ssh_client#", "");

				if (options.debug)
					printf("[%d]:Before exec command id:%ld\n", getpid(),
						   cmd_id);

				sprintf(logmsg, "Starting [%s] with pid:%d", cmd,
						getpid());
				syslog(LOG_INFO, "%s", logmsg);

				/*
				 * Write pid to file (-p option) 
				 */
				if (strlen(pid_file)) {
					FILE *pfp;
					pfp = fopen(pid_file, "w");
					if (!pfp) {
						snprintf(logmsg, sizeof(logmsg), "fopen:%s:%s",
								 pid_file, strerror(errno));
						syslog(LOG_ERR, "%s", logmsg);
					} else {
						fprintf(pfp, "%d", getpid());
						fclose(pfp);
					}
				}

				i = 0;
				while ((dup2(pipefd[1], 1) == -1) && (errno == EINTR)
					   && i < 100) {
					i++;
				}
				close(pipefd[0]);	// close read-end of pipe
				dup2(1, 2);		// stderr->stdout

				if (cmd_type == 'C') {
					makeargv(newcmd, args);	// make argument vector
					// from newcmd (newcmd
					// gets nulls on
					// delimiters)
					if (execvp(args[0], args) == -1) {
						snprintf(logmsg, sizeof(logmsg),
								 "execvp:%s,command:%s", strerror(errno),
								 cmd);
						syslog(LOG_ERR, "%s", logmsg);
						exit(errno);
					}
				} else {		// cmd_type == 'P'
					for (i = strlen(newcmd) - 1; (!isalnum(newcmd[i]));
						 i--)
						newcmd[i] = 0;	// rtrim
					if (execl("/bin/sh", "sh", "-c", newcmd, (char *) 0) ==
						-1) {
						snprintf(logmsg, sizeof(logmsg),
								 "SHELL execvp:%s command:%s",
								 strerror(errno), cmd);
						/*
						 * exec in this case will always succeed unless
						 * /bin/sh is missing, it's the shell not exec
						 * that returns the error 
						 */
						syslog(LOG_ERR, "%s", logmsg);
						exit(errno);
					}
				}
				fprintf(stderr, "ERROR: how did we reach this\n");
				exit(-5555);
			}
			// unblock signal handler so we can get exit status
			sigemptyset(&signal_set);
			sigaddset(&signal_set, SIGCHLD);
			if (sigprocmask(SIG_UNBLOCK, &signal_set, NULL) == -1) {
				sprintf(logmsg, "sigprocmask(unblock):%s",
						strerror(errno));
				syslog(LOG_ERR, "%s", logmsg);
			}
			// parent, waits for child's output and posts it
			signal(SIGALRM, sigalarm_CommandKiller);
			alarm(timeout);

			if (options.debug)
				printf
					("[%d]:Added SIGALRM for %d seconds (should kill pid %d)\n",
					 getpid(), timeout, cmd_pid);

			close(pipefd[1]);	// close write-end of pipe

			if (options.debug)
				printf("[%d]:Reading command pid %d output\n", getpid(),
					   cmd_pid);

			buf[0] = b[0] = 0;
			// read command output in chunks until buf is full
			message_chunk = 0;
			while ((r = read(pipefd[0], b, sizeof(b) - 1)) != 0) {
				if (r < 0) {
					if (errno == EINTR)
						continue;
					else {
						fprintf(stderr, "ERROR: read():%s",
								strerror(errno));
					}
					break;
				}

				b[r] = 0;
				message_chunk++;
				len += r;
				if (len >= sizeof(buf)) {
					sprintf(logmsg,
							"[%d]: WARNING: readloop: command id %ld output > sizeofbuf (%zu):truncated\n",
							getpid(), cmd_id, sizeof(buf));
					syslog(LOG_ERR, "%s", logmsg);
					break;
				}

				strcat(buf, b);

				if (options.syslog) {
					syslog(LOG_INFO, "%s:read chunk %d,  %s", cmd,
						   message_chunk, b);
				} else
					fprintf(stdout, "%s", b);

				if (options.debug) {
					fprintf(stderr,
							"[%d]: readloop: read_bytes:%d chunk:%d, strlen(b):%zu, strlen(buf):%zu, b:[%s]\n",
							getpid(), r, message_chunk, strlen(b),
							strlen(buf), b);
				}
			}
			close(pipefd[0]);

			// Command exited at this point

			if (options.debug) {
				fprintf(stderr,
						"[%d]: cmd_exitstatus:%d, cmd_exitreason:%s\n",
						getpid(), cmd_exitstatus, cmd_exitreason);
				fprintf(stderr,
						"[%d]: waiting for child handler to update exitstatus\n",
						getpid());
			}
			// Wait a bit for SIGCHLD signal handler to update exitstatus
			// variable for us to report to server
			while (cmd_exitstatus == -9999) {
				int sleepcount = 0;
				sleep(1);
				if (sleepcount++ > 10) {
					sprintf(logmsg,
							"[%d]: waited too much for exitstatus update, returning\n",
							getpid());
					syslog(LOG_WARNING, "%s", logmsg);
					break;
				}
			}

			if (options.debug) {
				fprintf(stderr,
						"[%d]: After loop: cmd_exitstatus:%d, cmd_exitreason:%s\n",
						getpid(), cmd_exitstatus, cmd_exitreason);
			}

			if (options.debug) {
				fprintf(stderr,
						"[%d]: Done reading, buffer:[%s], cmd_exitstatus:%d, cmd_exitreason:%s\n",
						getpid(), buf, cmd_exitstatus, cmd_exitreason);
			}

			fprintf(stderr, "exit_valid:(%s), cmd_exitstatus2:%d\n",
					exit_valid, cmd_exitstatus2);
			if (number_in_csv(cmd_exitstatus2, exit_valid)) {
				sprintf(logmsg,
						"[%d]:%d is in the list of valid exit statuses (%s), exiting with sigusr2",
						getpid(), cmd_exitstatus2, exit_valid);
				syslog(LOG_NOTICE, "%s", logmsg);
				kill(main_pid, SIGUSR2);
				exit(0);
			}

			fprintf(stderr, "[%d]: Exiting\n\n", getpid());
			exit(0);

		}						// cmd==C || P
		exit(0);
	} else {					// we are the parent
		// unblock sigchld
		sigemptyset(&signal_set);
		sigaddset(&signal_set, SIGCHLD);
		if (sigprocmask(SIG_UNBLOCK, &signal_set, NULL) == -1) {
			sprintf(logmsg, "sigprocmask(unblock):%s", strerror(errno));
			syslog(LOG_WARNING, "%s", logmsg);
		}

		nchildren++;
		if (options.debug)
			printf("\n[%d]:I have %d children\n", getpid(), nchildren);
	}
}								// runCommand

/*
 * argv is an array of pointers to buf parts buf will be overwritten
 * (spaces replaced with 0) 
 */
void makeargv(char *buf, char **argv) {
	while (*buf != '\0') {		/* if not the end of buf */
		while (*buf == ' ' || *buf == '\t' || *buf == '\n' || *buf == '\r')
			*buf++ = '\0';		/* replace white spaces with 0 */
		*argv++ = buf;

		while (*buf != '\0' && *buf != ' ' &&
			   *buf != '\t' && *buf != '\n' && *buf != '\r')
			buf++;
	}
	// *argv = '\0';
	*argv = (char *) 0;
}

void showUsage() {
	printf("\nRestarter. (https://bitbucket.org/sivann/restarter)\n");
	printf
		("Usage: restarter [-d] [-h] [-t timeout] [-c command] [-p pid_file]\n");
	printf
		("\t-c [command]\tcommand to execute, include arguments in quotes. Mandatory.\n");
	printf("\t-d\t\tdebug\n");
	printf("\t-s\t\tuse a shell to execute command(s)\n");
	printf("\t-t\t\ttimeout: terminate process after timeout seconds\n");
	printf
		("\t-l\t\tsyslog: redirect command stdout and stderr to syslog\n");
	printf
		("\t-m\t\tmultiple: keep multiple instances of process running\n");
	printf
		("\t-e\t\tvalid exit status: comma separated exit status which prevent restart\n");
	printf("\t-i\t\tsyslog ident string\n");
	printf("\t-p\t\twrite pid of new process to pid_file\n");
	printf
		("\t-1\t\tstart only if process specified by -p is not running\n");
	printf("\n");
}

// return true if n exists in csv
int number_in_csv(int n, char *csv) {
	int i;

	while (sscanf(csv, "%d", &i) > 0) {
		if (i == n)
			return 1;
	}
	return 0;
}

/*
 * wait and set exit status in global var so it can be reported back (used 
 * by command executing process) 
 */
static void sigchildhdl_GetExitStatus(int sig) {
	int e, r;
	pid_t child_pid = 0;

	while ((r = waitpid(-1, &e, WNOHANG)) > 0) {
		child_pid = r;
		// nchildren--;
		setWaitStatus(e);
		if (options.debug) {
			printf
				("[%d]:sigchildhdl_GetExitStatus SIGCHLD handler, child_pid:%d, waitpid returned:%d, exit_reason:%s, child exit status:%d, signal:%d, nchildren now:%d\n",
				 getpid(), child_pid, r, cmd_exitreason, e, sig,
				 nchildren);
		}

		sprintf(logmsg,
				"[%d]:sigchildhdl_GetExitStatus SIGCHLD handler, child_pid:%d, waitpid returned:%d, exit_reason:%s, child exit status:%d, signal:%d, nchildren now:%d\n",
				getpid(), child_pid, r, cmd_exitreason, e, sig, nchildren);
		syslog(LOG_ERR, "%s", logmsg);


	}

	if (child_pid == -1 && errno != ECHILD) {
		sprintf(logmsg,
				"[%d]:sigchildhdl_GetExitStatus SIGCHLD handler ERROR: waitpid: %s\n",
				getpid(), strerror(errno));
		syslog(LOG_ERR, "%s", logmsg);
	}

	if (child_pid == cmd_pid) {	// just to be sure
		cmd_exitstatus = e;
	}

}

/*
 * just wait and count children (used by main process) 
 */
void sigchildhdl_Count(int sig) {
	int e, r, child_pid = 0;

	while ((r = waitpid(-1, &e, WNOHANG)) > 0) {
		child_pid = r;
		nchildren--;
	}

	if (options.debug)
		printf
			("*** [%d]:sigchildhdl_Count(signal:%d), child_pid:%d exited with:%d, nchildren:%d\n",
			 getpid(), sig, child_pid, e, nchildren);

	// signal (SIGCHLD, sigchildhdl_Count);

}


/*
 * Examine a wait() status using the W* macros 
 */
void setWaitStatus(int status) {
	char s[128];

	s[0] = 0;

	cmd_exitstatus2 = -999;

	if (WIFEXITED(status)) {
		sprintf(s, "process exited, exit status=%d", WEXITSTATUS(status));
		cmd_exitstatus2 = WEXITSTATUS(status);
	} else if (WIFSIGNALED(status)) {
		sprintf(s, "process killed by signal %d (%s)", WTERMSIG(status),
				strsignal(WTERMSIG(status)));
		if (WCOREDUMP(status))
			strcat(s, " (core dumped)");
	} else if (WIFSTOPPED(status)) {
		sprintf(s, "process stopped by signal %d (%s)", WSTOPSIG(status),
				strsignal(WSTOPSIG(status)));
	} else if (WIFCONTINUED(status)) {
		sprintf(s, "process continued\n");
	} else {					/* Should never happen */
		sprintf(s, "what happened to this process? (exit status=%x)",
				(unsigned int) status);
	}
	strcpy(cmd_exitreason, s);
}



/*
 * check if lock exists, and act action == 0 : exit action == 1 : replace
 * previous lock-holding process: if lock is active kill pid in lockfile
 * (restarter called with -f) 
 */
void lock_or_act(char *lockfn, int action) {
	int ret, flags;
	char b[64];

	if ((lock_fd =
		 open(lockfn, O_CREAT | O_RDWR | O_SYNC, S_IRUSR | S_IWUSR)) == -1)
	{
		perror("lock");
		exit(1);
	}
	// Prevent locks to be inherited on children. 
	// Old kernels do not support O_CLOEXEC flag in open()
	if ((flags = fcntl(lock_fd, F_GETFD, 0)) == -1) {
		sprintf(logmsg, "lock_or_act:fcntl:F_GETFD: %s", strerror(errno));
		syslog(LOG_ERR, "%s", logmsg);
	} else {
		flags |= FD_CLOEXEC;
		if (fcntl(lock_fd, F_SETFD, flags) == -1) {
			sprintf(logmsg, "lock_or_act:fcntl:F_SETFD: %s",
					strerror(errno));
			syslog(LOG_ERR, "%s", logmsg);
			if (action != 1)	// better to ignore in this case
				exit(EXIT_FAILURE);
		}
	}

	// lock or fail
	if ((ret = lockf(lock_fd, F_TLOCK, 0)) == -1) {
		// could not lock, probably already locked

		if (action == 0) {
			sprintf(logmsg,
					"Another instance is running, %s is locked, exiting",
					lockfn);
			syslog(LOG_ERR, "%s", logmsg);
			exit(EXIT_FAILURE);
		} else {				// kill running process and retry lock
			pid_t oldpid;
			int r;

			// if (!(fp = fdopen(lock_fd,"r"));
			r = read(lock_fd, b, 63);
			b[r] = 0;
			sscanf(b, "%d", &oldpid);
			sprintf(logmsg,
					"Another instance is running, %s is locked, killing with SIGTERM old pid %d",
					lockfn, oldpid);
			syslog(LOG_INFO, "%s", logmsg);
			if (kill(oldpid, 0)) {
				sprintf(logmsg, "old pid %d disappeared before killing it",
						oldpid);
				syslog(LOG_INFO, "%s", logmsg);
			} else
				kill(oldpid, 15);

			sleep(2);
			if (kill(oldpid, 0)) {
				sprintf(logmsg, "old pid %d killed", oldpid);
				syslog(LOG_INFO, "%s", logmsg);
			} else
				kill(oldpid, 9);

			sleep(1);

			// try to lock again
			if ((ret = lockf(lock_fd, F_TLOCK, 0)) == -1) {
				sprintf(logmsg,
						"failed to acquire lock, %s even after killing with SIGKILL pid %d",
						lockfn, oldpid);
				syslog(LOG_ERR, "%s", logmsg);
				exit(EXIT_FAILURE);
			}
		}
	}
	// lock succedded here

	// write our pid in the lockfile
	snprintf(b, 64, "%d", getpid());
	ftruncate(lock_fd, 0);
	lseek(lock_fd, 0, SEEK_SET);
	write(lock_fd, b, strlen(b));
}
