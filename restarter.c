/*
   restarter
   run a command and restart it on exit
   sivann at gmail.com 2015

*/

/* Get strsignal() declaration from <string.h> */
#define _POSIX_C_SOURCE
#define _GNU_SOURCE


#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <ctype.h>

#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <limits.h>
#include <syslog.h>
#include <sys/klog.h>

#include <sys/prctl.h>


#include <arpa/inet.h>
#include <netdb.h>
#include <curl/curl.h>
#include <sys/utsname.h>

#include <restarter.h>


#define MAX_CMD_OUTPUT_LENGTH 1048576 /* maximum command output length (bytes) */
#define MAX_CMD_LENGTH 1048576 /* length of command & popen scripts (bytes) */
#define TIMEOUT_KILL_SEC 3 /* If timed out command has been unsuccessfully killed with SIGTERM, wait that many seconds before SIGKILL */

/* Globals */
option_s options;

pid_t cmd_pid;             /* pid of execed command */
int cmd_exitstatus;        /* exit status of cmd_pid */
char cmd_exitreason[128];

int nchildren=0;           /* current number of forked children processes */
int fastpolls=0;           /* remaining number of fast poll cycles */
int popen_alarm_active=0;  /* interrupted by alarm, for expiring popen commands */
char logmsg[MAX_CMD_LENGTH];
int lock_fd;               /* file lock used to prevent agent to run twice */

char cmd[1024]; // command to run

int main (int argc, char *argv[]) {
    int opt;
    struct sigaction sa;

    char lockfn[512];
    char lock_agentname[128];

    /* Defaults */
    options.debug=0;
    options.command_restart_period=3;
    options.command_timeout=0;
    options.max_children=2;

    /* initialize in case options are missing from .ini */
    cmd[0]=0;

    /* Parse Options */
    while ( (opt = getopt (argc, argv, "r:t:hdc:s") ) != -1) {
        switch (opt) {
        case 'd':
            options.debug++;
            break;
        case 's':
            options.cmd_type='P';
            break;
        case 'r':
            options.command_restart_period=atoi(optarg);
            if (options.command_restart_period<=0) {
                fprintf(stderr,"Invalid restart period specified (-r %s)\n",optarg);
                exit (2);
            }
            break;
         case 't':
            options.command_timeout=atoi(optarg);
            if (options.command_timeout<=0) {
                fprintf(stderr,"Invalid timeout specified (-t %s)\n",optarg);
                exit (2);
            }
            break;
        case 'c':
            strlcpy (cmd,optarg,512);
            break;
        case 'h':
            showUsage();
            exit(0);
            break;
        default: /* '?' */
            showUsage();
            exit (EXIT_FAILURE);
        }
    }

    if (cmd[0]==0) {
        fprintf(stderr,"Command not specified (-c)\n");
        exit(0);
    }

    // Initialize syslog
    openlog (argv[0], LOG_PID|LOG_PERROR , LOG_LOCAL3);
    syslog (LOG_INFO, "Started by uid %d", getuid () );

    /* Acquire lock to prevent agents to run simultaneously. Replace previous process if requested by commandline option. */
    strlcpy(lock_agentname,"restarter",127);
    str_replace_char_inline(lock_agentname,'/','-');
    snprintf(lockfn,512,"/tmp/restarter-%s.lock",lock_agentname);
    lock_or_act(lockfn, 0);


    // add signal handler to count child processes and limit parallel commands (max_children)
    sigemptyset (&sa.sa_mask);
    sa.sa_flags = 0;
    sa.sa_handler = sigchildhdl_Count;
    if (sigaction (SIGCHLD, &sa, NULL) == -1) {
        snprintf (logmsg,sizeof(logmsg),"main:sigaction:%s",strerror (errno) );
        syslog (LOG_ERR,"%s",logmsg);
    }

    mainloop(); 

    syslog (LOG_INFO, "After main loop, exiting");

    return 0;
}

void mainloop() {
    //char cmd[256];
    unsigned long cmd_id=1234;

    while (1) {
        if (options.debug) {
            printf ("\n[%d]:Loop\n",getpid());
            printf("Running: (%s)\n",cmd);
        }
        syslog (LOG_INFO, "Running: (%s)",cmd);
        runCommand (cmd,options.cmd_type,cmd_id,options.command_timeout);
        while (nchildren) {
            if (options.debug) {
                syslog(LOG_INFO,"I have %d children, waiting for status change",nchildren);
            }
            deepSleep (options.command_restart_period);
        }
    }


}


/* sleep, uninterrupted by signals */
void deepSleep (unsigned int seconds) {
    unsigned int rem;

    if (options.debug)
        fprintf (stderr,"[%d]:deepSleep:sleeping for %d seconds\n",getpid(),seconds);

    for (rem=seconds; rem;)
        rem=sleep (rem);
}

/* kill cmd_pid (for timeout) */
void sigalarm_CommandKiller (int signum) {       /* parent SIGALRM handler     */
    int r;

    r = kill (cmd_pid, SIGTERM);
    if (r != 0) {
        sprintf (logmsg,"[%d]:SIGALRM,signal:%d:kill error:%s\n",getpid(),signum,strerror (errno) );
        syslog (LOG_ERR,"%s",logmsg);
        exit (errno);
    }

    deepSleep (TIMEOUT_KILL_SEC);

    /* if pid still exists, kill -9 */
    if (kill (cmd_pid,0) )
        kill (cmd_pid,SIGKILL);

    if (options.debug) {
        fprintf (stderr,"[%d]:SIGALRM:sigalarm_CommandKiller:killed:%d\n",getpid(),cmd_pid);
    }

    /*
      We have set SIG_IGN on SIGCHLD, so no wait necessary
    */

    return;
}

void alarm_popen_handler () {       /* parent SIGALRM handler     */
    popen_alarm_active = 1;
}


/* runCommand: call a command via exec (cmd_type:C) or popen (cmd_type:P)
 * command_type: C,P
 * - fork:
 * - parent: returns , continues loop
 *   - child: forks again:
 *     - parent waits for output, posts output via http, and kills child on timeout
 *     - child execs <cmd> (C), or execs /bin/sh -c <cmd> (P)
 *
 * command_type: 0  (not used any more)
 * - fork:
 * - parent: returns , continues loop
 *   - child: calls cmd with popen, reads output, posts, kills process group on timeout
 */

void runCommand (char * cmd, char cmd_type, unsigned long cmd_id, int timeout) {
    unsigned long int mypid, child_pid;
    char buf[MAX_CMD_OUTPUT_LENGTH] ; //used to also hold command output

    char post_result_url[512], post_tunnelport_url[512];

    char *args[64];
    int r,pipefd[2];
    int message_chunk=0;

    sigset_t signal_set;
    struct sigaction sa;

    sprintf (post_result_url,"%s/ca/agents/%s/commands/%lu/result",options.server_url, options.agent_id, cmd_id);
    sprintf (post_tunnelport_url,"%s/ca/agents/%s/commands/%lu/tunnelport",options.server_url, options.agent_id, cmd_id);

    if (options.debug)
        printf ("runCommand(%s,%d)\n",cmd,timeout);

    //block sigchld signals so it stays blocked on child (signal handler set in main())
    sigemptyset (&signal_set);
    sigaddset (&signal_set, SIGCHLD);
    if (sigprocmask (SIG_BLOCK, &signal_set, NULL) == -1) {
        sprintf (logmsg,"sigprocmask(block):%s",strerror (errno) );
        syslog (LOG_ERR,"%s",logmsg);
    }

    if (! (child_pid=fork () ) ) { //child
        char pname[64];
        struct rlimit limit;

        //signal(SIGCHLD, SIG_IGN);
        //no special handler for executed command
        if (cmd_type != 'P') {
            sa.sa_handler = SIG_IGN;
        }
        else if (cmd_type == 'P') { //allow popen to handle its child and return correct exit status on pclose()
            sa.sa_handler = SIG_DFL;
        }

        sigemptyset (&sa.sa_mask);
        sa.sa_flags = 0;
        if (sigaction (SIGCHLD, &sa, 0) == -1) {
            sprintf (logmsg,"sigaction (ign):%s",strerror (errno) );
            syslog (LOG_ERR,"%s",logmsg);
        }

        /* Do not leave core files */
        getrlimit (RLIMIT_CORE, &limit);
        limit.rlim_cur = 0;
        setrlimit (RLIMIT_CORE, &limit);

        mypid = getpid ();

        if (options.debug)
            printf ("[%lu]:Child %lu born, cmd:%s, timeout:%d, cmd_type:%c\n", 
                    mypid, child_pid, cmd, timeout, cmd_type);

        snprintf(pname, sizeof(pname),"restarter %c cmd %ld", cmd_type, cmd_id);
        //prctl(PR_SET_NAME, "Test");

        /* Plain popen no longer used since it lacks good status reporting, timeout, stderr */
        if (cmd_type=='C' || cmd_type=='P') { //exec
            int i=0;
            unsigned int len=0;
            char b[512];

            if (pipe (pipefd) == -1) {
                sprintf (logmsg,"pipe:%s",strerror (errno) );
                syslog (LOG_ERR,"%s",logmsg);
                return;
            }

            cmd_exitstatus=-9999;
            cmd_exitreason[0]=0;

            //signal handler, to get exit code of execed command

            sigemptyset (&sa.sa_mask);
            sa.sa_flags = 0;
            sa.sa_handler = sigchildhdl_GetExitStatus;
            if (sigaction (SIGCHLD, &sa, NULL) == -1) {
                sprintf (logmsg,"main:sigaction:%s",strerror (errno) );
                syslog (LOG_ERR,"%s",logmsg);
            }
            //block sigchld signals so it stays blocked on child
            sigemptyset (&signal_set);
            sigaddset (&signal_set, SIGCHLD);
            if (sigprocmask (SIG_BLOCK, &signal_set, NULL) == -1)  {
                sprintf (logmsg,"sigprocmask(block):%s",strerror (errno) );
                syslog (LOG_ERR,"%s",logmsg);
            }


            if (! (cmd_pid=fork () ) ) {
                //inside child, will be replaced by cmd via exec
                char *newcmd;

                sa.sa_handler = SIG_IGN;
                sigemptyset (&sa.sa_mask);
                sa.sa_flags = 0;
                if (sigaction (SIGCHLD, &sa, 0) == -1) {
                    sprintf (logmsg,"sigaction (ign):%s",strerror (errno) );
                    syslog (LOG_ERR,"%s",logmsg);
                }
                //signal(SIGCHLD, SIG_IGN);
                if (options.debug)
                    printf ("[%d]:Before exec command id:%ld\n", getpid(),cmd_id);

                newcmd=str_replace (cmd,"#ssh_client#","");

                i=0;
                while ( (dup2 (pipefd[1], 1) == -1) && (errno == EINTR) && i < 100) {
                    i++;
                }
                close (pipefd[0]); //close read-end of pipe
                dup2 (1, 2); // stderr->stdout

                if (cmd_type == 'C') {
                    makeargv (newcmd,args); //make argument vector from newcmd (newcmd gets nulls on delimiters)
                    if (execvp (args[0], args) == -1) {
                        snprintf (logmsg,sizeof(logmsg),"execvp:%s,command:%s",strerror (errno),cmd );
                        syslog (LOG_ERR,"%s",logmsg);
                        exit (errno);
                    }
                }
                else { // cmd_type == 'P'
                    for (i = strlen (newcmd) - 1; (!isalnum (newcmd[i]) ); i--) newcmd[i]=0; //rtrim
                    if (execl("/bin/sh", "sh", "-c", newcmd, (char *)0) == -1) {
                        snprintf (logmsg,sizeof(logmsg),"SHELL execvp:%s command:%s",strerror (errno),cmd );
                        /* exec in this case will always succeed unless /bin/sh is missing, 
                         * it's the shell not exec that returns the error */
                        syslog (LOG_ERR,"%s",logmsg);
                        exit (errno);
                    }
                }
                fprintf (stderr,"ERROR: how did we reach this\n");
                exit (-5555);
            }

            //unblock signal handler so we can get exit status
            sigemptyset (&signal_set);
            sigaddset (&signal_set, SIGCHLD);
            if (sigprocmask (SIG_UNBLOCK, &signal_set, NULL) == -1) {
                sprintf (logmsg,"sigprocmask(unblock):%s",strerror (errno) );
                syslog (LOG_ERR,"%s",logmsg);
            }

            //parent, waits for child's output and posts it
            signal (SIGALRM, sigalarm_CommandKiller);
            alarm (timeout);

            if (options.debug)
                printf ("[%d]:Added SIGALRM for %d seconds (should kill pid %d)\n", getpid(), timeout, cmd_pid);

            close (pipefd[1]); //close write-end of pipe

            if (options.debug)
                printf ("[%d]:Reading child %d output\n", getpid(), cmd_pid);

            buf[0]=b[0]=0;
            //read command output in chunks until buf is full
            message_chunk = 0;
            while ( (r=read (pipefd[0], b, sizeof (b)-1) ) != 0) {
                b[r]=0;
                message_chunk ++;
                len+=r;
                if (len>=sizeof (buf) ) {
                    sprintf (logmsg,
                             "[%d]: WARNING: readloop: command %ld output > sizeofbuf (%ld):truncated\n", getpid(), cmd_id, sizeof (buf) );
                    syslog (LOG_ERR,"%s",logmsg);
                    break;
                }
                strcat (buf,b);
                syslog (LOG_INFO,"%s:read chunk %d,  %s",cmd,message_chunk,b);

                if (options.debug) {
                    fprintf (stderr,"[%d]: readloop: (%s)",getpid(),b);
                }
            }
            close (pipefd[0]);

            if (options.debug) {
                fprintf (stderr,"[%d]: cmd_exitstatus:%d, cmd_exitreason:%s\n",getpid(), cmd_exitstatus, cmd_exitreason);
                fprintf (stderr,"[%d]: waiting for child handler to update exitstatus\n",getpid() );
            }

            // Wait a bit for SIGCHLD signal handler to update exitstatus variable for us to report to server
            while (cmd_exitstatus == -9999) {
                int sleepcount=0;
                sleep (1);
                if (sleepcount++ > 10) {
                    sprintf (logmsg,"[%d]: waited too much for exitstatus update, returning\n",getpid() );
                    syslog (LOG_WARNING,"%s",logmsg);
                }
            }

            if (options.debug) {
                fprintf (stderr,"[%d]: Done reading:[%s], cmd_exitstatus:%d, cmd_exitreason:%s\n",
                        getpid(), buf, cmd_exitstatus, cmd_exitreason);
                fprintf (stderr,"[%d]:Will now post on (%s)\n", getpid(), post_result_url);
            }

            fprintf(stderr,"restarter: output: %s\nExit status:%d Exit Reason%s\n", buf, cmd_exitstatus, cmd_exitreason) ;
            //sleep(5); //for TCP LINGER, now set inside a curl callback

            if (options.debug)
                fprintf (stderr,"[%d]:Done running\n", getpid() );

            exit (0);

        } //cmd==C || P
        exit (0);
    }
    else { // we are the  parent
        // unblock sigchld
        sigemptyset (&signal_set);
        sigaddset (&signal_set, SIGCHLD);
        if (sigprocmask (SIG_UNBLOCK, &signal_set, NULL) == -1)  {
            sprintf (logmsg,"sigprocmask(unblock):%s",strerror (errno) );
            syslog (LOG_WARNING,logmsg);
        }

        nchildren++;
        if (options.debug)
            printf ("[%d]:I have %d children\n", getpid(), nchildren);
    }
} // runCommand

/* argv is an array of pointers to buf parts
 * buf will be overwritten (spaces replaced with 0)
 */
void  makeargv (char *buf, char **argv) {
    while (*buf != '\0') {       /* if not the end of buf */
        while (*buf == ' ' || *buf == '\t' || *buf == '\n' || *buf == '\r' )
            *buf++ = '\0';     /* replace white spaces with 0    */
        *argv++ = buf;

        while (*buf != '\0' && *buf != ' ' &&
                *buf != '\t' && *buf != '\n' && *buf != '\r' )
            buf++;
    }
    *argv = '\0';
}

void showUsage() {
    printf ("\nCool Agent, remote execution client. (https://bitbucket.org/sivann/restarter)\n");
    printf ("Usage: restarter [-d] [-h] [-t timeout] [-c command]\n");
    printf ("\t-c [command]\tcommand to execute, include arguments in quotes. Mandatory.\n");
    printf ("\t-d\t\tdebug\n");
    printf ("\t-s\t\tuse a shell to execute command(s)\n");
    printf ("\t-t\t\ttimeout: terminate process after timeout seconds\n");
    printf("\n");
}


/* wait and set exit status in global var so it can be reported back (used by command executing process) */
void sigchildhdl_GetExitStatus (int sig) {
    int e, r;
    pid_t child_pid=0;

    while ( (r = waitpid (-1, &e, WNOHANG) ) > 0) {
        child_pid=r;
        //nchildren--;
        setWaitStatus (e);
        if (options.debug) {
            printf ("[%d]:sigchildhdl_GetExitStatus,waitpid: returned:%d, exit_reason:%s, nchildren now:%d\n", getpid(),r,cmd_exitreason,nchildren);
        }
    }

    if (child_pid == -1 && errno != ECHILD) {
        sprintf (logmsg,"[%d]:sigchildhdl_GetExitStatus,ERROR: waitpid: %s\n",getpid(),strerror (errno) );
        syslog (LOG_ERR,"%s",logmsg);
    }

    if (child_pid == cmd_pid) { //just to be sure
        cmd_exitstatus = e;
    }

    if (options.debug)
        printf ("[%d]:sigchildhdl_GetExitStatus,signal:%d, child_pid:%d, child exited status:%d, nchildren:%d\n",
                getpid (), sig, child_pid, e, nchildren);

    //signal (SIGCHLD, sigchildhdl_GetExitStatus);

}

/* just wait and count children (used by main process) */
void sigchildhdl_Count (int sig) {
    int e, r, child_pid=0;

    while ( (r = waitpid (-1, &e, WNOHANG) ) > 0) {
        child_pid=r;
        nchildren--;
    }

    if (options.debug)
        printf ("[%d]:sigchildhdl_Count(signal:%d), child_pid:%d exited with:%d, nchildren:%d\n",
                getpid (), sig, child_pid, e, nchildren);

    //signal (SIGCHLD, sigchildhdl_Count);

}


/* Examine a wait() status using the W* macros */
void setWaitStatus (int status) {
    char s[128];

    s[0]=0;

    if (WIFEXITED (status) ) {
        sprintf (s,"process exited, exit status=%d", WEXITSTATUS (status) );
    }
    else if (WIFSIGNALED (status) ) {
        sprintf (s,"process killed by signal %d (%s)", WTERMSIG (status), strsignal (WTERMSIG (status) ) );
        if (WCOREDUMP (status) )
            strcat (s," (core dumped)");
    }
    else if (WIFSTOPPED (status) ) {
        sprintf (s,"process stopped by signal %d (%s)", WSTOPSIG (status), strsignal (WSTOPSIG (status) ) );
    }
    else if (WIFCONTINUED (status) ) {
        sprintf (s,"process continued\n");
    }
    else {   /* Should never happen */
        sprintf (s,"what happened to this process? (exit status=%x)", (unsigned int) status);
    }
    strcpy (cmd_exitreason,s);
}



/* check of lock exists, and act
 * action == 0 : exit
 * action == 1 : replace previous lock-holding process: if lock is active kill pid in lockfile (restarter called with -f)
 */
void lock_or_act(char * lockfn, int action) {
    int ret,flags;
    char b[64];

    if ((lock_fd = open(lockfn, O_CREAT|O_RDWR|O_SYNC,S_IRUSR | S_IWUSR)) == -1) {
        perror("lock");
        exit(1);
    }


    //Prevent locks to be inherited on children. 
    //Old kernels do not support O_CLOEXEC flag in open()
    if ((flags = fcntl (lock_fd, F_GETFD, 0)) == -1) {
            sprintf (logmsg,"lock_or_act:fcntl:F_GETFD: %s",strerror (errno) );
            syslog (LOG_ERR,"%s",logmsg);
    }
    else {
        flags |= FD_CLOEXEC;
        if (fcntl (lock_fd, F_SETFD, flags) == -1 ) {
            sprintf (logmsg,"lock_or_act:fcntl:F_SETFD: %s",strerror (errno) );
            syslog (LOG_ERR,"%s",logmsg);
            if (action !=1) //better to ignore in this case
                exit(EXIT_FAILURE);
        }
    }

    //lock or fail
    if ((ret = lockf(lock_fd, F_TLOCK, 0)) == -1) {
        //could not lock, probably already locked

        if (action == 0) {
            sprintf(logmsg,"Another instance is running, %s is locked, exiting",lockfn);
            syslog (LOG_ERR,"%s",logmsg);
            exit(EXIT_FAILURE);
        }
        else { //kill running process and retry lock
            pid_t oldpid;
            int r;

            //if (!(fp = fdopen(lock_fd,"r"));
            r = read(lock_fd,b,63);
            b[r]=0;
            sscanf(b,"%d",&oldpid);
            sprintf(logmsg,"Another instance is running, %s is locked, killing with SIGTERM old pid %d",lockfn, oldpid);
            syslog (LOG_INFO,"%s",logmsg);
            if (kill(oldpid,0)) {
                sprintf(logmsg,"old pid %d disappeared before killing it",oldpid);
                syslog (LOG_INFO,"%s",logmsg);
            }
            else
                kill(oldpid,15);

            sleep (2);
            if (kill(oldpid,0)) {
                sprintf(logmsg,"old pid %d killed",oldpid);
                syslog (LOG_INFO,"%s",logmsg);
            }
            else
                kill(oldpid,9);

            sleep(1);

            //try to lock again
            if ((ret = lockf(lock_fd, F_TLOCK, 0)) == -1) {
                sprintf(logmsg,"failed to acquire lock, %s even after killing with SIGKILL pid %d",lockfn,oldpid);
                syslog (LOG_ERR,"%s",logmsg);
                exit(EXIT_FAILURE);
            }
        }
    }

    //lock succedded here

    //write our pid in the lockfile
    snprintf(b,64,"%d",getpid()) ;
    ftruncate(lock_fd, 0);
    lseek(lock_fd,0,SEEK_SET);
    write(lock_fd,b,strlen(b));
}


int restart(char **argv) {
    if (execvp(argv[0], argv)) {
        /* ERROR, handle this yourself */
        sprintf (logmsg,"restart:execvp:%s",strerror (errno) );
        syslog (LOG_ERR,"%s",logmsg);
        return -1;
    }

    return 0;
}

