extern const char *gitversion;
extern const char *gitdate;
extern const char *compdate;
extern const char *sampleini;

#include <sys/utsname.h>
#include <stdlib.h>


struct MemoryStruct {
    char *buf;
    size_t size;
};

typedef struct {
    int debug;
    char* ssh_client;
    char* password_file;
    char cmd_type;
    int command_restart_period;
    int command_timeout;
    int syslog;
    int max_children;
    int run1;
} option_s;



/* function prototypes */
//void parseCmdAndAct(struct MemoryStruct * ms, char *argv[], int *want_registration, int *want_fullupdate);
void runCommand (char * cmd, char cmd_type, unsigned long cmd_id, int timeout) ;
static void sigchildhdl_Count (int);
static void sigchildhdl_GetExitStatus (int sig) ;
static void sigalarm_CommandKiller (int signum) ;
void usr2_handler(int sig);
void showUsage();
void showVersion();
void deepSleep(unsigned long int);
void  makeargv(char *buf, char **argv) ;
char *str_replace (const char *string, const char *substr, const char *replacement);
void setWaitStatus(int status) ;
void dump(const char *text, FILE *stream, unsigned char *ptr, size_t size);
int strlen_no_ws(char *str) ;
#ifndef __APPLE__
size_t strlcpy(char *dst, const char *src, size_t siz); /* like strncpy but always null-terminates */
size_t strlcat(char *dst, const char *src, size_t siz);
#endif
int ini_cb_handler (const char *section, const char *key, const char *value, void *userdata) ;
void getAdditionalInfo();
void lock_or_act(char * lockfn,int action);
int contains_chars(char * s, char * chars);
void str_replace_char_inline(char * s, char old, char new) ;
void update_agent(char **argv,char * arch, unsigned long int) ;
void mainloop();
int number_in_csv(int,char*);
