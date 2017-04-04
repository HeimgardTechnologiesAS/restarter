#ifndef __COOLAGENT_H
#define __COOLAGENT_H
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
    char* agent_id;
    char* agent_id_enc;
    char* server_url;
    char* ssh_client;
    char* password_file;
    char cmd_type;
    int command_restart_period;
    int command_timeout;
    int syslog;
    int max_children;
} option_s;



/* function prototypes */
//void parseCmdAndAct(struct MemoryStruct * ms, char *argv[], int *want_registration, int *want_fullupdate);
void runCommand (char * cmd, char cmd_type, unsigned long cmd_id, int timeout) ;
void sigchildhdl_Count (int);
void sigchildhdl_GetExitStatus (int sig) ;
void sigalarm_CommandKiller (int signum) ;
void showUsage();
void showVersion();
void deepSleep(unsigned long int);
void  makeargv(char *buf, char **argv) ;
char *str_replace (const char *string, const char *substr, const char *replacement);
void setWaitStatus(int status) ;
void dump(const char *text, FILE *stream, unsigned char *ptr, size_t size);
int strlen_no_ws(char *str) ;
size_t strlcpy(char *dst, const char *src, size_t siz); /* like strncpy but always null-terminates */
size_t strlcat(char *dst, const char *src, size_t siz);
int ini_cb_handler (const char *section, const char *key, const char *value, void *userdata) ;
void getAdditionalInfo();
void lock_or_act(char * lockfn,int action);
int contains_chars(char * s, char * chars);
void str_replace_char_inline(char * s, char old, char new) ;
void update_agent(char **argv,char * arch, unsigned long int) ;
int restart(char **argv);
void mainloop();

#endif
