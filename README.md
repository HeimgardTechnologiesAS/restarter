# Readme
Command supervisor and restarter. Restarts a command on crash or exit. Logs command output and reports exit reason on syslog.
This is the part of the coolagent https://bitbucket.org/sivann/coolagent command execution.

```

Restarter. (https://bitbucket.org/sivann/restarter)
Usage: restarter [-d] [-h] [-t timeout] [-c command] [-p pid_file]
	-c [command]	command to execute, include arguments in quotes. Mandatory.
	-d		debug
	-s		use a shell to execute command(s)
	-t		timeout: terminate process after timeout seconds
	-l		syslog: redirect command stdout and stderr to syslog
	-m		multiple: keep multiple instances of process running
	-e		valid exit status: comma separated exit status which prevent restart
	-i		syslog ident string
	-p		write pid of new process to pid_file
	-1		start only if process specified by -p is not running

```
