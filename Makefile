#Makefile for restarter

CC=gcc
CFLAGS=-I. -O2 -g -Wall -Wextra
EXECUTABLE=restarter

UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)


OBJECTS=$(SOURCES:%.c=%.o) #substitution reference
SOURCES=restarter.c helpers.c strl.c #version.c http.c
PATH:=.:$(PATH)

all: $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS) Makefile
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@ $(LIBS)

version.c: ../.git/HEAD ../.git/index Makefile
	echo "const char *gitversion = \"$(shell git describe --abbrev=6 --always --tags)\";" > $@
# echo "const char *gitdate = \"$(shell git log -1 --format=%ad --date=iso8601-strict)\";" >> $@
	echo "const char *gitdate = \"$(shell git log -1 --format=%ad --date=iso8601|sed -e 's/ /T/' -e 's/ //')\";" >> $@ #iso8601-strict needs newer git
	echo "const char *compdate = \"$(shell date --iso-8601=minutes)\";" >> $@

%.o: %.c %.h
	$(CC) -c $(CFLAGS) $(LIBS) $< -o $@

clean:  
	rm -f restarter core *.o

bindist: restarter
	echo $$PATH
	cp restarter bindist/$(UNAME_M)/
	restarter -v > bindist/$(UNAME_M)/restarter.version

install: restarter
	install -d $(DESTDIR)$(PREFIX)/bin/
	install -m 0755 restarter $(DESTDIR)$(PREFIX)/bin/
