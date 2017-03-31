#Makefile for restarter

CC=gcc
CFLAGS=-I. -O2 -g -Wall -Wextra
EXECUTABLE=restarter

LIBS=-lcurl

UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)

ifeq ($(UNAME_S), Solaris)
LIBS=-lsocket -lnsl
endif

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

#PATH TO STATIC COMPILED LIBCURL and openssl for wstaticcurl target
# configure libcurl with --disable-sspi --disable-manual --disable-ldaps --disable-ldap --disable-rtsp --disable-pop3 --disable-imap --disable-smb --disable-gopher 
#LOCAL_CURL=/home/sivann/sbx/curl-7.50.0/
#LOCAL_SSL=/home/sivann/sbx/openssl-1.0.1t/
LOCAL_CURL=/usr/local/
LOCAL_SSL=/usr/local/ssl/

#wstaticcurl: LIBS=-lssh2 -ldl -lidn -lrt $(LOCAL_CURL)/lib/.libs/libcurl.a $(LOCAL_SSL)/libssl.a $(LOCAL_SSL)/libcrypto.a
wstaticcurl: LIBS=-lssh2 -lz -ldl -lidn -lrt $(LOCAL_CURL)/lib/libcurl.a $(LOCAL_SSL)/lib/libssl.a $(LOCAL_SSL)/lib/libcrypto.a
wstaticcurl: CFLAGS=-I. -O0 -g -Wall -Wextra -I $(LOCAL_CURL)/include/ -I$(LOCAL_SSL)/include
wstaticcurl: $(EXECUTABLE)

bindist: restarter
	echo $$PATH
	cp restarter bindist/$(UNAME_M)/
	restarter -v > bindist/$(UNAME_M)/restarter.version
