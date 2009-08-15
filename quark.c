/* See LICENSE file for license details. */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define LENGTH(x)  (sizeof x / sizeof x[0])
#define MAXREQLEN  256

typedef struct {
	const char *extension;
	const char *mimetype;
} MimeType;

static const char HttpOk[]           = "200 OK";
static const char HttpMoved[]        = "302 Moved Permanently";
static const char HttpUnauthorized[] = "401 Unauthorized";
static const char HttpNotFound[]     = "404 Not Found";
static const char texthtml[]         = "text/html";

static ssize_t writedata(const char *buf);
static void die(const char *errstr, ...);
static void response(void);
static void responsedir(void);
static void responsedirdata(DIR *d);
static void responsefile(void);
static void responsefiledata(int fd, off_t size);
static int request(void);
static void serve(int fd);
static void sighandler(int sig);
static char *tstamp(void);

#include "config.h"

static char location[256];
static int running = 1;
static char name[128];
static char reqbuf[MAXREQLEN];
static char respbuf[1024];
static int fd, cfd;

ssize_t
writedata(const char *buf) {
	ssize_t r, offset = 0;
	size_t len = strlen(buf);

	while(offset < len) {
		if((r = write(cfd, buf + offset, len - offset)) == -1) {
			fprintf(stderr, "%s: client %s closed connection\n", tstamp(), name);
			return -1;
		}
		offset += r;
	}
	return offset;
}

void
logmsg(const char *errstr, ...) {
	va_list ap;

	fprintf(stdout, "%s: ", tstamp());
	va_start(ap, errstr);
	vfprintf(stdout, errstr, ap);
	va_end(ap);
}

void
logerrmsg(const char *errstr, ...) {
	va_list ap;

	fprintf(stderr, "%s: ", tstamp());
	va_start(ap, errstr);
	vfprintf(stderr, errstr, ap);
	va_end(ap);
}

void
die(const char *errstr, ...) {
	va_list ap;

	fprintf(stderr, "%s: ", tstamp());
	va_start(ap, errstr);
	vfprintf(stderr, errstr, ap);
	va_end(ap);
	exit(EXIT_FAILURE);
}

int
responsehdr(const char *status) {
	if(snprintf(respbuf, sizeof respbuf,
		"HTTP/1.1 %s\r\n"
		"Connection: close\r\n"
		"Date: %s\r\n"
		"Server: quark-"VERSION"\r\n",
		status, tstamp()) >= sizeof respbuf)
	{
		logerrmsg("snprintf failed, buffer size exceeded");
		return -1;
	}
	return writedata(respbuf);
}

int
responsecontentlen(off_t size) {
	if(snprintf(respbuf, sizeof respbuf,
		"Content-Length: %lu\r\n",
		size) >= sizeof respbuf)
	{
		logerrmsg("snprintf failed, buffer sizeof exceeded");
		return -1;
	}
	return writedata(respbuf);
}

int
responselocation(const char *location, const char *pathinfo) {
	if(snprintf(respbuf, sizeof respbuf,
		"Location: %s%s\r\n",
		location, pathinfo) >= sizeof respbuf)
	{
		logerrmsg("snprintf failed, buffer sizeof exceeded");
		return -1;
	}
	return writedata(respbuf);
}

int
responsecontenttype(const char *mimetype) {
	if(snprintf(respbuf, sizeof respbuf,
		"Content-Type: %s\r\n",
		mimetype) >= sizeof respbuf)
	{
		logerrmsg("snprintf failed, buffer sizeof exceeded");
		return -1;
	}
	return writedata(respbuf);
}

void
responsefiledata(int fd, off_t size) {
	off_t offset = 0;

	while(offset < size)
		if(sendfile(cfd, fd, &offset, size - offset) == -1) {
			fprintf(stderr, "%s: sendfile failed on client %s: %s\n", tstamp(), name, strerror(errno));
			return;
		}
}

void
responsefile(void) {
	const char *mimetype = "unknown";
	char *p;
	int i, ffd;
	struct stat st;

	stat(reqbuf, &st);
	if((ffd = open(reqbuf, O_RDONLY)) == -1) {
		fprintf(stderr, "%s: %s requests unknown path %s\n", tstamp(), name, reqbuf);
		if(responsehdr(HttpNotFound) != -1
		&& responsecontenttype(texthtml) != -1
		&& writedata("\r\n<html><body>404 Not Found</body></html>\r\n") != -1);
	}
	else {
		if((p = strrchr(reqbuf, '.'))) {
			p++;
			for(i = 0; i < LENGTH(servermimes); i++)
				if(!strcmp(servermimes[i].extension, p)) {
					mimetype = servermimes[i].mimetype;
					break;
				}
		}
		if(responsehdr(HttpOk) != -1
		&& responsecontentlen(st.st_size) != -1
		&& responsecontenttype(mimetype) != -1
		&& writedata("\r\n") != -1)
			responsefiledata(ffd, st.st_size);
		close(ffd);
	}
}

void
responsedirdata(DIR *d) {
	struct dirent *e;

	if(responsehdr(HttpOk) != -1
	&& responsecontenttype(texthtml) != -1
	&& writedata("\r\n<html><body><a href='..'>..</a><br>\r\n") != -1);
	else
		return;
	while((e = readdir(d))) {
		if(e->d_name[0] == '.') /* ignore hidden files, ., .. */
			continue;
		if(snprintf(respbuf, sizeof respbuf, "<a href='%s%s'>%s</a><br>\r\n",
		            reqbuf, e->d_name, e->d_name) >= sizeof respbuf)
		{
			logerrmsg("snprintf failed, buffer sizeof exceeded");
			return;
		}
		if(writedata(respbuf) == -1)
			return;
	}
	writedata("</body></html>\r\n");
}

void
responsedir(void) {
	ssize_t len = strlen(reqbuf);
	DIR *d;

	if((reqbuf[len - 1] != '/') && (len + 1 < MAXREQLEN - 1)) {
		/* add directory terminator if necessary */
		reqbuf[len++] = '/';
		reqbuf[len] = 0;
		fprintf(stdout, "%s: redirecting %s to %s%s\n", tstamp(), name, location, reqbuf);
		if(responsehdr(HttpMoved) != -1
		&& responselocation(location, reqbuf) != -1
		&& responsecontenttype(texthtml) != -1
		&& writedata("\r\n<html><body>301 Moved Permanently</a></body></html>\r\n") != -1);
		return;
	}
	if(len + strlen(docindex) + 1 < MAXREQLEN - 1)
		memcpy(reqbuf + len, docindex, strlen(docindex) + 1);
	if(access(reqbuf, R_OK) == -1) { /* directory mode */
		reqbuf[len] = 0; /* cut off docindex again */
		if((d = opendir(reqbuf))) {
			responsedirdata(d);
			closedir(d);
		}
	}
	else
		responsefile(); /* docindex */

}

void
response(void) {
	char *p;
	struct stat st;

	for(p = reqbuf; *p; p++)
		if(*p == '\\' || (*p == '/' && *(p + 1) == '.')) { /* don't serve bogus or hidden files */
			fprintf(stderr, "%s: %s requests bogus or hidden file %s\n", tstamp(), name, reqbuf);
			if(responsehdr(HttpUnauthorized) != -1
			&& responsecontenttype(texthtml) != -1
			&& writedata("\r\n<html><body>401 Unauthorized</body></html>\r\n") != -1);
			return;
		}
	fprintf(stdout, "%s: %s requests: %s\n", tstamp(), name, reqbuf);
	stat(reqbuf, &st);
	if(S_ISDIR(st.st_mode))
		responsedir();
	else
		responsefile();
}

int
request(void) {
	char *p, *res;
	int r, ishead = 0;

	if((r = read(cfd, reqbuf, (MAXREQLEN - 1))) < 0) {
		fprintf(stderr, "%s: read: %s\n", tstamp(), strerror(errno));
		return -1;
	}
	for(p = reqbuf; p < reqbuf + MAXREQLEN && *p != '\r' && *p != '\n'; p++);
	if(*p == '\r' || *p == '\n') {
		*p = 0;
		/* parse command */
		if(strncmp(reqbuf, "GET ", 4)) {
			fprintf(stderr, "%s: %s performs unsupported request %s\n", tstamp(), name, reqbuf);
			return -1;
		}
		if(reqbuf[4] != '/') {
			fprintf(stderr, "%s: %s performs invalid request %s\n", tstamp(), name, reqbuf);
			return -1;
		}
	}
	/* determine path */
	for(res = reqbuf + 4; *res && *(res + 1) == '/'; res++);
	for(p = res; *p && *p != ' '; p++);
	*p = 0;
	memmove(reqbuf, res, (p - res) + 1);
	return 0;
}

void
serve(int fd) {
	int result;
	socklen_t salen;
	struct sockaddr sa;

	salen = sizeof sa;
	while(running) {
		if((cfd = accept(fd, &sa, &salen)) == -1)
			break;
		if(fork() == 0) {
			close(fd);
			name[0] = 0;
			getnameinfo(&sa, salen, name, sizeof name,  NULL, 0, NI_NOFQDN);
			result = request();
			shutdown(cfd, SHUT_RD);
			if(result == 0)
				response();
			shutdown(cfd, SHUT_WR);
			close(cfd);
			exit(EXIT_SUCCESS);
		}
	}
	fprintf(stdout, "%s: shutting down\n", tstamp());
}

void
sighandler(int sig) {
	switch(sig) {
	default: break;
	case SIGHUP:
	case SIGINT:
	case SIGQUIT:
	case SIGABRT:
	case SIGTERM:
		close(fd);
		running = 0;
		break;
	case SIGCHLD:
		while(0 < waitpid(-1, NULL, WNOHANG));
		break;
	}
}

char *
tstamp(void) {
	static char res[25];
	time_t t = time(NULL);

	memcpy(res, asctime(gmtime(&t)), 24);
	res[24] = 0;
	return res;
}

int
main(int argc, char *argv[]) {
	struct addrinfo hints, *ai;
	struct passwd *upwd, *gpwd;
	int i;

	/* arguments */
	for(i = 1; i < argc; i++)
		if(!strcmp(argv[i], "-v"))
			die("quark-"VERSION", © 2009 Anselm R Garbe\n");
		else
			die("usage: quark [-v]\n");

	/* sanity checks */
	if(!(upwd = getpwnam(user)))
		die("error: invalid user %s\n", user);
	if(!(gpwd = getpwnam(group)))
		die("error: invalid group %s\n", group);

	/* init */
	setbuf(stdout, NULL); /* unbuffered stdout */
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;
	if((i = getaddrinfo(servername, serverport, &hints, &ai)))
		die("error: getaddrinfo: %s\n", gai_strerror(i));
	if((fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol)) == -1) {
		freeaddrinfo(ai);
		die("error: socket: %s\n", strerror(errno));
	}
	if(bind(fd, ai->ai_addr, ai->ai_addrlen) == -1) {
		close(fd);
		freeaddrinfo(ai);
		die("error: bind: %s\n", strerror(errno));
	}
	if(listen(fd, SOMAXCONN) == -1) {
		close(fd);
		freeaddrinfo(ai);
		die("error: listen: %s\n", strerror(errno));
	}

	if(!strcmp(serverport, "80"))
		i = snprintf(location, sizeof location, "http://%s", servername);
	else
		i = snprintf(location, sizeof location, "http://%s:%s", servername, serverport);
	if(i >= sizeof location) {
		close(fd);
		freeaddrinfo(ai);
		die("error: location too long\n");
	}

	signal(SIGCHLD, sighandler);
	signal(SIGHUP, sighandler);
	signal(SIGINT, sighandler);
	signal(SIGQUIT, sighandler);
	signal(SIGABRT, sighandler);
	signal(SIGTERM, sighandler);
	signal(SIGKILL, sighandler);

	if(chroot(docroot) == -1)
		die("error: chroot %s: %s\n", docroot, strerror(errno));

	if(setgid(gpwd->pw_gid) == -1)
		die("error: cannot set group id\n");
	if(setuid(upwd->pw_uid) == -1)
		die("error: cannot set user id\n");

	if(getuid() == 0)
		die("error: won't run with root permissions, choose another user\n");
	if(getgid() == 0)
		die("error: won't run with root permissions, choose another group\n");

	fprintf(stdout, "%s: listening on %s:%s using %s as root directory\n", tstamp(), servername, serverport, docroot);

	serve(fd); /* main loop */
	freeaddrinfo(ai);
	return 0;
}
