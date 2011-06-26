/* See LICENSE file for license details. */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pwd.h>
#include <grp.h>
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
#define MAXBUFLEN  1024

enum {
	GET  = 4,
	HEAD = 5,
};

typedef struct {
	const char *extension;
	const char *mimetype;
} MimeType;

typedef struct _Param Param;
struct _Param {
	const char *key;
	const char *value;
	Param *next;
};

typedef struct {
	int type;
	int fd;
	const char *hostname;
	const char *resource;
	Param *params;
} Request;

typedef struct {
	const char *hostname;
	const char *resource;
	void (*handle)(const Request *r);
} RequestHandler;

static const char HttpOk[]           = "200 OK";
static const char HttpMoved[]        = "302 Moved Permanently";
static const char HttpUnauthorized[] = "401 Unauthorized";
static const char HttpNotFound[]     = "404 Not Found";
static const char texthtml[]         = "text/html";

static ssize_t writetext(const char *buf);
static ssize_t writedata(const char *buf, size_t buflen);
static void atomiclog(int fd, const char *errstr, va_list ap);
static void die(const char *errstr, ...);
static void logmsg(const char *errstr, ...);
static void logerrmsg(const char *errstr, ...);
static void response(void);
static void responsecgi(void);
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
static char host[NI_MAXHOST];
static char reqbuf[MAXBUFLEN+1];
static char resbuf[MAXBUFLEN+1];
static char reqhost[256];
static int fd;
static Request req;

ssize_t
writedata(const char *buf, size_t buf_len) {
	ssize_t r, offset = 0;

	while(offset < buf_len) {
		if((r = write(req.fd, buf + offset, buf_len - offset)) == -1) {
			logerrmsg("client %s closed connection\n", host);
			return -1;
		}
		offset += r;
	}
	return offset;
}

ssize_t
writetext(const char *buf) {
	return writedata(buf, strlen(buf));
}

void
atomiclog(int fd, const char *errstr, va_list ap) {
	static char buf[512];
	int n;

	/*
	assemble the message in buf and write it in one pass
	to avoid interleaved concurrent writes on a shared fd.
	*/
	n = snprintf(buf, sizeof buf, "%s: ", tstamp());
	n += vsnprintf(buf + n, sizeof buf - n, errstr, ap);
	if (n >= sizeof buf)
		n = sizeof buf - 1;
	write(fd, buf, n);
}

void
logmsg(const char *errstr, ...) {
	va_list ap;

	va_start(ap, errstr);
	atomiclog(STDOUT_FILENO, errstr, ap);
	va_end(ap);
}

void
logerrmsg(const char *errstr, ...) {
	va_list ap;

	va_start(ap, errstr);
	atomiclog(STDERR_FILENO, errstr, ap);
	va_end(ap);
}

void
die(const char *errstr, ...) {
	va_list ap;

	va_start(ap, errstr);
	atomiclog(STDERR_FILENO, errstr, ap);
	va_end(ap);
	exit(EXIT_FAILURE);
}

int
responsehdr(const char *status) {
	if(snprintf(resbuf, MAXBUFLEN,
		"HTTP/1.1 %s\r\n"
		"Connection: close\r\n"
		"Date: %s\r\n"
		"Server: quark-"VERSION"\r\n",
		status, tstamp()) >= MAXBUFLEN)
	{
		logerrmsg("snprintf failed, buffer size exceeded");
		return -1;
	}
	return writetext(resbuf);
}

int
responsecontentlen(off_t size) {
	if(snprintf(resbuf, MAXBUFLEN,
		"Content-Length: %lu\r\n",
		size) >= MAXBUFLEN)
	{
		logerrmsg("snprintf failed, buffer sizeof exceeded");
		return -1;
	}
	return writetext(resbuf);
}

int
responselocation(const char *location, const char *pathinfo) {
	if(snprintf(resbuf, MAXBUFLEN,
		"Location: %s%s\r\n",
		location, pathinfo) >= MAXBUFLEN)
	{
		logerrmsg("snprintf failed, buffer sizeof exceeded");
		return -1;
	}
	return writetext(resbuf);
}

int
responsecontenttype(const char *mimetype) {
	if(snprintf(resbuf, MAXBUFLEN,
		"Content-Type: %s\r\n",
		mimetype) >= MAXBUFLEN)
	{
		logerrmsg("snprintf failed, buffer sizeof exceeded");
		return -1;
	}
	return writetext(resbuf);
}

void
responsefiledata(int fd, off_t size) {
	off_t offset = 0;

	while(offset < size)
		if(sendfile(req.fd, fd, &offset, size - offset) == -1) {
			logerrmsg("sendfile failed on client %s: %s\n", host, strerror(errno));
			return;
		}
}

void
responsefile(void) {
	const char *mimetype = "unknown";
	char *p;
	int i, ffd;
	struct stat st;

	if(stat(reqbuf, &st) == -1 || (ffd = open(reqbuf, O_RDONLY)) == -1) {
		logerrmsg("%s requests unknown path %s\n", host, reqbuf);
		if(responsehdr(HttpNotFound) != -1
		&& responsecontenttype(texthtml) != -1)
			;
		else
			return;
		if(req.type == GET)
			writetext("\r\n<html><body>404 Not Found</body></html>\r\n");
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
		&& responsecontenttype(mimetype) != -1)
			;
		else
			return;
		if(req.type == GET && writetext("\r\n") != -1)
			responsefiledata(ffd, st.st_size);
		close(ffd);
	}
}

void
responsedirdata(DIR *d) {
	struct dirent *e;

	if(responsehdr(HttpOk) != -1
	&& responsecontenttype(texthtml) != -1)
		;
	else
		return;
	if(req.type == GET) {
		if(writetext("\r\n<html><body><a href='..'>..</a><br>\r\n") == -1)
			return;
		while((e = readdir(d))) {
			if(e->d_name[0] == '.') /* ignore hidden files, ., .. */
				continue;
			if(snprintf(resbuf, MAXBUFLEN, "<a href='%s%s'>%s</a><br>\r\n",
				    reqbuf, e->d_name, e->d_name) >= MAXBUFLEN)
			{
				logerrmsg("snprintf failed, buffer sizeof exceeded");
				return;
			}
			if(writetext(resbuf) == -1)
				return;
		}
		writetext("</body></html>\r\n");
	}
}

void
responsedir(void) {
	ssize_t len = strlen(reqbuf);
	DIR *d;

	if((reqbuf[len - 1] != '/') && (len + 1 < MAXBUFLEN)) {
		/* add directory terminator if necessary */
		reqbuf[len++] = '/';
		reqbuf[len] = 0;
		logmsg("redirecting %s to %s%s\n", host, location, reqbuf);
		if(responsehdr(HttpMoved) != -1
		&& responselocation(location, reqbuf) != -1
		&& responsecontenttype(texthtml) != -1)
			;
		else
			return;
		if(req.type == GET)
			writetext("\r\n<html><body>301 Moved Permanently</a></body></html>\r\n");
		return;
	}
	if(len + strlen(docindex) + 1 < MAXBUFLEN)
		memcpy(reqbuf + len, docindex, strlen(docindex) + 1);
	if(access(reqbuf, R_OK) == -1) { /* directory mode */
		reqbuf[len] = 0; /* cut off docindex again */
		if((d = opendir(reqbuf))) {
			responsedirdata(d);
			closedir(d);
		}
		else
			logerrmsg("client %s requests %s but opendir failed: %s\n", host, reqbuf, strerror(errno));
	}
	else
		responsefile(); /* docindex */
}

void
responsecgi(void) {
	FILE *cgi;
	int r;

	if(req.type == GET)
		setenv("REQUEST_METHOD", "GET", 1);
	else if(req.type == HEAD)
		setenv("REQUEST_METHOD", "HEAD", 1);
	else
		return;
	if(*reqhost)
		setenv("SERVER_NAME", reqhost, 1);
	setenv("SCRIPT_NAME", cgi_script, 1);
	setenv("REQUEST_URI", reqbuf, 1);
	logmsg("CGI SERVER_NAME=%s SCRIPT_NAME=%s REQUEST_URI=%s\n", reqhost, cgi_script, reqbuf);
	if(chdir(cgi_dir) == -1)
		logerrmsg("chdir to cgi directory %s failed: %s\n", cgi_dir, strerror(errno));
	if((cgi = popen(cgi_script, "r"))) {
		if(responsehdr(HttpOk) == -1)
			return;
		while((r = fread(resbuf, 1, MAXBUFLEN, cgi)) > 0) {
			if(writedata(resbuf, r) == -1) {
				pclose(cgi);
				return;
			}
		}
		pclose(cgi);
	}
	else {
		logerrmsg("%s requests %s, but cannot run cgi script %s\n", host, cgi_script, reqbuf);
		if(responsehdr(HttpNotFound) != -1
		&& responsecontenttype(texthtml) != -1)
			;
		else
			return;
		if(req.type == GET)
			writetext("\r\n<html><body>404 Not Found</body></html>\r\n");
	}
}

void
response(void) {
	char *p;
	struct stat st;

	for(p = reqbuf; *p; p++)
		if(*p == '\\' || (*p == '/' && *(p + 1) == '.')) { /* don't serve bogus or hidden files */
			logerrmsg("%s requests bogus or hidden file %s\n", host, reqbuf);
			if(responsehdr(HttpUnauthorized) != -1
			&& responsecontenttype(texthtml) != -1)
				;
			else
				return;
			if(req.type == GET)
				writetext("\r\n<html><body>401 Unauthorized</body></html>\r\n");
			return;
		}
	logmsg("%s requests: %s\n", host, reqbuf);
	if(cgi_mode)
		responsecgi();
	else {
		if(stat(reqbuf, &st) != -1 && S_ISDIR(st.st_mode))
			responsedir();
		else
			responsefile();
	}
}

int
request(void) {
	char *p, *res;
	int r;
	size_t offset = 0;

	do { /* MAXBUFLEN byte of reqbuf is emergency 0 terminator */
		if((r = read(req.fd, reqbuf + offset, MAXBUFLEN - offset)) == -1) {
			logerrmsg("read: %s\n", strerror(errno));
			return -1;
		}
		offset += r;
		reqbuf[offset] = 0;
	}
	while(r > 0 && offset < MAXBUFLEN && (!strstr(reqbuf, "\r\n") || !strstr(reqbuf, "\n")));
	if((res = strstr(reqbuf, "Host:"))) {
		for(res = res + 5; *res && (*res == ' ' || *res == '\t'); res++);
		if(!*res)
			goto invalid_request;
		for(p = res; *p && *p != ' ' && *p != '\t' && *p != '\r' && *p != '\n'; p++);
		if(!*p)
			goto invalid_request;
		*p = 0;
		if(p - res > sizeof reqhost)
			goto invalid_request;
		memcpy(reqhost, res, p - res);
		reqhost[p - res] = 0;
	}
	for(p = reqbuf; *p && *p != '\r' && *p != '\n'; p++);
	if(*p == '\r' || *p == '\n') {
		*p = 0;
		/* check command */
		if(!strncmp(reqbuf, "GET ", 4) && reqbuf[4] == '/')
			req.type = GET;
		else if(!strncmp(reqbuf, "HEAD ", 5) && reqbuf[5] == '/')
			req.type = HEAD;
		else
			goto invalid_request;
	}
	else
		goto invalid_request;
	/* determine path */
	for(res = reqbuf + req.type; *res && *(res + 1) == '/'; res++); /* strip '/' */
	if(!*res)
		goto invalid_request;
	for(p = res; *p && *p != ' ' && *p != '\t'; p++);
	if(!*p)
		goto invalid_request;
	*p = 0;
	memmove(reqbuf, res, (p - res) + 1);
	return 0;
invalid_request:
	logerrmsg("%s performs invalid request %s\n", host, reqbuf);
	return -1;
}

void
serve(int fd) {
	int result;
	socklen_t salen;
	struct sockaddr sa;

	while(running) {
		salen = sizeof sa;
		if((req.fd = accept(fd, &sa, &salen)) == -1) {
			/* el cheapo socket release */
			logerrmsg("cannot accept: %s, sleep a second...\n", strerror(errno));
			sleep(1);
			continue;
		}
		result = fork();
		if(result == 0) {
			close(fd);
			host[0] = 0;
			getnameinfo(&sa, salen, host, sizeof host, NULL, 0, NI_NOFQDN);
			result = request();
			shutdown(req.fd, SHUT_RD);
			if(result == 0)
				response();
			shutdown(req.fd, SHUT_WR);
			close(req.fd);
			exit(EXIT_SUCCESS);
		} else if (result == -1)
			logerrmsg("fork failed: %s\n", strerror(errno));
		close(req.fd);
	}
	logmsg("shutting down\n");
}

void
sighandler(int sig) {
	static const char *signame[64] = {
		[SIGHUP] = "SIGHUP",
		[SIGINT] = "SIGINT",
		[SIGQUIT] = "SIGQUIT",
		[SIGABRT] = "SIGABRT",
		[SIGTERM] = "SIGTERM",
		[SIGCHLD] = "SIGCHLD"
	};
	switch(sig) {
	default: break;
	case SIGHUP:
	case SIGINT:
	case SIGQUIT:
	case SIGABRT:
	case SIGTERM:
		logerrmsg("received signal %s, closing down\n", signame[sig] ? signame[sig] : "");
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
	struct passwd *upwd;
	struct group *gpwd;
	int i;

	/* arguments */
	for(i = 1; i < argc; i++)
		if(!strcmp(argv[i], "-v"))
			die("quark-"VERSION", © 2009-2011 Anselm R Garbe\n");
		else
			die("usage: quark [-v]\n");

	/* sanity checks */
	if(user)
		if(!(upwd = getpwnam(user)))
			die("error: invalid user %s\n", user);
	if(group)
		if(!(gpwd = getgrnam(group)))
			die("error: invalid group %s\n", group);

	signal(SIGCHLD, sighandler);
	signal(SIGHUP, sighandler);
	signal(SIGINT, sighandler);
	signal(SIGQUIT, sighandler);
	signal(SIGABRT, sighandler);
	signal(SIGTERM, sighandler);
	signal(SIGKILL, sighandler);

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

	if(chdir(docroot) == -1)
		die("error: chdir %s: %s\n", docroot, strerror(errno));
	if(chroot(".") == -1)
		die("error: chroot .: %s\n", strerror(errno));

	if(gpwd)
		if(setgid(gpwd->gr_gid) == -1)
			die("error: cannot set group id\n");
	if(upwd)
		if(setuid(upwd->pw_uid) == -1)
			die("error: cannot set user id\n");

	if(getuid() == 0)
		die("error: won't run with root permissions, choose another user\n");
	if(getgid() == 0)
		die("error: won't run with root permissions, choose another group\n");

	logmsg("listening on %s:%s using %s as root directory\n", servername, serverport, docroot);

	serve(fd); /* main loop */
	freeaddrinfo(ai);
	return 0;
}
