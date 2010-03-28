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
#define MAXREQLEN  255

enum {
	GET  = 4,
	HEAD = 5,
};

typedef struct {
	const char *extension;
	const char *mimetype;
} MimeType;

static const char HttpOk[]           = "200 OK";
static const char HttpMoved[]        = "302 Moved Permanently";
static const char HttpUnauthorized[] = "401 Unauthorized";
static const char HttpNotFound[]     = "404 Not Found";
static const char texthtml[]         = "text/html";

static ssize_t writetext(const char *buf);
static ssize_t writedata(const char *buf, size_t buflen);
static void die(const char *errstr, ...);
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
static char name[128];
static char reqbuf[MAXREQLEN+1];
static char respbuf[1024];
static int fd, cfd, reqtype;

ssize_t
writedata(const char *buf, size_t buf_len) {
	ssize_t r, offset = 0;

	while(offset < buf_len) {
		if((r = write(cfd, buf + offset, buf_len - offset)) == -1) {
			fprintf(stderr, "%s: client %s closed connection\n", tstamp(), name);
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
	return writetext(respbuf);
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
	return writetext(respbuf);
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
	return writetext(respbuf);
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
	return writetext(respbuf);
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
		&& responsecontenttype(texthtml) != -1)
			;
		else
			return;
		if(reqtype == GET)
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
		if(reqtype == GET && writetext("\r\n") != -1)
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
	if(reqtype == GET) {
		if(writetext("\r\n<html><body><a href='..'>..</a><br>\r\n") == -1)
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
			if(writetext(respbuf) == -1)
				return;
		}
		writetext("</body></html>\r\n");
	}
}

void
responsedir(void) {
	ssize_t len = strlen(reqbuf);
	DIR *d;

	if((reqbuf[len - 1] != '/') && (len + 1 < MAXREQLEN)) {
		/* add directory terminator if necessary */
		reqbuf[len++] = '/';
		reqbuf[len] = 0;
		fprintf(stdout, "%s: redirecting %s to %s%s\n", tstamp(), name, location, reqbuf);
		if(responsehdr(HttpMoved) != -1
		&& responselocation(location, reqbuf) != -1
		&& responsecontenttype(texthtml) != -1)
			;
		else
			return;
		if(reqtype == GET)
			writetext("\r\n<html><body>301 Moved Permanently</a></body></html>\r\n");
		return;
	}
	if(len + strlen(docindex) + 1 < MAXREQLEN)
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
responsecgi(void) {
	FILE *cgi;
	int r;

	if(reqtype == GET)
		setenv("REQUEST_METHOD", "GET", 1);
	else if(reqtype == HEAD)
		setenv("REQUEST_METHOD", "HEAD", 1);
	else
		return;
	setenv("SERVER_NAME", servername, 1);
	setenv("SCRIPT_NAME", cgi_script, 1);
	setenv("REQUEST_URI", reqbuf, 1);
	chdir(cgi_dir);
	if((cgi = popen(cgi_script, "r"))) {
		if(responsehdr(HttpOk) == -1)
			return;
		while((r = fread(respbuf, 1, sizeof respbuf - 1, cgi)) > 0) {
			if(writedata(respbuf, r) == -1) {
				pclose(cgi);
				return;
			}
		}
		pclose(cgi);
	}
	else {
		fprintf(stderr, "%s: %s requests %s, but cannot run cgi script %s\n", tstamp(), name, cgi_script, reqbuf);
		if(responsehdr(HttpNotFound) != -1
		&& responsecontenttype(texthtml) != -1)
			;
		else
			return;
		if(reqtype == GET)
			writetext("\r\n<html><body>404 Not Found</body></html>\r\n");
	}
}

void
response(void) {
	char *p;
	struct stat st;

	for(p = reqbuf; *p; p++)
		if(*p == '\\' || *p == '?' || *p == '%' || *p == '&' || (*p == '/' && *(p + 1) == '.')) { /* don't serve bogus or hidden files */
			fprintf(stderr, "%s: %s requests bogus or hidden file %s\n", tstamp(), name, reqbuf);
			if(responsehdr(HttpUnauthorized) != -1
			&& responsecontenttype(texthtml) != -1)
				;
			else
				return;
			if(reqtype == GET)
				writetext("\r\n<html><body>401 Unauthorized</body></html>\r\n");
			return;
		}
	fprintf(stdout, "%s: %s requests: %s\n", tstamp(), name, reqbuf);
	if(cgi_mode)
		responsecgi();
	else {
		stat(reqbuf, &st);
		if(S_ISDIR(st.st_mode))
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

	do { /* MAXREQLEN byte of reqbuf is emergency 0 terminator */
		if((r = read(cfd, reqbuf + offset, MAXREQLEN - offset)) < 0) {
			fprintf(stderr, "%s: read: %s\n", tstamp(), strerror(errno));
			return -1;
		}
		offset += r;
		reqbuf[offset] = 0;
	}
	while(offset < MAXREQLEN && !strstr(reqbuf, "\r\n\r\n") && !strstr(reqbuf, "\n\n"));
	for(p = reqbuf; *p && *p != '\r' && *p != '\n'; p++);
	if(p >= reqbuf + MAXREQLEN)
		goto invalid_request;
	if(*p == '\r' || *p == '\n') {
		*p = 0;
		/* check command */
		if(!strncmp(reqbuf, "GET ", 4) && reqbuf[4] == '/')
			reqtype = GET;
		else if(!strncmp(reqbuf, "HEAD ", 5) && reqbuf[5] != '/')
			reqtype = HEAD;
		else
			goto invalid_request;
	}
	else
		goto invalid_request;
	/* determine path */
	for(res = reqbuf + reqtype; *res && *(res + 1) == '/'; res++); /* strip '/' */
	if(res >= reqbuf + MAXREQLEN)
		goto invalid_request;
	for(p = res; *p && *p != ' ' && *p != '\t'; p++);
	if(p >= reqbuf + MAXREQLEN)
		goto invalid_request;
	*p = 0;
	memmove(reqbuf, res, (p - res) + 1);
	return 0;
invalid_request:
	fprintf(stderr, "%s: %s performs invalid request %s\n", tstamp(), name, reqbuf);
	return -1;
}

void
serve(int fd) {
	int result;
	socklen_t salen;
	struct sockaddr sa;

	salen = sizeof sa;
	while(running) {
		if((cfd = accept(fd, &sa, &salen)) == -1) {
			/* el cheapo socket release */
			fprintf(stderr, "%s: cannot accept: %s, sleep a second...\n", tstamp(), strerror(errno));
			sleep(1);
			continue;
		}
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
		close(cfd);
	}
	fprintf(stdout, "%s: shutting down\n", tstamp());
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
		fprintf(stderr, "%s: received signal %s, closing down\n", tstamp(), signame[sig] ? signame[sig] : "");
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
		if(!strcmp(argv[i], "-n")) {
			if(++i < argc) servername = argv[i];
		}
		else if(!strcmp(argv[i], "-p")) {
			if(++i < argc) serverport = argv[i];
		}
		else if(!strcmp(argv[i], "-r")) {
			if(++i < argc) docroot = argv[i];
		}
		else if(!strcmp(argv[i], "-i")) {
			if(++i < argc) docindex = argv[i];
		}
		else if(!strcmp(argv[i], "-u")) {
			if(++i < argc) user = argv[i];
		}
		else if(!strcmp(argv[i], "-g")) {
			if(++i < argc) group = argv[i];
		}
		else if(!strcmp(argv[i], "-c")) {
			if(++i < argc) cgi_dir = argv[i];
			if(++i < argc) {
				cgi_script = argv[i];
				cgi_mode = 1;
			}
		}
		else if(!strcmp(argv[i], "-v"))
			die("quark-"VERSION", © 2009-2010 Anselm R Garbe\n");
		else
			die("\nusage: quark [-n <server-name>]\n"
			    "             [-p <port>]\n"
			    "             [-r <doc root>]\n"
			    "             [-i <doc index>]\n"
			    "             [-u <user>]\n"
			    "             [-g <group>]\n"
			    "             [-c <cgi dir> <cgi script>]\n"
			    "             [-v]\n");

	/* sanity checks */
	if(!(upwd = getpwnam(user)))
		die("error: invalid user %s\n", user);
	if(!(gpwd = getpwnam(group)))
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
