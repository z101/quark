/* See LICENSE file for license details. */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <netdb.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include "arg.h"
char *argv0;

#define LENGTH(x)  (sizeof x / sizeof x[0])
#define MAXBUFLEN  1024
#define MIN(x,y)   ((x) < (y) ? (x) : (y))

enum {
	GET  = 4,
	HEAD = 5,
};

typedef struct {
	const char *extension;
	const char *mimetype;
} MimeType;

typedef struct {
	int type;
	int fd;
} Request;

static const char HttpOk[]           = "200 OK";
static const char HttpMoved[]        = "301 Moved Permanently";
static const char HttpNotModified[]  = "304 Not Modified";
static const char HttpUnauthorized[] = "401 Unauthorized";
static const char HttpNotFound[]     = "404 Not Found";
static const char texthtml[]         = "text/html";

enum {
	HEADER,
	CONTENTLEN,
	LOCATION,
	CONTENTTYPE,
	MODIFIED
};

static const char *resentry[] = {
	[HEADER]      = "HTTP/1.1 %s\r\nConnection: close\r\nDate: %s\r\nServer: quark-"VERSION"\r\n",
	[CONTENTLEN]  = "Content-Length: %lu\r\n",
	[LOCATION]    = "Location: %s%s\r\n",
	[CONTENTTYPE] = "Content-Type: %s\r\n",
	[MODIFIED]    = "Last-Modified: %s\r\n"
};

static ssize_t writetext(const char *buf);
static ssize_t writedata(const char *buf, size_t buflen);
static void atomiclog(int fd, const char *errstr, va_list ap);
static void logmsg(const char *errstr, ...);
static void logerrmsg(const char *errstr, ...);
static void die(const char *errstr, ...);
static int putresentry(int type, ...);
static void response(void);
static void responsecgi(void);
static void responsedir(void);
static void responsedirdata(DIR *d);
static void responsefile(void);
static void responsefiledata(int fd, off_t size);
static int getreqentry(char *name, char *target, size_t targetlen, char *breakchars);
static int request(void);
static void serve(int fd);
static void sighandler(int sig);
static char *tstamp(void);

#include "config.h"

static char location[256];
static int running = 1;
static int status;
static char host[NI_MAXHOST];
static char reqbuf[MAXBUFLEN+1];
static char resbuf[MAXBUFLEN+1];
static char reqhost[256];
static char reqmod[256];
static int fd;
static Request req;

ssize_t
writedata(const char *buf, size_t buf_len) {
	ssize_t r, offset;

	for (offset = 0; offset < buf_len; offset += r) {
		if ((r = write(req.fd, buf + offset, buf_len - offset)) == -1) {
			logerrmsg("client %s closed connection\n", host);
			return 1;
		}
	}
	return 0;
}

ssize_t
writetext(const char *buf) {
	return writedata(buf, strlen(buf));
}

void
atomiclog(int fd, const char *errstr, va_list ap) {
	static char buf[512];
	int n;

	/* assemble the message in buf and write it in one pass
	   to avoid interleaved concurrent writes on a shared fd. */
	n = snprintf(buf, sizeof buf, "%s\t", tstamp());
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
putresentry(int type, ...) {
	va_list ap;

	va_start(ap, type);
	if (vsnprintf(resbuf, MAXBUFLEN, resentry[type], ap) >= MAXBUFLEN) {
		logerrmsg("vsnprintf failed, buffer size exceeded");
		return -1;
	}
	va_end(ap);
	return writetext(resbuf);
}

void
responsefiledata(int fd, off_t size) {
	char buf[BUFSIZ];
	ssize_t n;

	for (; (n = read(fd, buf, MIN(size, sizeof buf))) > 0; size -= n)
		if (write(req.fd, buf, n) != n)
			logerrmsg("error writing to client %s at %ls: %s\n", host, n, strerror(errno));
	if (n == -1)
		logerrmsg("error reading from file: %s\n", strerror(errno));
}

void
responsefile(void) {
	const char *mimetype;
	char *p;
	char mod[25];
	int i, ffd, r;
	struct stat st;
	time_t t;

	if ((r = stat(reqbuf, &st)) == -1 || (ffd = open(reqbuf, O_RDONLY)) == -1) {
		/* file not found */
		if (putresentry(HEADER, HttpNotFound, tstamp())
		 || putresentry(CONTENTTYPE, texthtml))
			return;
		status = 404;
		if (req.type == GET)
			writetext("\r\n<html><body>404 Not Found</body></html>\r\n");
	} else {
		/* check if modified */
		t = st.st_mtim.tv_sec;
		memcpy(mod, asctime(gmtime(&t)), 24);
		mod[24] = 0;
		if (!strcmp(reqmod, mod) && !putresentry(HEADER, HttpNotModified, tstamp())) {
			/* not modified, we're done here*/
			status = 304;
		} else {
			/* determine mime-type */
			if ((p = strrchr(reqbuf, '.'))) {
				p++;
				for (i = 0; i < LENGTH(servermimes); i++)
					if (!strcmp(servermimes[i].extension, p)) {
						mimetype = servermimes[i].mimetype;
						break;
					}
			}
			/* serve file */
			if (putresentry(HEADER, HttpOk, tstamp())
			 || putresentry(MODIFIED, mod)
			 || putresentry(CONTENTLEN, st.st_size)
			 || putresentry(CONTENTTYPE, mimetype))
				return;
			status = 200;
			if (req.type == GET && !writetext("\r\n"))
				responsefiledata(ffd, st.st_size);
		}
		close(ffd);
	}
}

void
responsedirdata(DIR *d) {
	struct dirent *e;

	if (putresentry(HEADER, HttpOk, tstamp())
	 || putresentry(CONTENTTYPE, texthtml))
		return;
	status = 200;
	if (req.type == GET) {
		if (writetext("\r\n<html><body><a href='..'>..</a><br>\r\n"))
			return;
		while ((e = readdir(d))) {
			if (e->d_name[0] == '.') /* ignore hidden files, ., .. */
				continue;
			if (snprintf(resbuf, MAXBUFLEN, "<a href='%s%s'>%s</a><br>\r\n",
				     reqbuf, e->d_name, e->d_name) >= MAXBUFLEN)
			{
				logerrmsg("snprintf failed, buffer sizeof exceeded");
				return;
			}
			if (writetext(resbuf))
				return;
		}
		writetext("</body></html>\r\n");
	}
}

void
responsedir(void) {
	ssize_t len = strlen(reqbuf);
	DIR *d;

	if ((reqbuf[len - 1] != '/') && (len + 1 < MAXBUFLEN)) {
		/* add directory terminator if necessary */
		reqbuf[len] = '/';
		reqbuf[len + 1] = 0;
		if (putresentry(HEADER, HttpMoved, tstamp())
		 || putresentry(LOCATION, location, reqbuf)
		 || putresentry(CONTENTTYPE, texthtml))
			return;
		status = 301;
		reqbuf[len] = 0;
		if (req.type == GET)
			writetext("\r\n<html><body>301 Moved Permanently</a></body></html>\r\n");
		return;
	}
	if (len + strlen(docindex) + 1 < MAXBUFLEN)
		memcpy(reqbuf + len, docindex, strlen(docindex) + 1);
	if (access(reqbuf, R_OK) == -1) { /* directory mode */
		reqbuf[len] = 0; /* cut off docindex again */
		if ((d = opendir(reqbuf))) {
			responsedirdata(d);
			closedir(d);
		} else {
			logerrmsg("client %s requests %s but opendir failed: %s\n", host, reqbuf, strerror(errno));
		}
	} else {
		responsefile(); /* docindex */
	}
}

void
responsecgi(void) {
	FILE *cgi;
	int r;

	if (req.type == GET)
		setenv("REQUEST_METHOD", "GET", 1);
	else if (req.type == HEAD)
		setenv("REQUEST_METHOD", "HEAD", 1);
	else
		return;
	if (*reqhost)
		setenv("SERVER_NAME", reqhost, 1);
	setenv("SCRIPT_NAME", cgi_script, 1);
	setenv("REQUEST_URI", reqbuf, 1);
	logmsg("CGI SERVER_NAME=%s SCRIPT_NAME=%s REQUEST_URI=%s\n", reqhost, cgi_script, reqbuf);
	if (chdir(cgi_dir) == -1)
		logerrmsg("error\tchdir to cgi directory %s failed: %s\n", cgi_dir, strerror(errno));
	if ((cgi = popen(cgi_script, "r"))) {
		if (putresentry(HEADER, HttpOk, tstamp()))
			return;
		status = 200;
		while ((r = fread(resbuf, 1, MAXBUFLEN, cgi)) > 0) {
			if (writedata(resbuf, r)) {
				pclose(cgi);
				return;
			}
		}
		pclose(cgi);
	} else {
		logerrmsg("error\t%s requests %s, but cannot run cgi script %s\n", host, cgi_script, reqbuf);
		if (putresentry(HEADER, HttpNotFound, tstamp())
		 || putresentry(CONTENTTYPE, texthtml))
			return;
		status = 404;
		if (req.type == GET)
			writetext("\r\n<html><body>404 Not Found</body></html>\r\n");
	}
}

void
response(void) {
	char *p;
	struct stat st;

	for (p = reqbuf; *p; p++)
		if (*p == '\\' || (*p == '/' && *(p + 1) == '.')) { /* don't serve bogus or hidden files */
			if (putresentry(HEADER, HttpUnauthorized, tstamp())
			 || putresentry(CONTENTTYPE, texthtml))
				return;
			status = 401;
			if (req.type == GET)
				writetext("\r\n<html><body>401 Unauthorized</body></html>\r\n");
			return;
		}
	if (cgi_mode) {
		responsecgi();
	} else {
		if (stat(reqbuf, &st) != -1 && S_ISDIR(st.st_mode))
			responsedir();
		else
			responsefile();
	}
}

int
getreqentry(char *name, char *target, size_t targetlen, char *breakchars) {
	char *p, *res;

	if ((res = strstr(reqbuf, name))) {
		for (res = res + strlen(name); *res && (*res == ' ' || *res == '\t'); ++res);
		if (!*res)
			return 1;
		for (p = res; *p && !strchr(breakchars, *p); ++p);
		if (!*p)
			return 1;
		if ((size_t)(p - res) >= targetlen)
			return 1;
		memcpy(target, res, p - res);
		target[p - res] = 0;
		return 0;
	}
	return -1;
}

int
request(void) {
	char *p, *res;
	int r;
	size_t offset = 0;

	/* read request into reqbuf (MAXBUFLEN byte of reqbuf is emergency 0 terminator */
	for (; r > 0 && offset < MAXBUFLEN && (!strstr(reqbuf, "\r\n") || !strstr(reqbuf, "\n"));) {
		if ((r = read(req.fd, reqbuf + offset, MAXBUFLEN - offset)) == -1) {
			logerrmsg("error\tread: %s\n", strerror(errno));
			return -1;
		}
		offset += r;
		reqbuf[offset] = 0;
	}

	/* extract host and mod */
	if (getreqentry("Host:", reqhost, LENGTH(reqhost), " \t\r\n") != 0)
		goto invalid_request;

	if (getreqentry("If-Modified-Since:", reqmod, LENGTH(reqmod), "\r\n") == 1)
		goto invalid_request;

	/* extract method */
	for (p = reqbuf; *p && *p != '\r' && *p != '\n'; p++);
	if (*p == '\r' || *p == '\n') {
		*p = 0;
		/* check command */
		if (!strncmp(reqbuf, "GET ", 4) && reqbuf[4] == '/')
			req.type = GET;
		else if (!strncmp(reqbuf, "HEAD ", 5) && reqbuf[5] == '/')
			req.type = HEAD;
		else
			goto invalid_request;
	} else {
		goto invalid_request;
	}

	/* determine path */
	for (res = reqbuf + req.type; *res && *(res + 1) == '/'; res++); /* strip '/' */
	if (!*res)
		goto invalid_request;
	for (p = res; *p && *p != ' ' && *p != '\t'; p++);
	if (!*p)
		goto invalid_request;
	*p = 0;
	memmove(reqbuf, res, (p - res) + 1);
	return 0;
invalid_request:
	return -1;
}

void
serve(int fd) {
	int result;
	socklen_t salen;
	struct sockaddr sa;

	while (running) {
		salen = sizeof sa;
		if ((req.fd = accept(fd, &sa, &salen)) == -1) {
			/* el cheapo socket release */
			logerrmsg("info\tcannot accept: %s, sleep a second...\n", strerror(errno));
			sleep(1);
			continue;
		}
		result = fork();
		if (result == 0) {
			close(fd);
			host[0] = 0;
			getnameinfo(&sa, salen, host, sizeof host, NULL, 0, NI_NOFQDN);
			result = request();
			shutdown(req.fd, SHUT_RD);
			status = -1;
			if (result == 0)
				response();
			logmsg("%d\t%s\t%s\n", status, host, reqbuf);
			shutdown(req.fd, SHUT_WR);
			close(req.fd);
			exit(EXIT_SUCCESS);
		} else if (result == -1) {
			logerrmsg("error\tfork failed: %s\n", strerror(errno));
		}
		close(req.fd);
	}
	logmsg("info\tshutting down\n");
}

void
sighandler(int sig) {
	if (sig == SIGCHLD) {
		while(0 < waitpid(-1, NULL, WNOHANG));
	} else {
		logerrmsg("info\tsignal %s, closing down\n", strsignal(sig));
		close(fd);
		running = 0;
	}
}

char *
tstamp(void) {
	static char res[30];
	time_t t = time(NULL);

	strftime(res, sizeof res, "%a, %d %b %Y %H:%M:%S %Z", localtime(&t));
	return res;
}

int
main(int argc, char *argv[]) {
	struct addrinfo hints, *ai;
	struct passwd *upwd;
	struct group *gpwd;
	int i;

	ARGBEGIN {
	case 'v':
		die("quark-"VERSION"\n");
	default:
		die("usage: %s [-v]\n", argv0);
	} ARGEND;

	/* sanity checks */
	if (user && !(upwd = getpwnam(user)))
		die("error\tinvalid user %s\n", user);
	if (group && !(gpwd = getgrnam(group)))
		die("error\tinvalid group %s\n", group);

	signal(SIGCHLD, sighandler);
	signal(SIGHUP, sighandler);
	signal(SIGINT, sighandler);
	signal(SIGQUIT, sighandler);
	signal(SIGABRT, sighandler);
	signal(SIGTERM, sighandler);

	/* init */
	setbuf(stdout, NULL); /* unbuffered stdout */
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;
	if ((i = getaddrinfo(servername, serverport, &hints, &ai)))
		die("error\tgetaddrinfo: %s\n", gai_strerror(i));
	if ((fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol)) == -1) {
		freeaddrinfo(ai);
		die("error\tsocket: %s\n", strerror(errno));
	}
	if (bind(fd, ai->ai_addr, ai->ai_addrlen) == -1) {
		close(fd);
		freeaddrinfo(ai);
		die("error\tbind: %s\n", strerror(errno));
	}
	if (listen(fd, SOMAXCONN) == -1) {
		close(fd);
		freeaddrinfo(ai);
		die("error\tlisten: %s\n", strerror(errno));
	}

	if (!strcmp(serverport, "80"))
		i = snprintf(location, sizeof location, "http://%s", servername);
	else
		i = snprintf(location, sizeof location, "http://%s:%s", servername, serverport);
	if (i >= sizeof location) {
		close(fd);
		freeaddrinfo(ai);
		die("error\tlocation too long\n");
	}

	if (chdir(docroot) == -1)
		die("error\tchdir %s: %s\n", docroot, strerror(errno));
	if (chroot(".") == -1)
		die("error\tchroot .: %s\n", strerror(errno));

	if (gpwd && setgid(gpwd->gr_gid) == -1)
		die("error\tcannot set group id\n");
	if (upwd && setuid(upwd->pw_uid) == -1)
		die("error\tcannot set user id\n");

	if (getuid() == 0)
		die("error\twon't run with root permissions, choose another user\n");
	if (getgid() == 0)
		die("error\twon't run with root permissions, choose another group\n");

	logmsg("ready\t%s:%s\t%s\n", servername, serverport, docroot);

	serve(fd); /* main loop */
	freeaddrinfo(ai);
	return 0;
}
