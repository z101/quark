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
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include "arg.h"
char *argv0;

#define LENGTH(x)  (sizeof x / sizeof x[0])
#define MAXBUFLEN  1024
#define MIN(x,y)   ((x) < (y) ? (x) : (y))

#define HttpOk          "200 OK"
#define HttpMoved       "301 Moved Permanently"
#define HttpNotModified "304 Not Modified"
#define HttpForbidden   "403 Forbidden"
#define HttpNotFound    "404 Not Found"
#define texthtml        "text/html"

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

enum {
	HEADER,
	CONTENTLEN,
	LOCATION,
	CONTENTTYPE,
	MODIFIED
};

static const char *resentry[] = {
	[HEADER]      = "HTTP/1.1 %s\r\n"
			"Connection: close\r\n"
			"Date: %s\r\n"
			"Server: quark-"VERSION"\r\n",
	[CONTENTLEN]  = "Content-Length: %lu\r\n",
	[LOCATION]    = "Location: %s%s\r\n",
	[CONTENTTYPE] = "Content-Type: %s\r\n",
	[MODIFIED]    = "Last-Modified: %s\r\n"
};

static char *tstamp(time_t t);
static int writedata(const char *buf, size_t buflen);
static int writetext(const char *buf);
static void atomiclog(int fd, const char *errstr, va_list ap);
static void logmsg(const char *errstr, ...);
static void logerrmsg(const char *errstr, ...);
static void die(const char *errstr, ...);
static int putresentry(int type, ...);
static void responsefiledata(int fd, off_t size);
static void responsefile(void);
static void responsedirdata(DIR *d);
static void responsedir(void);
static void responsecgi(void);
static void response(void);
static int getreqentry(char *name, char *target, size_t targetlen, char *breakchars);
static int request(void);
static void serve(int fd);
static void sighandler(int sig);

#include "config.h"

static char location[256];
static int running = 1;
static int status;
static char host[NI_MAXHOST];
static char reqbuf[MAXBUFLEN];
static char resbuf[MAXBUFLEN];
static char reqhost[256];
static char reqmod[256];
static int fd = -1;
static Request req;

char *
tstamp(time_t t) {
	static char res[30];

	if (!t)
		t = time(NULL);
	strftime(res, sizeof res, "%a, %d %b %Y %H:%M:%S GMT", gmtime(&t));
	return res;
}

int
writedata(const char *buf, size_t buf_len) {
	ssize_t r, offset;

	for (offset = 0; offset < buf_len; offset += r) {
		if ((r = write(req.fd, buf + offset, buf_len - offset)) == -1) {
			logerrmsg("client %s closed connection\n", host);
			return -1;
		}
	}
	return 0;
}

int
writetext(const char *buf) {
	return writedata(buf, strlen(buf));
}

void
atomiclog(int fd, const char *errstr, va_list ap) {
	static char buf[512];
	size_t n;

	/* assemble the message in buf and write it in one pass
	   to avoid interleaved concurrent writes on a shared fd. */
	n = snprintf(buf, sizeof buf, "%s\t", tstamp(0));
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
	ssize_t n, m, size_in;

	for (; (n = read(fd, buf, MIN(size, sizeof buf))) > 0; size -= n)
		for(size_in = n; (m = write(req.fd, buf, size_in)) > 0; size_in -= m);

	if (m == -1 && errno != EPIPE)
		logerrmsg("error writing to client %s: %s\n", host, strerror(errno));
	if (n == -1)
		logerrmsg("error reading from file: %s\n", strerror(errno));
}

void
responsefile(void) {
	const char *mimetype = "application/octet-stream";
	char mod[30], *p;
	int r, ffd;
	struct stat st;

	if ((r = stat(reqbuf, &st)) == -1 || (ffd = open(reqbuf, O_RDONLY)) == -1) {
		/* file not found */
		if (putresentry(HEADER, HttpNotFound, tstamp(0))
		 || putresentry(CONTENTTYPE, texthtml))
			return;
		status = 404;
		if (req.type == GET)
			writetext("\r\n<html><body>"HttpNotFound"</body></html>\r\n");
	} else {
		snprintf(mod, sizeof(mod), "%s", tstamp(st.st_mtim.tv_sec));
		/* check if modified */
		if (!strcmp(reqmod, mod)
		 && !putresentry(HEADER, HttpNotModified, tstamp(0))) {
			/* not modified, we're done here*/
			status = 304;
		} else {
			/* determine mime-type */
			if ((p = strrchr(reqbuf, '.'))) {
				p++;
				for (r = 0; r < LENGTH(servermimes); r++)
					if (!strcmp(servermimes[r].extension, p)) {
						mimetype = servermimes[r].mimetype;
						break;
					}
			}
			/* serve file */
			if (putresentry(HEADER, HttpOk, tstamp(0))
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

	if (putresentry(HEADER, HttpOk, tstamp(0))
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
	size_t len = strlen(reqbuf);
	DIR *d;

	if (len > 0 && (reqbuf[len - 1] != '/') && (len + 1 < MAXBUFLEN)) {
		/* add directory terminator if necessary */
		reqbuf[len] = '/';
		reqbuf[len + 1] = 0;
		if (putresentry(HEADER, HttpMoved, tstamp(0))
		 || putresentry(LOCATION, location, reqbuf)
		 || putresentry(CONTENTTYPE, texthtml))
			return;
		status = 301;
		reqbuf[len] = 0;
		if (req.type == GET)
			writetext("\r\n<html><body>"HttpMoved"</a></body></html>\r\n");
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
			logerrmsg("client %s requests %s but opendir failed: %s\n",
				  host, reqbuf, strerror(errno));
		}
	} else {
		responsefile(); /* docindex */
	}
}

void
responsecgi(void) {
	FILE *cgi;
	size_t r;

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
	logmsg("CGI SERVER_NAME=%s SCRIPT_NAME=%s REQUEST_URI=%s\n",
	       reqhost, cgi_script, reqbuf);
	if (chdir(cgi_dir) == -1)
		logerrmsg("error\tchdir to cgi directory %s failed: %s\n",
			  cgi_dir, strerror(errno));
	if ((cgi = popen(cgi_script, "r"))) {
		if (putresentry(HEADER, HttpOk, tstamp(0)))
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
		logerrmsg("error\t%s requests %s, but cannot run cgi script %s\n",
			  host, cgi_script, reqbuf);
		if (putresentry(HEADER, HttpNotFound, tstamp(0))
		 || putresentry(CONTENTTYPE, texthtml))
			return;
		status = 404;
		if (req.type == GET)
			writetext("\r\n<html><body>"HttpNotFound"</body></html>\r\n");
	}
}

void
response(void) {
	char *p;
	struct stat st;

	for (p = reqbuf; *p; p++)
		if (*p == '\\' || (*p == '/' && *(p + 1) == '.')) {
			/* don't serve bogus or hidden files */
			if (putresentry(HEADER, HttpForbidden, tstamp(0))
			 || putresentry(CONTENTTYPE, texthtml))
				return;
			status = 403;
			if (req.type == GET)
				writetext("\r\n<html><body>"HttpForbidden"</body></html>\r\n");
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
	ssize_t r;
	size_t offset = 0;

	/* read request into reqbuf (MAXBUFLEN byte of reqbuf is emergency 0 terminator */
	for (; (r = read(req.fd, reqbuf + offset, MAXBUFLEN - offset)) > 0 && offset < MAXBUFLEN
		&& (!strstr(reqbuf, "\r\n") || !strstr(reqbuf, "\n")); )
	{
		offset += r;
		reqbuf[offset] = 0;
	}
	if (r == -1) {
		logerrmsg("error\tread: %s\n", strerror(errno));
		return -1;
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

			/* get host */
			host[0] = 0;
			switch(sa.sa_family) {
				case AF_INET:
					inet_ntop(AF_INET, &(((struct sockaddr_in *)&sa)->sin_addr),
						  host, sizeof host);
					break;
				case AF_INET6:
					inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)&sa)->sin6_addr),
						  host, sizeof host);
					break;
			}

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

void
usage(void) {
	die("usage: %s [-c] [-d cgidir] [-e cgiscript] [-u user] [-g group] "
	    "[-i index] [-r docroot] [-s server] [-p port] [-v]\n", argv0);
}

int
main(int argc, char *argv[]) {
	struct addrinfo hints, *ai = NULL;
	struct passwd *upwd;
	struct group *gpwd;
	int i;

	ARGBEGIN {
	case 'c':
		cgi_mode = 1;
		break;
	case 'd':
		cgi_dir = EARGF(usage());
		break;
	case 'e':
		cgi_script = EARGF(usage());
		break;
	case 'u':
		user = EARGF(usage());
		break;
	case 'g':
		group = EARGF(usage());
		break;
	case 'i':
		docindex = EARGF(usage());
		break;
	case 'r':
		docroot = EARGF(usage());
		break;
	case 'p':
		serverport = EARGF(usage());
		break;
	case 's':
		servername = EARGF(usage());
		break;
	case 'v':
		die("quark-"VERSION"\n");
	default:
		usage();
	} ARGEND;

	/* sanity checks */
	if (user && *user && !(upwd = getpwnam(user)))
		die("error\tinvalid user %s\n", user);
	if (group && *group && !(gpwd = getgrnam(group)))
		die("error\tinvalid group %s\n", group);

	signal(SIGCHLD, sighandler);
	signal(SIGHUP, sighandler);
	signal(SIGINT, sighandler);
	signal(SIGQUIT, sighandler);
	signal(SIGABRT, sighandler);
	signal(SIGTERM, sighandler);
	signal(SIGPIPE, SIG_IGN);

	/* init */
	setbuf(stdout, NULL); /* unbuffered stdout */
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;
	if ((i = getaddrinfo(servername, serverport, &hints, &ai))) {
		logerrmsg("error\tgetaddrinfo: %s\n", gai_strerror(i));
		goto err;
	}
	if ((fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol)) == -1) {
		logerrmsg("error\tsocket: %s\n", strerror(errno));
		goto err;
	}
	if (bind(fd, ai->ai_addr, ai->ai_addrlen) == -1) {
		logerrmsg("error\tbind: %s\n", strerror(errno));
		goto err;
	}
	if (listen(fd, SOMAXCONN) == -1) {
		logerrmsg("error\tlisten: %s\n", strerror(errno));
		goto err;
	}

	if (!strcmp(serverport, "80"))
		i = snprintf(location, sizeof location, "http://%s", servername);
	else
		i = snprintf(location, sizeof location, "http://%s:%s", servername, serverport);
	if (i >= sizeof location) {
		logerrmsg("error\tlocation too long\n");
		goto err;
	}

	if (chdir(docroot) == -1) {
		logerrmsg("error\tchdir %s: %s\n", docroot, strerror(errno));
		goto err;
	}
	if (chroot(".") == -1) {
		logerrmsg("error\tchroot .: %s\n", strerror(errno));
		goto err;
	}

	if (gpwd && setgid(gpwd->gr_gid) == -1) {
		logerrmsg("error\tcannot set group id\n");
		goto err;
	}
	if (upwd && setuid(upwd->pw_uid) == -1) {
		logerrmsg("error\tcannot set user id\n");
		goto err;
	}

	if (getuid() == 0) {
		logerrmsg("error\twon't run with root permissions, choose another user\n");
		goto err;
	}
	if (getgid() == 0) {
		logerrmsg("error\twon't run with root permissions, choose another group\n");
		goto err;
	}

	logmsg("ready\t%s:%s\t%s\n", servername, serverport, docroot);

	serve(fd); /* main loop */
	close(fd);
	freeaddrinfo(ai);
	return EXIT_SUCCESS;
err:
	if (fd != -1)
		close(fd);
	if (ai)
		freeaddrinfo(ai);
	return EXIT_FAILURE;
}
