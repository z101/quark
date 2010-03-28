/* quark configuration */

static char *servername  = "127.0.0.1";
static char *serverport  = "80";
static char *docroot     = ".";
static char *docindex    = "index.html";
static char *user        = "nobody";
static char *group       = "nobody";
static char *cgi_dir     = "/var/www/werc-dev/bin";
static char *cgi_script  = "./werc.rc";
static int   cgi_mode    = 0;

static const MimeType servermimes[] = {
	{ "html", "text/html; charset=UTF-8" },
	{ "htm",  "text/html; charset=UTF-8" },
	{ "css",  "text/css" },
	{ "txt",  "text/plain" },
	{ "text", "text/plain" },
	{ "png",  "image/png" },
	{ "gif",  "image/gif" },
	{ "jpg",  "image/jpg" },
	{ "iso",  "application/x-iso9660-image" },
	{ "gz",   "application/x-gtar" },
	{ "pdf",  "application/x-pdf" },
	{ "tar",  "application/tar" },
};
