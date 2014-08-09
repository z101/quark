/* quark configuration */

static const char  servername[] = "127.0.0.1";
static const char  serverport[] = "80";
static const char  docroot[]    = ".";
static const char  docindex[]   = "index.html";
static const char *user         = "nobody";
static const char *group        = "nogroup";
static const char  cgi_dir[]    = "/var/www/werc-dev/bin";
static const char  cgi_script[] = "./werc.rc";
static const int   cgi_mode     = 0;

static const MimeType servermimes[] = {
	{ "html", "text/html; charset=UTF-8" },
	{ "htm",  "text/html; charset=UTF-8" },
	{ "css",  "text/css" },
	{ "txt",  "text/plain" },
	{ "text", "text/plain" },
	{ "md",   "text/plain" },
	{ "png",  "image/png" },
	{ "gif",  "image/gif" },
	{ "jpg",  "image/jpg" },
	{ "iso",  "application/x-iso9660-image" },
	{ "gz",   "application/x-gtar" },
	{ "pdf",  "application/x-pdf" },
	{ "tar",  "application/tar" },
	{ "mp3",  "audio/mp3" }
};
