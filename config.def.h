/* quark configuration */

static const char *servername = "127.0.0.1";
static const char *serverport = "80";
static const char *docroot    = ".";
static const char *docindex   = "index.html";
static const char *user       = "nobody";
static const char *group      = "nobody";
static const char *cgi_dir    = ".";
static const char *cgi_script = "/werc.rc";
static int cgi_mode           = 0;

static const MimeType servermimes[] = {
	{ "html", "text/html; charset=UTF-8" },
	{ "htm",  "text/html; charset=UTF-8" },
	{ "css",  "text/css" },
	{ "js",   "application/javascript" },
	{ "txt",  "text/plain" },
	{ "md",   "text/plain" },
	{ "png",  "image/png" },
	{ "gif",  "image/gif" },
	{ "jpeg", "image/jpeg" },
	{ "jpg",  "image/jpeg" },
	{ "iso",  "application/x-iso9660-image" },
	{ "gz",   "application/x-gtar" },
	{ "pdf",  "application/x-pdf" },
	{ "tar",  "application/tar" },
	{ "mp3",  "audio/mp3" }
};
