/* quark configuration */

static const char servername[] = "192.168.1.66";
static const char serverport[] = "80";
static const char docroot[]    = ".";
static const char docindex[]   = "index.html";
static const char user[]       = "nobody";
static const char group[]      = "nobody";

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
