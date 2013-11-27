/*
 * milter-null.c
 *
 * Copyright 2006, 2012 by Anthony Howe. All rights reserved.
 *
 * The following should be added to the sendmail.mc file:
 *
 *	INPUT_MAIL_FILTER(
 *		`milter-null',
 *		`S=unix:/var/lib/milter-null/socket, T=S:10s;R:10s'
 *	)dnl
 *
 * $OpenBSD$
 */

/***********************************************************************
 *** Leave this header alone. Its generate from the configure script.
 ***********************************************************************/

#include "config.h"

/***********************************************************************
 *** You can change the stuff below if the configure script doesn't work.
 ***********************************************************************/

#ifndef RUN_AS_USER
#define RUN_AS_USER			"milter"
#endif

#ifndef RUN_AS_GROUP
#define RUN_AS_GROUP			"milter"
#endif

#ifndef MILTER_CF
#define MILTER_CF			"/etc/mail/" MILTER_NAME ".cf"
#endif

#ifndef PID_FILE
#define PID_FILE			"/var/run/milter/" MILTER_NAME ".pid"
#endif

#ifndef SOCKET_FILE
#define SOCKET_FILE			"/var/run/milter/" MILTER_NAME ".socket"
#endif

#ifndef WORK_DIR
#define WORK_DIR			"/var/tmp"
#endif

/***********************************************************************
 *** No configuration below this point.
 ***********************************************************************/

/* Re-assert this macro just in case. May cause a compiler warning. */
#define _REENTRANT	1

#include <com/snert/lib/version.h>

#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/stat.h>

#if HAVE_INTTYPES_H
# include <inttypes.h>
#else
# if HAVE_STDINT_H
# include <stdint.h>
# endif
#endif

#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#include <com/snert/lib/mail/limits.h>
#include <com/snert/lib/mail/smf.h>
#include <com/snert/lib/mail/smdb.h>
#include <com/snert/lib/mail/tlds.h>
#include <com/snert/lib/util/Text.h>
#include <com/snert/lib/util/convertDate.h>
#include <com/snert/lib/util/option.h>
#include <com/snert/lib/util/md5.h>
#include <com/snert/lib/util/time62.h>

#if LIBSNERT_MAJOR < 1 || LIBSNERT_MINOR < 75
# error "LibSnert 1.75.8 or better is required"
#endif

#define MILTER_STRING	MILTER_NAME "/" MILTER_VERSION

/***********************************************************************
 *** Constants
 ***********************************************************************/

#define	TAG_FORMAT		"%05d %s: "
#define	TAG_ARGS		data->work.cid, data->work.qid

#define X_SCANNED_BY		"X-Scanned-By"
#define X_MILTER_PASS		"X-" MILTER_NAME "-Pass"
#define X_MILTER_REPORT		"X-" MILTER_NAME "-Report"

/***********************************************************************
 *** Global Variables
 ***********************************************************************/

typedef struct {
	smfWork work;
	time_t sent;				/* per message */
	int has_report;				/* per message */
	int rcpt_count;				/* per message */
	int found_null_tag;			/* per message */
	char digest_string[33];			/* per message */
	unsigned char digest[16];		/* per message */
	char message_id[SMTP_PATH_LENGTH];	/* per message */
	char client_name[SMTP_DOMAIN_LENGTH+1];	/* per connection */
	char client_addr[IPV6_TAG_LENGTH+IPV6_STRING_LENGTH];	/* per connection */
} *workspace;

static const char hex_digit[] = "0123456789abcdef";

#define USAGE_DATE_TTL							\
  "Date: header time-to-live in seconds. DSN or MDN messages\n"		\
"# containing Date: headers older than this value are rejected.\n"	\
"#"

#define USAGE_ONE_RCPT_PER_NULL							\
  "When the sender is MAIL FROM:<>, then there can only be one\n"		\
"# RCPT TO: specified since the null address is only used to return\n"		\
"# a Delivery Status Notification or Message Disposition Notification\n"	\
"# to the original sender and its not possible to have two or more\n"		\
"# sender's for one message (in theory).\n"					\
"#"

#define USAGE_SECRET								\
  "Specify a phrase used to generate and validate X-Null-Tag headers.\n"	\
"# Be sure to quote the string if it contains white space.\n"			\
"#"

#define USAGE_POLICY								\
  "Policy to apply when a DSN or MDN does not reference a message that\n"	\
"# originated here or has expired. Specify none, quarantine, reject, or\n"	\
"# discard.\n"									\
"#"

static Option optIntro		= { "",				NULL,		"\n# " MILTER_NAME "/" MILTER_VERSION "\n#\n# " MILTER_COPYRIGHT "\n#\n" };
static Option optDateTTL	= { "date-ttl",			"604800",	USAGE_DATE_TTL };
static Option optOneRcptPerNull	= { "one-rcpt-per-null",	"+",		USAGE_ONE_RCPT_PER_NULL };
static Option optPolicy		= { "policy",			"none",		USAGE_POLICY };
static Option optSecret		= { "secret",			"change me",	USAGE_SECRET };

static Option *optTable[] = {
	&optIntro,
	&optDateTTL,
	&optOneRcptPerNull,
	&optPolicy,
	&optSecret,
	NULL
};

/***********************************************************************
 *** Handlers
 ***********************************************************************/

/*
 * Open and allocate per-connection resources.
 */
static sfsistat
filterOpen(SMFICTX *ctx, char *client_name, _SOCK_ADDR *raw_client_addr)
{
	int access;
	workspace data;

	if (raw_client_addr == NULL) {
		smfLog(SMF_LOG_TRACE, "filterOpen() got NULL socket address, accepting connection");
		goto error0;
	}

	if (raw_client_addr->sa_family != AF_INET
#ifdef HAVE_STRUCT_SOCKADDR_IN6
	&& raw_client_addr->sa_family != AF_INET6
#endif
	) {
		smfLog(SMF_LOG_TRACE, "filterOpen() unsupported socket address type, accepting connection");
		goto error0;
	}

	if ((data = calloc(1, sizeof *data)) == NULL)
		goto error0;

	data->work.ctx = ctx;
	data->work.qid = smfNoQueue;
	TextCopy(data->client_name, sizeof (data->client_name), client_name);
	data->work.cid = smfOpenProlog(ctx, client_name, raw_client_addr, data->client_addr, sizeof (data->client_addr));

	smfLog(SMF_LOG_TRACE, TAG_FORMAT "filterOpen(%lx, '%s', [%s])", TAG_ARGS, (long) ctx, client_name, data->client_addr);

	if (smfi_setpriv(ctx, (void *) data) == MI_FAILURE) {
		syslog(LOG_ERR, TAG_FORMAT "failed to save workspace", TAG_ARGS);
		goto error1;
	}

	access = smfAccessHost(&data->work, MILTER_NAME "-connect:", client_name, data->client_addr, SMDB_ACCESS_OK);

	switch (access) {
#ifdef ENABLE_BLACKLIST
	case SMDB_ACCESS_REJECT:
		return smfReply(&data->work, 550, "5.7.1", "connection %s [%s] blocked", client_name, data->client_addr);
#endif
	case SMDB_ACCESS_ERROR:
		return SMFIS_REJECT;
	}

	return SMFIS_CONTINUE;
error1:
	free(data);
error0:
	return SMFIS_ACCEPT;
}

static sfsistat
filterMail(SMFICTX *ctx, char **args)
{
	int access;
	workspace data;
	char *auth_authen;

	if ((data = (workspace) smfi_getpriv(ctx)) == NULL)
		return smfNullWorkspaceError("filterMail");

	if ((data->work.qid = smfi_getsymval(ctx, "i")) == NULL)
		data->work.qid = smfNoQueue;

	data->sent = 0;
	data->has_report = 0;
	data->rcpt_count = 0;
	data->found_null_tag = 0;
	data->message_id[0] = '\0';
	data->digest_string[0] = '\0';
#ifdef ENABLE_WHITELIST
	data->work.skipMessage = data->work.skipConnection;
#endif
	auth_authen = smfi_getsymval(ctx, smMacro_auth_authen);

	smfLog(SMF_LOG_TRACE, TAG_FORMAT "filterMail(%lx, %lx) MAIL='%s' auth='%s'", TAG_ARGS, (long) ctx, (long) args, args[0], auth_authen == NULL ? "" : auth_authen);

	access = smfAccessMail(&data->work, MILTER_NAME "-from:", args[0], SMDB_ACCESS_UNKNOWN);

	switch (access) {
#ifdef ENABLE_BLACKLIST
	case SMDB_ACCESS_REJECT:
		return smfReply(&data->work, 550, "5.7.1", "sender blocked");
#endif
	case SMDB_ACCESS_ERROR:
		return SMFIS_REJECT;
	}

	access = smfAccessAuth(&data->work, MILTER_NAME "-auth:", auth_authen, args[0], NULL, NULL);

	switch (access) {
	case SMDB_ACCESS_ERROR:
		return SMFIS_REJECT;
#ifdef ENABLE_BLACKLIST
	case SMDB_ACCESS_REJECT:
		return smfReply(&data->work, 550, "5.7.1", "sender authorisation <%s> denied", auth_authen);
#endif
	case SMDB_ACCESS_OK:
		syslog(LOG_INFO, TAG_FORMAT "sender %s authenticated, accept", TAG_ARGS, args[0]);
		return SMFIS_ACCEPT;
	}

	return SMFIS_CONTINUE;
}

static sfsistat
filterRcpt(SMFICTX *ctx, char **args)
{
	int access;
	workspace data;

	if ((data = (workspace) smfi_getpriv(ctx)) == NULL)
		return smfNullWorkspaceError("filterRcpt");

	smfLog(SMF_LOG_TRACE, TAG_FORMAT "filterRcpt(%lx, %lx) RCPT='%s'", TAG_ARGS, (long) ctx, (long) args, args[0]);

	/* Assume the first recipient given for a DSN/MDN,
	 * is the original sender. Typically there is only
	 * ever one recipient, unless a site chooses to
	 * send a copy to postmater, an archive mailbox, etc.
	 */
	access = smfAccessRcpt(&data->work, MILTER_NAME "-to:", args[0]);

	switch (access) {
	case SMDB_ACCESS_ERROR:
		return SMFIS_REJECT;
#ifdef ENABLE_BLACKLIST
	case SMDB_ACCESS_REJECT:
		return smfReply(&data->work, 550, "5.7.1", "recipient blocked");
#endif
	case SMDB_ACCESS_OK:
		data->work.skipMessage = 1;
	}

	data->work.skipRecipient |= data->work.skipConnection;
	data->rcpt_count++;

	if (optOneRcptPerNull.value && 1 < data->rcpt_count && data->work.mail->address.length == 0)
		return smfReply(&data->work, 550, NULL, "too many recipients");

	return SMFIS_CONTINUE;
}

static sfsistat
filterHeader(SMFICTX *ctx, char *name, char *value)
{
	workspace data;

	if ((data = (workspace) smfi_getpriv(ctx)) == NULL)
		return smfNullWorkspaceError("filterHeader");

	smfLog(SMF_LOG_TRACE, TAG_FORMAT "filterHeader(%lx, '%s', '%.20s...')", TAG_ARGS, (long) ctx, name, value);

	if (0 < data->work.mail->address.length && TextInsensitiveCompare(name, "Date") == 0) {
		/* We need the Date: header when sending normal mail in
		 * order to generate the X-Null-Tag: header, but you want
		 * to skip it for a DSN message so that we search the DSN
		 * message body for a Date: header instead.
		 */
		(void) convertDate(value, &data->sent, NULL);
	} else if (TextInsensitiveCompare(name, "Message-ID") == 0) {
		value += strspn(value, " \t");
		TextCopy(data->message_id, sizeof (data->message_id), value);
	} else if (TextInsensitiveCompare(name, X_MILTER_REPORT) == 0) {
		data->has_report = 1;
	}

	return SMFIS_CONTINUE;
}

static sfsistat
filterBody(SMFICTX *ctx, unsigned char *chunk, size_t size)
{
	int i;
	workspace data;
	md5_state_t md5;
	long offset, length, next;
	char buffer[TIME62_BUFFER_SIZE];

	if ((data = (workspace) smfi_getpriv(ctx)) == NULL)
		return smfNullWorkspaceError("filterBody");

	if (size == 0)
		chunk = (unsigned char *) "";
	else if (size < 20)
		chunk[--size] = '\0';

	smfLog(SMF_LOG_TRACE, TAG_FORMAT "filterBody(%lx, '%.20s...', %lu)", TAG_ARGS, (long) ctx, chunk, (unsigned long) size);

	if (data->work.skipRecipient || data->found_null_tag || 0 < data->work.mail->address.length) {
		return SMFIS_CONTINUE;
	}

	if (data->sent == 0) {
		for (next = 0; 0 <= (offset = TextFind((char *)chunk+next, "*Date: *", size-next, 1)); next += offset+1) {
			if (isspace(chunk[next+offset-1])) {
				offset += next;
				break;
			}
		}

		if (0 <= offset && 0 <= (length = TextFind((char *)chunk + offset, "*\r*", size - offset, 0))) {
			chunk[offset+length] = '\0';
			(void) convertDate((char *)chunk + offset + sizeof ("Date: ")-1, &data->sent, NULL);
			smfLog(SMF_LOG_DEBUG, TAG_FORMAT "offset=%ld \"%s\" %lx", TAG_ARGS, offset, chunk+offset, data->sent);
			chunk[offset+length] = '\r';
		}
	}

	if (*data->digest_string == '\0' && 0 <= (offset = TextFind((char *)chunk, "*Message-Id: *", size, 1))) {
		offset += sizeof ("Message-Id: ")-1;

		if ((length = TextFind((char *)chunk + offset, "*>*", size - offset, 0)) < 0) {
			smfLog(SMF_LOG_DEBUG, TAG_FORMAT "failed to find end of Message-Id:", TAG_ARGS);
			return SMFIS_CONTINUE;
		}

		chunk[offset+length] = '\0';
		smfLog(SMF_LOG_DEBUG, TAG_FORMAT "offset=%ld \"%s>\"", TAG_ARGS, offset, chunk+offset);
		chunk[offset+length] = '>';

		md5_init(&md5);
		md5_append(&md5, (md5_byte_t *) data->work.rcpt->address.string, data->work.rcpt->address.length);
		md5_append(&md5, (md5_byte_t *) optSecret.string, strlen(optSecret.string));

		time62Encode(data->sent, buffer);
		md5_append(&md5, (md5_byte_t *) buffer, sizeof (buffer));

		md5_append(&md5, (md5_byte_t *) chunk + offset, length + 1);
		md5_finish(&md5, (md5_byte_t *) data->digest);

		for (i = 0; i < 16; i++) {
			data->digest_string[i << 1] = hex_digit[(data->digest[i] >> 4) & 0x0F];
			data->digest_string[(i << 1) + 1] = hex_digit[data->digest[i] & 0x0F];
		}
		data->digest_string[32] = '\0';

		smfLog(SMF_LOG_DEBUG, TAG_FORMAT "expected digest=%s", TAG_ARGS, data->digest_string);
	}

	if (*data->digest_string != '\0') {
		/* There can be multiple X-Null-Tag headers, one per relay. */
		while (0 <= (offset = TextFind((char *)chunk, "*X-Null-Tag: *", size, 1))) {
			offset += sizeof ("X-Null-Tag: ")-1;
			chunk += offset;
			size -= offset;

			/* If tag straddles body chunks, give up. */
			if (size < sizeof (data->digest_string)-1)
				break;

			smfLog(SMF_LOG_DEBUG, TAG_FORMAT "checking X-Null-Tag: %.32s", TAG_ARGS, chunk);

			if (memcmp(chunk, data->digest_string, sizeof (data->digest_string)-1) == 0) {
				smfLog(SMF_LOG_DEBUG, TAG_FORMAT "matched X-Null-Tag: %.32s", TAG_ARGS, chunk);
				data->found_null_tag = 1;
				break;
			}
		}
	}

	return SMFIS_CONTINUE;
}

static sfsistat
applyPolicy(workspace data, const char *fmt, ...)
{
	va_list args;
	char buffer[80];

	va_start(args, fmt);

	switch (*optPolicy.string) {
	case 'd':
		return SMFIS_DISCARD;
	case 'r':
		return smfReplyV(&data->work, 550, NULL, fmt, args);
#ifdef HAVE_SMFI_QUARANTINE
	case 'q':
		(void) vsnprintf(buffer, sizeof (buffer), fmt, args);
		if (smfi_quarantine(data->work.ctx, buffer) == MI_SUCCESS)
			return SMFIS_CONTINUE;
		/*@fallthrough@*/
#endif
	default:
		(void) vsnprintf(buffer, sizeof (buffer), fmt, args);
		(void) smfHeaderSet(data->work.ctx, X_MILTER_REPORT, buffer, 1, data->has_report);
	}

	va_end(args);

	return SMFIS_CONTINUE;
}

static sfsistat
filterEndMessage(SMFICTX *ctx)
{
	int i;
	workspace data;
	md5_state_t md5;
	const char *msg_id;
	char buffer[TIME62_BUFFER_SIZE];

	if ((data = (workspace) smfi_getpriv(ctx)) == NULL)
		return smfNullWorkspaceError("filterEndMessage");

	smfLog(SMF_LOG_TRACE, TAG_FORMAT "filterEndMessage(%lx)", TAG_ARGS, (long) ctx);

	if (data->work.mail->address.length == 0) {
		if (data->work.skipRecipient) {
			smfLog(SMF_LOG_DEBUG, TAG_FORMAT "white listed earlier, skipping message", TAG_ARGS);
			return SMFIS_CONTINUE;
		}

		if (0 < data->sent && data->sent + optDateTTL.value < time(NULL))
			return applyPolicy(data, "DSN or MDN in response to an old message");

		if (!data->found_null_tag)
			return applyPolicy(data, "DSN or MDN for message that did not originate here");
	} else if ((msg_id = smfi_getsymval(ctx, "{msg_id}")) != NULL || *(msg_id = data->message_id) != '\0') {
		smfLog(SMF_LOG_DEBUG, TAG_FORMAT "msg_id=%s date=%lx", TAG_ARGS, msg_id, data->sent);

		md5_init(&md5);
		md5_append(&md5, (md5_byte_t *) data->work.mail->address.string, data->work.mail->address.length);
		md5_append(&md5, (md5_byte_t *) optSecret.string, strlen(optSecret.string));

		time62Encode(data->sent, buffer);
		md5_append(&md5, (md5_byte_t *) buffer, sizeof (buffer));

		md5_append(&md5, (md5_byte_t *) msg_id, strlen(msg_id));
		md5_finish(&md5, (md5_byte_t *) data->digest);

		for (i = 0; i < 16; i++) {
			data->digest_string[i << 1] = hex_digit[(data->digest[i] >> 4) & 0x0F];
			data->digest_string[(i << 1) + 1] = hex_digit[data->digest[i] & 0x0F];
		}
		data->digest_string[32] = '\0';

		(void) smfi_addheader(ctx, "X-Null-Tag", data->digest_string);
	}

	return SMFIS_CONTINUE;
}

/*
 * Close and release per-connection resources.
 */
static sfsistat
filterClose(SMFICTX *ctx)
{
	workspace data;
	unsigned short cid = 0;

	if ((data = (workspace) smfi_getpriv(ctx)) != NULL) {
		cid = smfCloseEpilog(&data->work);
		free(data);
	}

	smfLog(SMF_LOG_TRACE, TAG_FORMAT "filterClose(%lx)", cid, smfNoQueue, (long) ctx);

	return SMFIS_CONTINUE;
}


/***********************************************************************
 ***  Milter Definition Block
 ***********************************************************************/

static smfInfo milter = {
	MILTER_MAJOR,
	MILTER_MINOR,
	MILTER_BUILD,
	MILTER_NAME,
	MILTER_AUTHOR,
	MILTER_COPYRIGHT,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	SMF_STDIO_CLOSE,

	/* struct smfiDesc */
	{
		MILTER_NAME,		/* filter name */
		SMFI_VERSION,		/* version code -- do not change */
		SMFIF_ADDHDRS,		/* flags */
		filterOpen,		/* connection info filter */
		NULL,			/* SMTP HELO command filter */
		filterMail,		/* envelope sender filter */
		filterRcpt,		/* envelope recipient filter */
		filterHeader,		/* header filter */
		NULL,			/* end of header */
		filterBody,		/* body block filter */
		filterEndMessage,	/* end of message */
		NULL,			/* message aborted */
		filterClose		/* connection cleanup */
#if SMFI_VERSION > 2
		, NULL			/* Unknown/unimplemented commands */
#endif
#if SMFI_VERSION > 3
		, NULL			/* SMTP DATA command */
#endif
	}
};

/***********************************************************************
 *** Startup
 ***********************************************************************/

int
main(int argc, char **argv)
{
	/* Default is OFF. */
	smfOptSmtpAuthOk.initial = "-";

	/* Defaults. */
	smfOptFile.initial = MILTER_CF;
	smfOptPidFile.initial = PID_FILE;
	smfOptRunUser.initial = RUN_AS_USER;
	smfOptRunGroup.initial = RUN_AS_GROUP;
	smfOptWorkDir.initial = WORK_DIR;
	smfOptMilterSocket.initial = "unix:" SOCKET_FILE;

	/* Parse command line options looking for a file= option. */
	optionInit(optTable, smfOptTable, NULL);
	(void) optionArrayL(argc, argv, optTable, smfOptTable, NULL);

	/* Parse the option file followed by the command line options again. */
	if (smfOptFile.string != NULL && *smfOptFile.string != '\0') {
		/* Do NOT reset this option. */
		smfOptFile.initial = smfOptFile.string;
		smfOptFile.string = NULL;

		optionInit(optTable, smfOptTable, NULL);
		(void) optionFile(smfOptFile.string, optTable, smfOptTable, NULL);
		(void) optionArrayL(argc, argv, optTable, smfOptTable, NULL);
	}

	/* Show them the funny farm. */
	if (smfOptHelp.string != NULL) {
		optionUsageL(optTable, smfOptTable, NULL);
		exit(2);
	}

	if (smfOptQuit.string != NULL) {
		/* Use SIGQUIT signal in order to avoid delays
		 * caused by libmilter's handling of SIGTERM.
		 * smfi_stop() takes too long since it waits
		 * for connections to terminate, which could
		 * be a several minutes or longer.
		 */
		exit(pidKill(smfOptPidFile.string, SIGQUIT) != 0);
	}

	if (smfOptRestart.string != NULL) {
		(void) pidKill(smfOptPidFile.string, SIGQUIT);
		sleep(2);
	}

	if (smfOptDaemon.value && smfStartBackgroundProcess())
		return 1;

	(void) smfi_settimeout((int) smfOptMilterTimeout.value);
	(void) smfSetLogDetail(smfOptVerbose.string);

	if (*optPolicy.string != 'r' && *optPolicy.string != 'd')
		milter.handlers.xxfi_flags |= SMFIF_ADDHDRS|SMFIF_CHGHDRS;

	openlog(MILTER_NAME, LOG_PID, LOG_MAIL);

	if (atexit(smfAtExitCleanUp)) {
		syslog(LOG_ERR, "atexit() failed\n");
		return 1;
	}

	if (*smfOptAccessDb.string != '\0') {
		if (smfLogDetail & SMF_LOG_DATABASE)
			smdbSetDebugMask(SMDB_DEBUG_ALL);

		if ((smdbAccess = smdbOpen(smfOptAccessDb.string, 1)) == NULL) {
			syslog(LOG_ERR, "failed to open \"%s\"", smfOptAccessDb.string);
			return 1;
		}
	}

	return smfMainStart(&milter);
}
