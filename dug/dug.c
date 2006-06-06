/*
 * Copyright (c) 2006 by Internet Systems Consortium, Inc. ("ISC")
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 *   Internet Systems Consortium, Inc.
 *   950 Charter Street
 *   Redwood City, CA 94063
 *   <info@isc.org>
 *   http://www.isc.org/
 */

/*
 * TODO: write man page
 * TODO: support more options
 * TODO: update release documentation
 */

/*
 * Note: It would probably be better to split the option printing part
 *       of this program out, and maybe the tables as well.
 *
 * Note: The error handling is pretty weak here. It should not crash,
 *       but bogus packets won't alert the user.
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <ctype.h>
#include <netdb.h>
#include <sys/time.h>

/* default time to wait for a reply, in seconds */
#define DEFAULT_TIMEOUT 5

const char *
dhcp_opcode2str(int opcode) {
	switch (opcode) {
		case 1: return "BOOTREQUEST";
		case 2: return "BOOTREPLY";
	}
	return NULL;
}

/* 
 * The hardware types can be found at the IANA page here:
 * 
 * http://www.iana.org/assignments/arp-parameters
 */
const char *
dhcp_htype2str(int htype) {
	switch (htype) {
		case 1: return "Ethernet";
		case 6: return "Token Ring";
		case 8: return "FDDI";
	}
	return NULL;
}

/*
 * These are prototypes for functions to print options of various 
 * types.
 */
void p_seconds(FILE *fp, int tag, int len, const unsigned char *data);
void p_overload(FILE *fp, int tag, int len, const unsigned char *data);
void p_type(FILE *fp, int tag, int len, const unsigned char *data);
void p_ip(FILE *fp, int tag, int len, const unsigned char *data);
void p_prl(FILE *fp, int tag, int len, const unsigned char *data);
void p_time(FILE *fp, int tag, int len, const unsigned char *data);
void p_client_id(FILE *fp, int tag, int len, const unsigned char *data);
void p_vendor_id(FILE *fp, int tag, int len, const unsigned char *data);
void p_message(FILE *fp, int tag, int len, const unsigned char *data);
void p_agent_info(FILE *fp, int tag, int len, const unsigned char *data);
void p_pasttime(FILE *fp, int tag, int len, const unsigned char *data);
void p_ip_list(FILE *fp, int tag, int len, const unsigned char *data);
void p_size(FILE *fp, int tag, int len, const unsigned char *data);

/*
 * This structure defines the information we need to print out an option.
 */
struct option {
	int tag;
	const char *name;
	void (*print_func)(FILE *fp, 
			   int tag, 
			   int len, 
			   const unsigned char *data);
};

/*
 * DHCP options can be found at the IANA page here:
 * 
 * http://www.iana.org/assignments/bootp-dhcp-parameters
 */
enum {
	DHCP_OPTION_PAD = 0,
	DHCP_OPTION_SUBNET_MASK = 1,
	DHCP_OPTION_TIME_OFFSET = 2,
	DHCP_OPTION_ROUTER = 3,
	DHCP_OPTION_TIME_SERVER = 4,
	DHCP_OPTION_NAME_SERVER = 5,
	DHCP_OPTION_DNS_SERVER = 6,
	DHCP_OPTION_LOG_SERVER = 7,
	DHCP_OPTION_COOKIE_SERVER = 8,
	DHCP_OPTION_LPR_SERVER = 9,
	DHCP_OPTION_IMPRESS_SERVER = 10,
	DHCP_OPTION_REQ_IP_ADDRESS = 50,
	DHCP_OPTION_LEASE_TIME = 51,
	DHCP_OPTION_OVERLOAD = 52,
	DHCP_OPTION_MESSAGE_TYPE = 53,
	DHCP_OPTION_SERVER_ID = 54,
	DHCP_OPTION_PRL = 55,
	DHCP_OPTION_MESSAGE = 56,
	DHCP_OPTION_MAX_MSG_SIZE = 57,
	DHCP_OPTION_T1 = 58,
	DHCP_OPTION_T2 = 59,
	DHCP_OPTION_VENDOR_CLASS_ID = 60,
	DHCP_OPTION_CLIENT_ID = 61,
	DHCP_OPTION_AGENT_INFO = 82,
	DHCP_OPTION_LAST_TRANSACTION = 91,
	DHCP_OPTION_ASSOCIATED_IP = 92,
	DHCP_OPTION_END = 255
};


struct option options[] = {
{ DHCP_OPTION_PAD, 		"Pad", 				NULL },
{ DHCP_OPTION_SUBNET_MASK, 	"Subnet Mask",			p_ip },
{ DHCP_OPTION_TIME_OFFSET, 	"Time Offset",			p_seconds },
{ DHCP_OPTION_ROUTER,	 	"Router Option",		p_ip_list },
{ DHCP_OPTION_TIME_SERVER, 	"Time Server Option",		p_ip_list },
{ DHCP_OPTION_NAME_SERVER, 	"Name Server Option",		p_ip_list },
{ DHCP_OPTION_DNS_SERVER, 	"Domain Name Server Option",	p_ip_list },
{ DHCP_OPTION_LOG_SERVER,	"Log Server Option",		p_ip_list },
{ DHCP_OPTION_COOKIE_SERVER,	"Cookie Server Option",		p_ip_list },
{ DHCP_OPTION_LPR_SERVER,	"LPR Server Option",		p_ip_list },
{ DHCP_OPTION_IMPRESS_SERVER,	"Impress Server Option",	p_ip_list },
{ DHCP_OPTION_REQ_IP_ADDRESS,	"Requested IP Address",		p_ip },
{ DHCP_OPTION_LEASE_TIME,	"IP Address Lease Time", 	p_seconds },
{ DHCP_OPTION_OVERLOAD,		"Option Overload",		p_overload },
{ DHCP_OPTION_MESSAGE_TYPE,	"DHCP Message Type",		p_type },
{ DHCP_OPTION_SERVER_ID, 	"Server Identifier", 		p_ip },
{ DHCP_OPTION_PRL, 		"Parameter Request List",	p_prl },
{ DHCP_OPTION_MESSAGE,		"Message",			p_message },
{ DHCP_OPTION_MAX_MSG_SIZE,	"Maximum DHCP Message Size",	p_size },
{ DHCP_OPTION_T1, 		"Renewal (T1) Time Value",	p_time },
{ DHCP_OPTION_T2,		"Rebinding (T2) Time Value",	p_time },
{ DHCP_OPTION_VENDOR_CLASS_ID,	"Vendor Class Identifier",	p_vendor_id },
{ DHCP_OPTION_CLIENT_ID,	"Client Identifier",		p_client_id },
{ DHCP_OPTION_AGENT_INFO,	"Relay Agent Information",	NULL },
{ DHCP_OPTION_LAST_TRANSACTION,	"Client Last Transaction Time", p_pasttime },
{ DHCP_OPTION_ASSOCIATED_IP,	"Associated IP",		p_ip_list },
{ DHCP_OPTION_END, 		"End Option",			NULL }
};
#define NUM_OPTIONS (sizeof(options)/sizeof(options[0]))

const struct option *
get_option(int tag) {
	int i;

	for (i=0; i<NUM_OPTIONS; i++) {
		if (options[i].tag == tag) {
			return &options[i];
		}
	}
	return NULL;
}

enum {
	/* RFC 2132 defines DHCP message types 1 to 8 */
	DHCPDISCOVER = 1,
	DHCPOFFER = 2,
	DHCPREQUEST = 3,
	DHCPDECLINE = 4,
	DHCPACK = 5,
	DHCPNAK = 6,
	DHCPRELEASE = 7,
	DHCPINFORM = 8,
	/* RFC 3203 defines DHCP message type 9 */
	DHCPFORCERENEW = 9,
	/* RFC 4388 defines DHCP message types 10 to 13 */
	DHCPLEASEQUERY = 10,
	DHCPLEASEUNASSIGNED = 11,
	DHCPLEASEUNKNOWN = 12,
	DHCPLEASEACTIVE = 13,
};

const char *dhcp_message_types[] = {
	NULL,
	"DHCPDISCOVER",
	"DHCPOFFER",
	"DHCPREQUEST",
	"DHCPDECLINE",
	"DHCPACK",
	"DHCPNAK",
	"DHCPRELEASE",
	"DHCPINFORM",
	"DHCPFORCERENEW",
	"DHCPLEASEQUERY",
	"DHCPLEASEUNASSIGNED",  
	"DHCPLEASEUNKNOWN",
	"DHCPLEASEACTIVE"
};
#define NUM_MSG_TYPES (sizeof(dhcp_message_types)/sizeof(dhcp_message_types[0]))

/*
 * Convert the string passed to one we can print. We wrap the string in
 * double-quotes, and escape non-ASCII characters. We also escape any 
 * double-quotes and the backslash character.
 *
 * For example:
 *
 * char s[] = { 4, 55, 85, 150, 0, 17 };
 * char *t = printable_string(s, sizeof(s));
 * puts(t);
 * free(t);
 *
 * This would output:
 *
 * "\x047U\x96\x00\x11"
 *
 * The memory is allocated by this function and must be freed by the 
 * caller. If no memory is available, it exits with an error message.
 */
char *
printable_string(const char *s, int slen) {
	int i;
	int len;
	char *r;
	char *p;
	const char hexdigits[] = "0123456789ABCDEF";

	len = 3;
	for (i=0; i<slen; i++) {
		if ((s[i] == '"') || 
		    (s[i] == '\\') || 
		    (s[i] < 32) || 
		    (s[i] > 126)) {
			len += 4;
		} else {
			len += 1;
		}
	}

	r = (char *)malloc(len);
	if (r == NULL) {
		fprintf(stderr, "Out of memory\n");
		exit(1);
	}

	p = r;
	*p++ = '"';
	for (i=0; i<slen; i++) {
		if ((s[i] == '"') || 
		    (s[i] == '\\') || 
		    (s[i] < 32) || 
		    (s[i] > 126)) {
			*p++ = '\\';
			*p++ = 'x';
			*p++ = hexdigits[(s[i] >> 4) & 0xF];
			*p++ = hexdigits[s[i] & 0xF];
		} else {
			*p++ = s[i];
		}
	}
	*p++ = '"';
	*p++ = '\0';

	return r;
}

void
print_datetime(FILE *fp, int secs) {
	time_t tmp;
	struct tm *t;

	time(&tmp);
	tmp += secs;
	tzset();
	t = localtime(&tmp);
	fprintf(fp, 
		"  time: %d seconds %s# %d-%02d-%02d %02d:%02d:%02d (%s)",
		secs, 
		(secs < 0) ? "ago " : "",
		t->tm_year + 1900,
		t->tm_mon + 1,
		t->tm_mday,
		t->tm_hour,
		t->tm_min,
		t->tm_sec,
		tzname[daylight]);
}

void
p_time(FILE *fp, int tag, int len, const unsigned char *data) {
	int secs;

	if (len != 4) return;
	secs = (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];
	print_datetime(fp, secs);
}

void
p_pasttime(FILE *fp, int tag, int len, const unsigned char *data) {
	int secs;

	if (len != 4) return;
	secs = (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];
	print_datetime(fp, -secs);
}

void
p_seconds(FILE *fp, int tag, int len, const unsigned char *data) {
	unsigned int secs;

	if (len != 4) return;

	secs = (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];
	fprintf(fp, "  Time: %d seconds\n", secs);
}

void
p_overload(FILE *fp, int tag, int len, const unsigned char *data) {
	if (len != 1) return;

	fprintf(fp, "  Option Overload: %d", data[0]);
	switch (data[0]) {
		case 1: 
			fprintf(fp, " # the 'file' field is "
				    "used to hold options"); 
			break;
		case 2:
			fprintf(fp, " # the 'sname' field is "
				    "used to hold options"); 
			break;
		case 3:
			fprintf(fp, " # both the 'sname' and 'file' fields are "
				    "used to hold options"); 
			break;
	}
	fprintf(fp, "\n");
}

void
p_type(FILE *fp, int tag, int len, const unsigned char *data) {
	int type;

	if (len != 1) return;

	type = data[0];
	fprintf(fp, "  message-type: %d", type);
	if ((type > 0) && (type < NUM_MSG_TYPES)) {
		if (dhcp_message_types[type] != NULL) {
			fprintf(fp, " # %s", dhcp_message_types[type]);
		}
	}
	fprintf(fp, "\n");
}

void
p_ip(FILE *fp, int tag, int len, const unsigned char *data) {
	struct in_addr addr;

	if (len != 4) return;
	memcpy(&addr, data, 4);
	fprintf(fp, "  addr: %s\n", inet_ntoa(addr));
}

void
p_ip_list(FILE *fp, int tag, int len, const unsigned char *data) {
	struct in_addr addr;
	int i;

	if ((len % 4) != 0) return;
	for (i=0; i<len; i+=4) {
		memcpy(&addr, &data[i], 4);
		fprintf(fp, "  addr: %s\n", inet_ntoa(addr));
	}
}

void
p_prl(FILE *fp, int tag, int len, const unsigned char *data) {
	int i;
	const struct option *o;

	for (i=0; i<len; i++) {
		fprintf(fp, "  option: %d", data[i]);
		o = get_option(data[i]);
		if (o != NULL) {
			fprintf(fp, " # %s", o->name);
		}
		fprintf(fp, "\n");
	}
}

/* XXX: should be a way to reuse code for ones that just print text */

void
p_vendor_id(FILE *fp, int tag, int len, const unsigned char *data) {
	char *tmp;

	tmp = printable_string(data, len);
	fprintf(fp, "  vendor-class-id: %s\n", tmp);
	free(tmp);
}

void
p_client_id(FILE *fp, int tag, int len, const unsigned char *data) {
	char *tmp;

	tmp = printable_string(data, len);
	fprintf(fp, "  client-id: %s\n", tmp);
	free(tmp);
}

void
p_message(FILE *fp, int tag, int len, const unsigned char *data) {
	char *tmp;

	tmp = printable_string(data, len);
	fprintf(fp, "  message: %s\n", tmp);
	free(tmp);
}

void
p_size(FILE *fp, int tag, int len, const unsigned char *data) {
	int size;

	if (len != 2) return;
	size = (data[0] << 8) | data[1];
	fprintf(fp, "  size: %d\n", size);
}


/*
 * The structure of a DHCP packet, as it appears on the wire.
 * This is only the fixed portion, options start after the end.
 */
struct dhcp_packet {
	unsigned char opcode;
	unsigned char htype;
	unsigned char hlen;
	unsigned char hops;
	char xid[4];
	unsigned char secs[2];
	char flags[2];
	char ciaddr[4];
	char yiaddr[4];
	char siaddr[4];
	char giaddr[4];
	char chaddr[16];
	char sname[64];
	char file[128];
};


/* 
 * Searches the options to see if the sname and file parts of the DHCP
 * packet have been overloaded and used as extra option space.
 */
int
get_option_overload(unsigned char *options, unsigned int options_len) {
	int p;
	int tag;
	int len;
	int val;

	p = 0;
	while (p < options_len) {
		tag = options[p++];

		if ((tag != DHCP_OPTION_PAD) && (tag != DHCP_OPTION_END)) {
			if (p >= options_len) break;
			len = options[p++];
			if (p >= options_len) break;
			if ((tag == DHCP_OPTION_OVERLOAD) && (len == 1)) {
				val = options[p];
				if ((val >= 1) && (val <= 3)) {
					return val;
				}
			}
			p += len;
		} 
	}
	return 0;
}

/*
 * Outputs the options.
 * XXX: Does not give error messages when incorrect.
 */
int
print_options(FILE *fp, unsigned char *options, unsigned int options_len) {
	int p;
	int tag;
	int len;
	unsigned char *data;
	const struct option *o;

	p = 0;
	while (p < options_len) {
		tag = options[p++];
		o = get_option(tag);

		fprintf(fp, "option: %d", tag);
		if (o != NULL) {
			fprintf(fp, " # %s", o->name);
		}
		fprintf(fp, "\n");

		if ((tag == DHCP_OPTION_PAD) && (tag == DHCP_OPTION_END)) {
			fprintf(fp, "  length: 0\n");
		} else {
			if (p >= options_len) return 0;
			len = options[p++];
			if (p > options_len) return 0;
			data = &options[p];
			p += len;
			if (p > options_len) return 0;

			fprintf(fp, "  length: %d\n", len);
			if ((o != NULL) && (o->print_func != NULL)) {
				(o->print_func)(fp, tag, len, data);
			}
		} 
	}
	return 1;
}

/*
 * Output the contents of a DHCP packet.
 */
void
print_dhcp_packet(FILE *fp, struct dhcp_packet *p, unsigned int len) {
	const char *tmp;
	int mask;
	struct in_addr addr;
	int i;
	unsigned char *options;
	unsigned int options_len;
	int option_overload;
	char *s;
		
	fprintf(fp, "op:     %d", p->opcode);
	tmp = dhcp_opcode2str(p->opcode);
	if (tmp != NULL) {
		fprintf(fp, " # %s", tmp);
	}
	fprintf(fp, "\n");

	fprintf(fp, "htype:  %d", p->htype);
	tmp = dhcp_htype2str(p->htype);
	if (tmp != NULL) {
		fprintf(fp, " # %s", tmp);
	}
	fprintf(fp, "\n");

	fprintf(fp, "hlen:   %d\n", p->hlen);
	fprintf(fp, "hops:   %d\n", p->hops);
	fprintf(fp, "xid:    0x%02X%02X%02X%02X\n", 
		p->xid[0] & 0xFF, p->xid[1] & 0xFF, 
		p->xid[2] & 0xFF, p->xid[3] & 0xFF);
	fprintf(fp, "secs:   %d\n", ((p->secs[0] << 8) | p->secs[1]) & 0xFFFF);

	fprintf(fp, "flags:  ");
	fprintf(fp, (p->flags[0] & 0x80) ? "B" : "-");
	for (mask = 0x40; mask > 0; mask >>= 1) {
		fprintf(fp, (p->flags[0] & mask) ? "?" : "-");
	}
	for (mask = 0x80; mask > 0; mask >>= 1) {
		fprintf(fp, (p->flags[1] & mask) ? "?" : "-");
	}
	fprintf(fp, "\n");

	memcpy(&addr, p->ciaddr, 4);
	fprintf(fp, "ciaddr: %s\n", inet_ntoa(addr));
	memcpy(&addr, p->yiaddr, 4);
	fprintf(fp, "yiaddr: %s\n", inet_ntoa(addr));
	memcpy(&addr, p->siaddr, 4);
	fprintf(fp, "siaddr: %s\n", inet_ntoa(addr));
	memcpy(&addr, p->giaddr, 4);
	fprintf(fp, "giaddr: %s\n", inet_ntoa(addr));

	fprintf(fp, "chaddr: ");
	if (p->hlen > 0) {
		fprintf(fp, "%02X", p->chaddr[0]);
		for (i=1; (i<p->hlen) && (i<sizeof(p->chaddr)); i++) {
			fprintf(fp, ":%02X", p->chaddr[i] & 0xFF);
		}
	}
	fprintf(fp, "\n");

	options = (unsigned char *)p + sizeof(*p);
	options_len = len - sizeof(*p);

	/*
	 * Check for DHCP options magic cookie.
	 */
	if ((options_len < 4) ||
	    (options[0] != 99) || 
	    (options[1] != 130) ||
	    (options[2] != 83) ||
	    (options[3] != 99)) {
		return;
	}
	options += 4;
	options_len -= 4;

	option_overload = get_option_overload(options, options_len);

	if ((option_overload == 2) || (option_overload == 3)) {
		fprintf(fp, "sname:  none # used for options\n");
	} else {
		s = printable_string(p->sname, strlen(p->sname));
		fprintf(fp, "sname:  %s\n", s);
		free(s);
	}

	if ((option_overload == 1) || (option_overload == 3)) {
		fprintf(fp, "file:   none # used for options\n");
	} else {
		s = printable_string(p->file, strlen(p->file));
		fprintf(fp, "file:   %s\n", s);
		free(s);
	}

	print_options(fp, options, options_len);

	if ((option_overload == 1) || (option_overload == 3)) {
		print_options(fp, p->file, sizeof(p->file));
	}
	if ((option_overload == 2) || (option_overload == 3)) {
		print_options(fp, p->sname, sizeof(p->sname));
	}
} 

const char *program_name = "dug";

void
get_program_name(int argc, char *argv[]) {
	if (argc > 0) {
		program_name = strrchr(argv[0], '/');
		if (program_name != NULL) {
			program_name++;
		} else {
			program_name = argv[0];
		}
	}
}

void
err_exit(int err_num, const char *fmt, ...) {
	va_list ap;

	err_num = errno;
	if (program_name != NULL) {
		fprintf(stderr, "%s: ", program_name);
	}
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	if (err_num != 0) { 
		fprintf(stderr, ", error %d; %s", errno, strerror(errno));
	}
	putc('\n', stderr);
	exit(1);
}

void 
usage(void) {
	fprintf(stderr, "Usage: %s [-v] [-c client_address:port] "
	                "[-s server_address:port] lease\n", program_name);
	fprintf(stderr, "\n");
	fprintf(stderr, "lease is the lease to query for, and may be:\n");
	fprintf(stderr, "  - an IP address, like 192.0.2.17\n");
	fprintf(stderr, "  - an MAC address, like 00:14:22:D9:65:72\n");
	fprintf(stderr, "  - a client identifer, like \"foobar\" or "
		        "'\\x66\\157\\x6Fba\\162'\n");
	exit(1);
}

/*
 * Parse the string into address and port. The string can be either a
 * literal IPv4 address or a hostname, in which case we are lazy and
 * just take whatever gethostbyname() returns to us.
 *
 * A port can also be specified, like "192.0.2.17:1234". If there is
 * no port, then the port value is not changed.
 */
void
parse_address_and_port(const char *s, struct in_addr *addr, int *port) {
	char *tmp_str;
	char *p;
	char *endptr;
	struct hostent *h;

	tmp_str = strdup(s);
	if (tmp_str == NULL) {
		err_exit(0, "Out of memory\n");
	}

	/* 
	 * Pull out the port, if specified.
	 */
	p = strchr(tmp_str, ':');
	if (p != NULL) {
		*port = strtol(p+1, &endptr, 10);
		if ((*port < 1) || (*port > 65535) || (*endptr != '\0')) {
			err_exit(0, "Port must be between 1 and 65535");
		}
		*p = '\0';
	}

	/* 
	 * Get the address (try parsing an IPv4 number first, then
	 * do a hostname lookup).
	 */
	if (inet_aton(tmp_str, addr) == 0) {
		h = gethostbyname(tmp_str);
		if ((h == NULL) || (h->h_addrtype != AF_INET)) {
			err_exit(0, "Invalid host name");
		}
		memcpy(addr, h->h_addr, sizeof(*addr));
	}

	free(tmp_str);
}

int
hexchar_val(unsigned char c) {
	if ((c >= '0') && (c <= '9')) {
		return c - '0';
	}
	if ((c >= 'A') && (c <= 'F')) {
		return c - 'A' + 10;
	}
	if ((c >= 'a') && (c <= 'f')) {
		return c - 'a' + 10;
	}
	return -1;
}

/*
 * MAC addresses must look like "00:16:6F:49:7D:9B", but can be
 * uppercase or lowercase. Leading zeros are required.
 */
int
parse_mac_address(const char *s, unsigned char *mac) {
	int i;
		
	/* 
	 * Verify we have the correct length.
	 */ 
	if (strlen(s) != 17) {
		return 0;
	}

	/*
	 * Verify we have the separating colons in the correct places.
	 */
	for (i=0; i<5; i++) {
		if (s[(i*3)+2] != ':') {
			return 0;
		}
	}

	/*
	 * Calculate our values.
	 */
	for (i=0; i<6; i++) {
		if (!isxdigit(s[i*3])) {
			return 0;
		}
		if (!isxdigit(s[(i*3)+1])) {
			return 0;
		}
		mac[i] = (hexchar_val(s[i*3]) << 4) | hexchar_val(s[(i*3) + 1]);
	}

	return 1;
}

/*
 * Handle the given string the same way as ANSI-C (except rather than
 * giving a parse error, we try to deal with bad escaped data).
 *
 * The returned value is allocated, and must be freed by the caller.
 *
 * This function is useful for specifying client identifiers on the
 * command line.
 */
char *
unescape_string(const char *s) {
	char *r;
	char *p;

	r = (char *)malloc(strlen(s)+1);
	if (r == NULL) {
		err_exit(0, "Out of memory\n");
	}

	p = r;
	while (*s != '\0') {
		if (*s == '\\') {
			s++;
			switch (*s) {
				case 'a': 
					*p++ = '\a';
					s++;
					break;
				case 'b':
					*p++ = '\b';
					s++;
					break;
				case 'f':
					*p++ = '\f';
					s++;
					break;
				case 'n':
					*p++ = '\n';
					s++;
					break;
				case 'r':
					*p++ = '\r';
					s++;
					break;
				case 't':
					*p++ = '\t';
					s++;
					break;
				case 'v':
					*p++ = '\v';
					s++;
					break;
				case 'x':
					s++;
					if (isxdigit(*s)) {
						*p = hexchar_val(*s);
						s++;
						if (isxdigit(*s)) {
							*p <<= 4;
							*p |= hexchar_val(*s);
							s++;
						}
						p++;
					}
					break;
				case '0': case '1': case '2': case '3': 
				case '4': case '5': case '6': case '7':
					*p = *s - '0';
					s++;
					if ((*s >= '0') && (*s <= '7')) {
						*p <<= 3;
						*p |= (*s - '0');
						s++;
					}
					if ((*s >= '0') && (*s <= '7')) {
						*p <<= 3;
						*p |= (*s - '0');
						s++;
					}
					p++;
					break;
				/* default is nothing... "\q" becomes "q" */
			}
		} else {
			*p++ = *s++;
		}
	}
	*p = '\0';

	return r;
}

int
local_socket(struct in_addr *addr, int port) {
	int sock;
	struct sockaddr_in sock_addr;

	memset(&sock_addr, 0, sizeof(sock_addr));
	sock_addr.sin_family = AF_INET;
	sock_addr.sin_port = htons(port);
	if (addr == NULL) {
		sock_addr.sin_addr.s_addr = INADDR_ANY;
	} else {
		sock_addr.sin_addr = *addr;
	}

	sock = socket(PF_INET, SOCK_DGRAM, 0);
	if (sock == -1) {
		err_exit(errno, "Unable to create socket");
	}
	if (bind(sock, (struct sockaddr *)&sock_addr, sizeof(sock_addr)) != 0) {
		err_exit(errno, "Unable to bind socket address");
	}
	return sock;
}

/* 
 * Make sure our timeval structure has a microsecond between 0 and 999999.
 */
void
normalize_time(struct timeval *t) {
	while (t->tv_usec < 0) {
		t->tv_sec -= 1;
		t->tv_usec += 1000000;
	}
	while (t->tv_usec > 1000000) {
		t->tv_sec += 1;
		t->tv_usec -= 1000000;
	}
}


int
main(int argc, char *argv[]) {
	unsigned char packet[65536];
	struct dhcp_packet *p;
	int op_ofs;
	int xid;
	int sock;
	struct sockaddr_in addr;
	int retval;
	fd_set rfds, wfds, efds;
	struct timeval timeout;
	struct timeval start;
	struct timeval now, end;
	int packet_len;

	/* command-line arguments */
	int c;
	struct in_addr client_address;
	int client_port;
	struct in_addr server_address;
	int server_port;
	int verbose;

	/* possible query types */
	struct in_addr lease_addr;
	unsigned char mac[6];
	char *tmp_str;
	int len;
	char *print_str;

	get_program_name(argc, argv);

	memset(&client_address, 0, sizeof(client_address));
	client_port = 68;
	memset(&server_address, 0, sizeof(server_address));
	server_port = 67;
	timeout.tv_sec = DEFAULT_TIMEOUT;
	timeout.tv_usec = 0;
	verbose = 0;

	opterr = 0;
	while ((c = getopt(argc, argv, "c:s:v")) != -1) {
		switch (c) {
			case 'c':
				parse_address_and_port(optarg,
						       &client_address,
						       &client_port);
				break;
			case 's':
				parse_address_and_port(optarg,
						       &server_address,
						       &server_port);
				break;
			case 'v':
				verbose++;
				break;
			case '?':
			default:
				usage();
		}
	}

	if (opterr || (optind != argc-1)) {
		usage();
	}

	if (verbose) {
		printf("# Sending query from %s:%d\n", 
		       inet_ntoa(client_address), 
		       client_port);
		printf("# Sending query to %s:%d\n", 
		       inet_ntoa(server_address), 
		       server_port);
	}

	/* 
	 * Build the query packet.
	 */
	memset(packet, '\0', sizeof(packet));
	p = (struct dhcp_packet *)packet;
	p->opcode = 1;
	p->htype = 1;
	p->hlen = 6;
	srand48(time(NULL));
	xid = mrand48();
	memcpy(p->xid, &xid, 4);
	op_ofs = sizeof(struct dhcp_packet);
	memcpy(p->giaddr, &client_address, 4);

	/*
	 * Add the DHCP option cookie.
	 */
	packet[op_ofs++] = 99;
	packet[op_ofs++] = 130;
	packet[op_ofs++] = 83;
	packet[op_ofs++] = 99;

	/* 
	 * Set the DHCP message type.
	 */
	packet[op_ofs++] = DHCP_OPTION_MESSAGE_TYPE;
	packet[op_ofs++] = 1;
	packet[op_ofs++] = DHCPLEASEQUERY;

	/*
	 * Set the lease information we are looking for.
	 */
	if (inet_aton(argv[optind], &lease_addr) != 0) {
		memcpy(p->ciaddr, &lease_addr, 4);
		if (verbose) {
			printf("# Querying for IP address: %s\n", 
			       inet_ntoa(lease_addr));
		}
	} else {
		if (parse_mac_address(argv[optind], mac)) {
			memcpy(p->chaddr, mac, 6);
			if (verbose) {
				printf("# Querying for MAC address: %s\n",
				       argv[optind]);
			}
		} else {
			tmp_str = unescape_string(argv[optind]);
			len = strlen(tmp_str);
			if (len > 255) {
				err_exit(0, "Client identifier too long");
			}

			if (verbose) {
				print_str = printable_string(tmp_str, len);
				printf("# Querying for client identifier: %s\n",
				       print_str);
				free(print_str);
			}

			packet[op_ofs++] = DHCP_OPTION_CLIENT_ID;
			packet[op_ofs++] = len;
			memcpy(&packet[op_ofs], tmp_str, len);
			op_ofs += len;
			free(tmp_str);

		}
	}

	if (verbose) {
		printf("\n");
		printf("# Query packet\n");
		printf("#\n");
		print_dhcp_packet(stdout, (struct dhcp_packet *)packet, op_ofs);
		printf("\n");
	}


	/* send the query */
	sock = local_socket(&client_address, client_port);
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(server_port);
	addr.sin_addr = server_address;
	retval = sendto(sock, 
			packet, 
			op_ofs, 
			0, 
			(struct sockaddr *)&addr, 
			sizeof(addr));
	if (retval == -1) {
		err_exit(errno, "Error sending packet");
	}

	/* 
	 * Calculate our timeout.
	 */
	gettimeofday(&start, NULL);
	end = start;
	end.tv_sec += timeout.tv_sec;
	end.tv_usec += timeout.tv_usec;
	normalize_time(&end);

	do {
		/* 
	 	 * Wait for the reply.
	 	 */ 
		FD_ZERO(&rfds);
		FD_SET(sock, &rfds);
		FD_ZERO(&wfds);
		FD_ZERO(&efds);
		gettimeofday(&now, NULL);
		timeout.tv_sec = end.tv_sec - now.tv_sec;
		timeout.tv_usec = end.tv_usec - now.tv_usec;
		normalize_time(&timeout);
		if (select(sock+1, &rfds, &wfds, &efds, &timeout) == -1) {
			err_exit(errno, "Error in waiting for reply");
		}
		if (!FD_ISSET(sock, &rfds)) {
			printf("Timeout\n");
			exit(1);
		}

		/* 
	 	 * Read reply.
	 	 */
		packet_len = recv(sock, packet, sizeof(packet), 0);
		if (packet_len == -1) {
			err_exit(errno, "Error reading reply");
		}

	} while ((packet_len < sizeof(struct dhcp_packet)) || 
		 (memcmp(p->xid, &xid, 4) != 0));
	gettimeofday(&now, NULL);

	printf("# Reply packet\n");
	printf("#\n");
	print_dhcp_packet(stdout, (struct dhcp_packet *)packet, packet_len);
	printf("\n");

	if (verbose) {
		/* 
		 * Technically we may want to count the time spent in
		 * DNS lookups and the like, but we will just time
		 * when we sent until now.
		 */
		now.tv_sec -= start.tv_sec;
		now.tv_usec -= start.tv_usec;
		normalize_time(&now);
		printf("# Query took %d.%06d seconds\n", 
		       now.tv_sec, 
		       now.tv_usec);
	}
	return 0;
}

