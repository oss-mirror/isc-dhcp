/* dhctra.c

   DHCP IPv6-Transport Relay Agent. */

/*
 * Copyright(c) 2004-2012 by Internet Systems Consortium, Inc.("ISC")
 * Copyright(c) 1997-2003 by Internet Software Consortium
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
 *   https://www.isc.org/
 *
 * This software has been written for Internet Systems Consortium
 * by Ted Lemon in cooperation with Vixie Enterprises and Nominum, Inc.
 * To learn more about Internet Systems Consortium, see
 * ``https://www.isc.org/''.  To learn more about Vixie Enterprises,
 * see ``http://www.vix.com''.   To learn more about Nominum, Inc., see
 * ``http://www.nominum.com''.
 */

#include "dhcpd.h"

#ifdef DHCPv6

#include <syslog.h>
#include <sys/time.h>

TIME default_lease_time = 43200; /* 12 hours... */
TIME max_lease_time = 86400; /* 24 hours... */
struct tree_cache *global_options[256];

struct option *requested_opts[2];

/* Needed to prevent linking against conflex.c. */
int lexline;
int lexchar;
char *token_line;
char *tlname;

const char *path_dhcrelay_pid = _PATH_DHCRELAY_PID;
isc_boolean_t no_dhcrelay_pid = ISC_FALSE;
/* False (default) => we write and use a pid file */
isc_boolean_t no_pid_file = ISC_FALSE;

int bogus_agent_drops = 0;	/* Packets dropped because agent option
				   field was specified and we're not relaying
				   packets that already have an agent option
				   specified. */
int bogus_giaddr_drops = 0;	/* Packets sent to us to relay back to a
				   client, but with a bogus giaddr. */
int client_packets_relayed = 0;	/* Packets relayed from client to server. */
int server_packet_errors = 0;	/* Errors sending packets to servers. */
int server_packets_relayed = 0;	/* Packets relayed from server to client. */
int client_packet_errors = 0;	/* Errors sending packets to clients. */

int add_agent_options = 0;	/* If nonzero, add relay agent options. */

int agent_option_errors = 0;    /* Number of packets forwarded without
				   agent options because there was no room. */
int drop_agent_mismatches = 0;	/* If nonzero, drop server replies that
				   don't have matching circuit-id's. */
int corrupt_agent_options = 0;	/* Number of packets dropped because
				   relay agent information option was bad. */
int missing_agent_option = 0;	/* Number of packets dropped because no
				   RAI option matching our ID was found. */
int bad_circuit_id = 0;		/* Circuit ID option in matching RAI option
				   did not match any known circuit ID. */
int missing_circuit_id = 0;	/* Circuit ID option in matching RAI option
				   was missing. */
int missing_cra6addr = 0;	/* CRA6ADDR option in matching RAI option
				   was missing. */
int unknown_server = 0;		/* IPv4 responses from an unknown server. */
int max_hop_count = 10;		/* Maximum hop count */

	/* Maximum size of a packet with agent options added. */
int dhcp_max_agent_option_packet_length = DHCP_MTU_MIN;

u_int16_t local_port;
u_int16_t remote_port;

/* Relay agent server list. */
struct server_list {
	struct server_list *next;
	struct sockaddr_in to;
	struct in_addr src;
} *servers;

struct interface_info *if6;

static void do_relay6to4(struct interface_info *, const char *, int, int,
			 const struct iaddr *, isc_boolean_t);
static void do_relay4to6(struct interface_info *, struct dhcp_packet *,
			 unsigned int, unsigned int, struct iaddr,
			 struct hardware *);
static int add_relay_agent_options(struct interface_info *,
				   struct dhcp_packet *, unsigned,
				   const struct iaddr *);
static int find_ipv6_by_agent_option(struct dhcp_packet *,
				     struct in6_addr *, u_int8_t *, int);
static int strip_relay_agent_options(struct interface_info *,
				     struct in6_addr *,
				     struct dhcp_packet *, unsigned);
static void set_server_src(struct server_list *);

static const char copyright[] =
"Copyright 2004-2012 Internet Systems Consortium.";
static const char arr[] = "All rights reserved.";
static const char message[] =
"Internet Systems Consortium DHCP IPv6-Transport Relay Agent";
static const char url[] =
"For info, please visit https://www.isc.org/software/dhcp/";

#define DHCTRA_USAGE \
"Usage: dhctra [-d] [-q] [-a] [-D] [-A <length>] [-c <hops>] [-p <port>]\n" \
"              [-pf <pid-file>] [--no-pid] server0 [ ... serverN]\n\n"

static void usage() {
	log_fatal(DHCTRA_USAGE);
}

int 
main(int argc, char **argv) {
	isc_result_t status;
	struct servent *ent;
	struct server_list *sp = NULL;
	struct interface_info *tmp = NULL;
	char *service_local = NULL, *service_remote = NULL;
	u_int16_t port_local = 0, port_remote = 0;
	int no_daemon = 0, quiet = 0;
	int fd;
	int i;

	/* Make sure that file descriptors 0(stdin), 1,(stdout), and
	   2(stderr) are open. To do this, we assume that when we
	   open a file the lowest available file descriptor is used. */
	fd = open("/dev/null", O_RDWR);
	if (fd == 0)
		fd = open("/dev/null", O_RDWR);
	if (fd == 1)
		fd = open("/dev/null", O_RDWR);
	if (fd == 2)
		log_perror = 0; /* No sense logging to /dev/null. */
	else if (fd != -1)
		close(fd);

	openlog("dhctra", LOG_NDELAY, LOG_DAEMON);

#if !defined(DEBUG)
	setlogmask(LOG_UPTO(LOG_INFO));
#endif	

	/* Set up the isc and dns library managers */
	status = dhcp_context_create();
	if (status != ISC_R_SUCCESS)
		log_fatal("Can't initialize context: %s",
			  isc_result_totext(status));

	/* Set up the OMAPI. */
	status = omapi_init();
	if (status != ISC_R_SUCCESS)
		log_fatal("Can't initialize OMAPI: %s",
			   isc_result_totext(status));

	/* Set up the OMAPI wrappers for the interface object. */
	interface_setup();

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-d")) {
			no_daemon = 1;
		} else if (!strcmp(argv[i], "-q")) {
			quiet = 1;
			quiet_interface_discovery = 1;
		} else if (!strcmp(argv[i], "-p")) {
			if (++i == argc)
				usage();
			local_port = validate_port(argv[i]);
			log_debug("binding to user-specified port %d",
				  ntohs(local_port));
		} else if (!strcmp(argv[i], "-c")) {
			int hcount;
			if (++i == argc)
				usage();
			hcount = atoi(argv[i]);
			if (hcount <= 255)
				max_hop_count= hcount;
			else
				usage();
		} else if (!strcmp(argv[i], "-a")) {
			add_agent_options = 1;
		} else if (!strcmp(argv[i], "-A")) {
			if (++i == argc)
				usage();

			dhcp_max_agent_option_packet_length = atoi(argv[i]);

			if (dhcp_max_agent_option_packet_length > DHCP_MTU_MAX)
				log_fatal("%s: packet length exceeds "
					  "longest possible MTU\n",
					  argv[i]);
		} else if (!strcmp(argv[i], "-D")) {
			drop_agent_mismatches = 1;
		} else if (!strcmp(argv[i], "-pf")) {
			if (++i == argc)
				usage();
			path_dhcrelay_pid = argv[i];
			no_dhcrelay_pid = ISC_TRUE;
		} else if (!strcmp(argv[i], "--no-pid")) {
			no_pid_file = ISC_TRUE;
		} else if (!strcmp(argv[i], "--version")) {
			log_info("isc-dhctra-%s", PACKAGE_VERSION);
			exit(0);
		} else if (!strcmp(argv[i], "--help") ||
			   !strcmp(argv[i], "-h")) {
			log_info(DHCTRA_USAGE);
			exit(0);
 		} else if (argv[i][0] == '-') {
			usage();
 		} else {
			struct hostent *he;
			struct in_addr ia, *iap = NULL;

			if (inet_aton(argv[i], &ia)) {
				iap = &ia;
			} else {
				he = gethostbyname(argv[i]);
				if (!he) {
					log_error("%s: host unknown", argv[i]);
				} else {
					iap = ((struct in_addr *)
					       he->h_addr_list[0]);
				}
			}

			if (iap) {
				sp = ((struct server_list *)
				      dmalloc(sizeof *sp, MDL));
				if (!sp)
					log_fatal("no memory for server.\n");
				sp->next = servers;
				servers = sp;
				memcpy(&sp->to.sin_addr, iap, sizeof *iap);
			}
 		}
	}

	/*
	 * If the user didn't specify a pid file directly
	 * find one from environment variables or defaults
	 */
	if (no_dhcrelay_pid == ISC_FALSE) {
		path_dhcrelay_pid = getenv("PATH_DHCRELAY6_PID");
		if (path_dhcrelay_pid == NULL)
			path_dhcrelay_pid = getenv("PATH_DHCRELAY_PID");
		if (path_dhcrelay_pid == NULL)
			path_dhcrelay_pid = _PATH_DHCRELAY_PID;
	}

	if (!quiet) {
		log_info("%s %s", message, PACKAGE_VERSION);
		log_info(copyright);
		log_info(arr);
		log_info(url);
	} else {
		quiet = 0;
		log_perror = 0;
	}

	/* Set default port */
	service_local = "bootps";
	service_remote = "bootpc";
	port_local = htons(67);
	port_remote = htons(68);

	if (!local_port) {
		ent = getservbyname(service_local, "udp");
		if (ent)
			local_port = ent->s_port;
		else
			local_port = port_local;

		ent = getservbyname(service_remote, "udp");
		if (ent)
			remote_port = ent->s_port;
		else
			remote_port = port_remote;

		endservent();
	}

	/* We need at least one server */
	if (servers == NULL) {
		log_fatal("No servers specified.");
	}

	/* Set up the server sockaddrs. */
	for (sp = servers; sp; sp = sp->next) {
		sp->to.sin_port = local_port;
		sp->to.sin_family = AF_INET;
#ifdef HAVE_SA_LEN
		sp->to.sin_len = sizeof sp->to;
#endif
		set_server_src(sp);
	}

	/* Get the current time... */
	gettimeofday(&cur_tv, NULL);

	/* Discover all the network interfaces. */
	local_family = AF_INET;
	discover_interfaces(DISCOVER_RELAY);

	/* Get the IPv6 socket. */
	local_family = AF_INET6;
	discover_interfaces(DISCOVER_RUNNING);
	status = interface_allocate(&if6, MDL);
	if (status != ISC_R_SUCCESS)
		log_fatal("interface_allocate: %s", isc_result_totext(status));
	strcpy(if6->name, "ipv6");
	interface_snorf(if6, 0);
	tmp = if6;
	interface_dereference(&tmp, MDL);
	if_register6(if6, 0);

	/* Become a daemon... */
	if (!no_daemon) {
		int pid;
		FILE *pf;
		int pfdesc;

		log_perror = 0;

		if ((pid = fork()) < 0)
			log_fatal("Can't fork daemon: %m");
		else if (pid)
			exit(0);

		if (no_pid_file == ISC_FALSE) {
			pfdesc = open(path_dhcrelay_pid,
				      O_CREAT | O_TRUNC | O_WRONLY, 0644);

			if (pfdesc < 0) {
				log_error("Can't create %s: %m",
					  path_dhcrelay_pid);
			} else {
				pf = fdopen(pfdesc, "w");
				if (!pf)
					log_error("Can't fdopen %s: %m",
						  path_dhcrelay_pid);
				else {
					fprintf(pf, "%ld\n",(long)getpid());
					fclose(pf);
				}	
			}
		}

		close(0);
		close(1);
		close(2);
		pid = setsid();

		IGNORE_RET (chdir("/"));
	}

	/* Set up the packet handler... */
	bootp_packet_handler = do_relay4to6;
	dhcpv6_packet_handler = do_relay6to4;

	/* Start dispatching packets and timeouts... */
	dispatch();

	/* Not reached */
	return (0);
}

/* From IPv6 to IPv4 BOOTREQUEST: forward it to all the servers. */

static void
do_relay6to4(struct interface_info *ip, const char *msg,
	     int len, int from_port, const struct iaddr *from,
	     isc_boolean_t was_unicast) {
	struct dhcp_packet *packet;
	struct server_list *sp;
	unsigned int length;

	packet = (struct dhcp_packet *)msg;
	length = (unsigned int)len;

	if (packet->hlen > sizeof packet->chaddr) {
		log_info("Discarding packet with invalid hlen, received on "
			 "%s v6 interface.", ip->name);
		return;
	}

	if (packet->op != BOOTREQUEST)
		return;

	/* only from a CRA */
	if (packet->giaddr.s_addr)
		return;

	/* Add relay agent options. If something goes wrong,
	   drop the packet. */
	if ((length = add_relay_agent_options(ip, packet, length, from)) == 0)
		return;

	if (packet->hops < max_hop_count)
		packet->hops = packet->hops + 1;
	else
		return;

	for (sp = servers; sp; sp = sp->next) {
		packet->giaddr.s_addr = sp->src.s_addr;
		if (send_packet((fallback_interface
				 ? fallback_interface : interfaces),
				 NULL, packet, length, sp->src,
				 &sp->to, NULL) < 0) {
			++client_packet_errors;
		} else {
			log_debug("Forwarded BOOTREQUEST for %s to %s",
				  print_hw_addr(packet->htype, packet->hlen,
						packet->chaddr),
				  inet_ntoa(sp->to.sin_addr));
			++client_packets_relayed;
		}
	}
				 
}

/* From IPv4 to IPv6 BOOTREPLY: forward it to the CRA. */

static void
do_relay4to6(struct interface_info *ip, struct dhcp_packet *packet,
	     unsigned int length, unsigned int from_port, struct iaddr from,
	     struct hardware *hfrom) {
	struct in_addr fromin;
	struct server_list *sp;
	struct sockaddr_in6 to;
	struct interface_info *out;

	if (packet->hlen > sizeof packet->chaddr) {
		log_info("Discarding packet with invalid hlen, received on "
			 "%s v4 interface.", ip->name);
		return;
	}

	if (packet->op != BOOTREPLY)
		return;

	/* Check if it comes from a configured server. */
	memcpy(&fromin, from.iabuf, sizeof(fromin));
	for (sp = servers; sp; sp = sp->next)
		if (fromin.s_addr == sp->to.sin_addr.s_addr)
			break;
	if (sp == NULL) {
		log_info("Discarding packet from unknown server '%s'.",
			 inet_ntoa(fromin));
		unknown_server++;
		return;
	}

	/* Find the interface that corresponds to the giaddr
	   in the packet. */
	if (packet->giaddr.s_addr) {
		for (out = interfaces; out; out = out->next) {
			int i;

			for (i = 0 ; i < out->address_count ; i++ ) {
				if (out->addresses[i].s_addr ==
				    packet->giaddr.s_addr)
					i = -1;
					break;
			}

			if (i == -1)
				break;
		}
	} else {
		out = NULL;
	}

	if (!out) {
		log_error("Packet to bogus giaddr %s.\n",
			  inet_ntoa(packet->giaddr));
		++bogus_giaddr_drops;
		return;
	}

	memset(&to, 0, sizeof(to));
	to.sin6_family = AF_INET6;
#ifdef HAVE_SA_LEN
	to.sin6_len = sizeof(to);
#endif
	to.sin6_port = remote_port;

	/* Wipe out the agent relay options and, if possible, figure
	   out which IPv6 address to use based on the contents of the
	   option that we put on the request to which the server is
	   replying. */
	if ((length = strip_relay_agent_options(ip,
						&to.sin6_addr,
						packet,
						length)) == 0)
		return;

	if (sendto(if6->wfdesc, (unsigned char *)packet, length, 0,
		   (struct sockaddr *)&to, sizeof(to)) < 0) {
		++server_packet_errors;
	} else {
		char addrbuf[MAX_ADDRESS_STRING_LEN];

		inet_ntop(AF_INET6, &to.sin6_addr, addrbuf,
			  MAX_ADDRESS_STRING_LEN);
		log_debug("Forwarded BOOTREPLY for %s to %s",
			  print_hw_addr(packet->htype, packet->hlen,
					packet->chaddr),
			  addrbuf);
		++server_packets_relayed;
	}
}

/* Strip any Relay Agent Information options from the DHCP packet
   option buffer.   If there is a CRA6ADDR suboption, look up the
   IPv6 address of the CRA based upon it. */

static int
strip_relay_agent_options(struct interface_info *in,
			  struct in6_addr *addr,
			  struct dhcp_packet *packet,
			  unsigned length) {
	int is_dhcp = 0;
	u_int8_t *op, *nextop, *sp, *max;
	int good_agent_option = 0;
	int status;

	/* If there's no cookie, it's a bootp packet, drop it. */
	if (memcmp(packet->options, DHCP_OPTIONS_COOKIE, 4))
		return (0);

	max = ((u_int8_t *)packet) + length;
	sp = op = &packet->options[4];

	while (op < max) {
		switch(*op) {
			/* Skip padding... */
		      case DHO_PAD:
			if (sp != op)
				*sp = *op;
			++op;
			++sp;
			continue;

			/* If we see a message type, it's a DHCP packet. */
		      case DHO_DHCP_MESSAGE_TYPE:
			is_dhcp = 1;
			goto skip;
			break;

			/* Quit immediately if we hit an End option. */
		      case DHO_END:
			if (sp != op)
				*sp++ = *op++;
			goto out;

		      case DHO_DHCP_AGENT_OPTIONS:
			/* We shouldn't see a relay agent option in a
			   packet before we've seen the DHCP packet type,
			   but if we do, we have to leave it alone. */
			if (!is_dhcp)
				goto skip;

			/* Do not process an agent option if it exceeds the
			 * buffer.  Fail this packet.
			 */
			nextop = op + op[1] + 2;
			if (nextop > max)
				return (0);

			status = find_ipv6_by_agent_option(packet, addr,
							   op + 2, op[1]);
			if (status == -1)
				return (0);
			good_agent_option = 1;
			op = nextop;
			break;

		      skip:
			/* Skip over other options. */
		      default:
			/* Fail if processing this option will exceed the
			 * buffer(op[1] is malformed).
			 */
			nextop = op + op[1] + 2;
			if (nextop > max)
				return (0);

			if (sp != op) {
				memmove(sp, op, op[1] + 2);
				sp += op[1] + 2;
				op = nextop;
			} else
				op = sp = nextop;

			break;
		}
	}
      out:

	/* If it's not a DHCP packet, drop it. */
	if (!is_dhcp)
		return (0);

	/* If none of the agent options we found matched, or if we didn't
	   find any agent options, count this packet as not having any
	   matching agent options, and if we're relying on agent options
	   to determine the IPv6 address, drop the packet. */

	if (!good_agent_option) {
		++missing_agent_option;
		return (0);
	}

	/* Adjust the length... */
	if (sp != op) {
		length = sp - ((u_int8_t *)packet);

		/* Make sure the packet isn't short(this is unlikely,
		   but WTH) */
		if (length < BOOTP_MIN_LEN) {
			memset(sp, DHO_PAD, BOOTP_MIN_LEN - length);
			length = BOOTP_MIN_LEN;
		}
	}
	return (length);
}


/* Find the CRA IPv6 address from the CRA6ADDR suboption, and
   find an interface that matches the circuit ID specified in the
   Relay Agent Information option.

   We actually deviate somewhat from the current specification here:
   if the option buffer is corrupt, we suggest that the caller not
   respond to this packet.  If the circuit ID doesn't match any known
   interface, we suggest that the caller to drop the packet.  Only if
   we find a circuit ID that matches an existing interface do we tell
   the caller to go ahead and process the packet. */

static int
find_ipv6_by_agent_option(struct dhcp_packet *packet,
			  struct in6_addr *addr,
			  u_int8_t *buf, int len) {
	int i = 0;
	u_int8_t *circuit_id = 0;
	unsigned circuit_id_len = 0;
	unsigned got_cra6addr = 0;
	struct interface_info *ip;

	while (i < len) {
		/* If the next agent option overflows the end of the
		   packet, the agent option buffer is corrupt. */
		if (i + 1 == len ||
		    i + buf[i + 1] + 2 > len) {
			++corrupt_agent_options;
			return (-1);
		}
		switch(buf[i]) {
			/* Remember where the circuit ID is... */
		      case RAI_CIRCUIT_ID:
			circuit_id = &buf[i + 2];
			circuit_id_len = buf[i + 1];
			i += circuit_id_len + 2;
			break;

			/* Require one cra6addr. */
		      case RAI_CRA6ADDR:
			if (buf[i + 1] != 16) {
				++corrupt_agent_options;
				return (-1);
			}
			memcpy(addr, buf + i + 2, 16);
			++got_cra6addr;
			i += buf[i + 1] + 2;
			break;

		      default:
			i += buf[i + 1] + 2;
			break;
		}
	}

	/* If there's no cra6addr, it is bad. */
	if (got_cra6addr != 1) {
		++missing_cra6addr;
		return (-1);
	}

	/* If there's no circuit ID, it's not really ours, tell the caller
	   it's no good. */
	if (!circuit_id) {
		if (add_agent_options) {
			++missing_circuit_id;
			return (-1);
		}
		return (1);
	}

	/* Scan the interface list looking for an interface whose
	   name matches the one specified in circuit_id. */

	for (ip = interfaces; ip; ip = ip->next) {
		if (ip->circuit_id &&
		    ip->circuit_id_len == circuit_id_len &&
		    !memcmp(ip->circuit_id, circuit_id, circuit_id_len))
			return (1);
	}

	/* If we didn't get a match, the circuit ID was bogus. */
	++bad_circuit_id;
	return (-1);
}

/*
 * Examine a packet to see if it's a candidate to have a Relay
 * Agent Information option tacked onto its tail.   If it is, tack
 * the option on.
 */
static int
add_relay_agent_options(struct interface_info *ip, struct dhcp_packet *packet,
			unsigned length, const struct iaddr *addr) {
	int is_dhcp = 0, mms;
	unsigned optlen;
	u_int8_t *op, *nextop, *sp, *max, *end_pad = NULL;

	/* If there's no cookie, it's a bootp packet, so drop it. */
	if (memcmp(packet->options, DHCP_OPTIONS_COOKIE, 4))
		return (0);

	max = ((u_int8_t *)packet) + dhcp_max_agent_option_packet_length;

	/* Commence processing after the cookie. */
	sp = op = &packet->options[4];

	while (op < max) {
		switch(*op) {
			/* Skip padding... */
		      case DHO_PAD:
			/* Remember the first pad byte so we can commandeer
			 * padded space.
			 *
			 * XXX: Is this really a good idea?  Sure, we can
			 * seemingly reduce the packet while we're looking,
			 * but if the packet was signed by the client then
			 * this padding is part of the checksum(RFC3118),
			 * and its nonpresence would break authentication.
			 */
			if (end_pad == NULL)
				end_pad = sp;

			if (sp != op)
				*sp++ = *op++;
			else
				sp = ++op;

			continue;

			/* If we see a message type, it's a DHCP packet. */
		      case DHO_DHCP_MESSAGE_TYPE:
			is_dhcp = 1;
			goto skip;

			/*
			 * If there's a maximum message size option, we
			 * should pay attention to it
			 */
		      case DHO_DHCP_MAX_MESSAGE_SIZE:
			mms = ntohs(*(op + 2));
			if (mms < dhcp_max_agent_option_packet_length &&
			    mms >= DHCP_MTU_MIN)
				max = ((u_int8_t *)packet) + mms;
			goto skip;

			/* Quit immediately if we hit an End option. */
		      case DHO_END:
			goto out;

		      case DHO_DHCP_AGENT_OPTIONS:
			/* We shouldn't see a relay agent option in a
			   packet before we've seen the DHCP packet type,
			   but if we do, we have to leave it alone. */
			if (!is_dhcp)
				goto skip;

			end_pad = NULL;

			/* There's already a Relay Agent Information option
			   in this packet. Drop it. */

			return (0);

		      skip:
			/* Skip over other options. */
		      default:
			/* Fail if processing this option will exceed the
			 * buffer(op[1] is malformed).
			 */
			nextop = op + op[1] + 2;
			if (nextop > max)
				return (0);

			end_pad = NULL;

			if (sp != op) {
				memmove(sp, op, op[1] + 2);
				sp += op[1] + 2;
				op = nextop;
			} else
				op = sp = nextop;

			break;
		}
	}
      out:

	/* If it's not a DHCP packet, drop it. */
	if (!is_dhcp)
		return (0);

	/* If the packet was padded out, we can store the agent option
	   at the beginning of the padding. */

	if (end_pad != NULL)
		sp = end_pad;

	/* Remember where the end of the packet was after parsing
	   it. */
	op = sp;

	/* Count the cra6addr (RAI_CRA6ADDR + len + IPv6 Address) */
	optlen = 18;

	/* Jump further if we want only the cra6addr. */
	if (!add_agent_options)
		goto mandatory_only;

	/* Sanity check.  Had better not ever happen. */
	if ((ip->circuit_id_len > 255) ||(ip->circuit_id_len < 1))
		log_fatal("Circuit ID length %d out of range [1-255] on "
			  "%s\n", ip->circuit_id_len, ip->name);
	optlen += ip->circuit_id_len + 2;           /* RAI_CIRCUIT_ID + len */

	if (ip->remote_id) {
		if (ip->remote_id_len > 255 || ip->remote_id_len < 1)
			log_fatal("Remote ID length %d out of range [1-255] "
				  "on %s\n", ip->circuit_id_len, ip->name);
		optlen += ip->remote_id_len + 2;    /* RAI_REMOTE_ID + len */
	}

    mandatory_only:
	/* We do not support relay option fragmenting(multiple options to
	 * support an option data exceeding 255 bytes).
	 */
	if ((optlen < 3) ||(optlen > 255))
		log_fatal("Total agent option length(%u) out of range "
			   "[3 - 255] on %s\n", optlen, ip->name);

	/*
	 * Is there room for the option, its code+len, and DHO_END?
	 * If not, forward without adding the option.
	 */
	if (max - sp >= optlen + 3) {
		log_debug("Adding %d-byte relay agent option", optlen + 3);

		/* Okay, cons up *our* Relay Agent Information option. */
		*sp++ = DHO_DHCP_AGENT_OPTIONS;
		*sp++ = optlen;

		/* Copy in the cra6addr... */
		*sp++ = RAI_CRA6ADDR;
		*sp++ = 16;
		memcpy(sp, addr->iabuf, 16);
		sp += 16;

		/* Copy in the circuit id... */
		if (add_agent_options) {
			*sp++ = RAI_CIRCUIT_ID;
			*sp++ = ip->circuit_id_len;
			memcpy(sp, ip->circuit_id, ip->circuit_id_len);
			sp += ip->circuit_id_len;

			/* Copy in remote ID... */
			if (ip->remote_id) {
				*sp++ = RAI_REMOTE_ID;
				*sp++ = ip->remote_id_len;
				memcpy(sp, ip->remote_id, ip->remote_id_len);
				sp += ip->remote_id_len;
			}
		}
	} else {
		++agent_option_errors;
		log_error("No room in packet (used %d of %d) "
			  "for %d-byte relay agent option: dropped",
			   (int) (sp - ((u_int8_t *) packet)),
			   (int) (max - ((u_int8_t *) packet)),
			   optlen + 3);
		return (0);
	}

	/*
	 * Deposit an END option unless the packet is full (shouldn't
	 * be possible).
	 */
	if (sp < max)
		*sp++ = DHO_END;

	/* Recalculate total packet length. */
	length = sp - ((u_int8_t *)packet);

	/* Make sure the packet isn't short(this is unlikely, but WTH) */
	if (length < BOOTP_MIN_LEN) {
		memset(sp, DHO_PAD, BOOTP_MIN_LEN - length);
		return (BOOTP_MIN_LEN);
	}

	return (length);
}

/* Find the source address to use with a server. */

static void
set_server_src(struct server_list *sp) {
	int sock;
	socklen_t len;
	struct sockaddr_in src;

	sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sock < 0)
		log_fatal("set_server_src: socket: %m");
	len = sizeof(src);
	if (connect(sock, (struct sockaddr *)&sp->to, len) < 0)
		log_fatal("set_server_src: connect: %m");
	memset(&src, 0, len);
	if (getsockname(sock, (struct sockaddr *)&src, &len) < 0)
		log_fatal("set_server_src: getsockname: %m");
	(void)close(sock);
	sp->src.s_addr = src.sin_addr.s_addr;
}

/* Stub routines needed for linking with DHCP libraries. */
void
bootp(struct packet *packet) {
	return;
}

void
dhcp(struct packet *packet) {
	return;
}

void
dhcp_tsv(struct packet *packet) {
	return;
}

void
classify(struct packet *p, struct class *c) {
	return;
}

int
check_collection(struct packet *p, struct lease *l, struct collection *c) {
	return 0;
}

isc_result_t
find_class(struct class **class, const char *c1, const char *c2, int i) {
	return ISC_R_NOTFOUND;
}

int
parse_allow_deny(struct option_cache **oc, struct parse *p, int i) {
	return 0;
}

isc_result_t
dhcp_set_control_state(control_object_state_t oldstate,
		       control_object_state_t newstate) {
	return ISC_R_SUCCESS;
}

#else

int
main(int argc, char **argv) {
	log_error("Required DHCPv6 support was disabled.");
	return -1;
}
#endif /* DHCPv6 */
