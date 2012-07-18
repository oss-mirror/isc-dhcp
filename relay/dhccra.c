/* dhccra.c

   DHCP Client Relay Agent. */

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

struct in_addr inaddr_any;

int client_packets_relayed = 0;	/* Packets relayed from client to server. */
int server_packet_errors = 0;	/* Errors sending packets to servers. */
int server_packets_relayed = 0;	/* Packets relayed from server to client. */
int client_packet_errors = 0;	/* Errors sending packets to clients. */

int max_hop_count = 10;		/* Maximum hop count */
int colocated_only = -1;	/* Serve only the colocated client. */

u_int16_t local_port;
u_int16_t remote_port;

struct interface_info *if6, *if4 = NULL;

/* server list. */
struct server_list {
	struct server_list *next;
	struct sockaddr_in6 to;
} *servers;

static int getrecv6();
static void do_relay4to6(struct interface_info *, struct dhcp_packet *,
			 unsigned int, unsigned int, struct iaddr,
			 struct hardware *);
static void do_relay6to4(struct interface_info *, const char *, int, int,
			 const struct iaddr *, isc_boolean_t);
static int find_relay_agent_options(struct dhcp_packet *, unsigned int);

static const char copyright[] =
"Copyright 2004-2012 Internet Systems Consortium.";
static const char arr[] = "All rights reserved.";
static const char message[] =
"Internet Systems Consortium DHCP Client Relay Agent";
static const char url[] =
"For info, please visit https://www.isc.org/software/dhcp/";

#define DHCCRA_USAGE \
"Usage: dhccra [-d] [-q] -S {node|link} [-c <hops>] [-p <port>]\n" \
"              [-pf <pid-file>] [--no-pid] [-l{4|6} <local-address>]\n" \
"              -i ifname server0 [ ... serverN]\n\n"

static void usage() {
	log_fatal(DHCCRA_USAGE);
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

	openlog("dhccra", LOG_NDELAY, LOG_DAEMON);

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
		} else if (!strcmp(argv[i], "-S")) {
			if (++i == argc)
				usage();
			if (strcmp(argv[i], "node") == 0)
				colocated_only = 1;
			else if (strcmp(argv[i], "link") == 0)
				colocated_only = 0;
			else
				usage();
		} else if (!strcmp(argv[i], "-p")) {
			if (++i == argc)
				usage();
			local_port = validate_port(argv[i]);
			log_debug("binding to user-specified port %d",
				  ntohs(local_port));
		} else if (!strcmp(argv[i], "-l4")) {
			if (++i == argc)
				usage();
			if (inet_pton(AF_INET, argv[i], &local_address) != 1)
				log_fatal("%s: bad IPv4 local address",
					  argv[i]);
		} else if (!strcmp(argv[i], "-l6")) {
			if (++i == argc)
				usage();
			if (inet_pton(AF_INET6, argv[i], &local_address6) != 1)
				log_fatal("%s: bad IPv6 local address",
					  argv[i]);
		} else if (!strcmp(argv[i], "-c")) {
			int hcount;
			if (++i == argc)
				usage();
			hcount = atoi(argv[i]);
			if (hcount <= 255)
				max_hop_count= hcount;
			else
				usage();
 		} else if (!strcmp(argv[i], "-i")) {
			if (if4 != NULL) {
				usage();
			}
			status = interface_allocate(&if4, MDL);
			if (status != ISC_R_SUCCESS)
				log_fatal("%s: interface_allocate(v4): %s",
					  argv[i],
					  isc_result_totext(status));
			if (++i == argc) {
				usage();
			}
			strcpy(if4->name, argv[i]);
			interface_snorf(if4, INTERFACE_REQUESTED);
			tmp = if4,
			interface_dereference(&tmp, MDL);
		} else if (!strcmp(argv[i], "-pf")) {
			if (++i == argc)
				usage();
			path_dhcrelay_pid = argv[i];
			no_dhcrelay_pid = ISC_TRUE;
		} else if (!strcmp(argv[i], "--no-pid")) {
			no_pid_file = ISC_TRUE;
		} else if (!strcmp(argv[i], "--version")) {
			log_info("isc-dhccra-%s", PACKAGE_VERSION);
			exit(0);
		} else if (!strcmp(argv[i], "--help") ||
			   !strcmp(argv[i], "-h")) {
			log_info(DHCCRA_USAGE);
			exit(0);
 		} else if (argv[i][0] == '-') {
			usage();
 		} else {
			struct addrinfo hints, *ai = NULL;

			memset(&hints, 0, sizeof(hints));
			hints.ai_flags = AI_CANONNAME;
			hints.ai_family = AF_INET6;
			hints.ai_socktype = SOCK_DGRAM;
			hints.ai_protocol = IPPROTO_UDP;
			if (getaddrinfo(argv[i], NULL, &hints, &ai) != 0)
				log_error("%s: host unknown", argv[i]);

			if (ai) {
				sp = ((struct server_list *)
				      dmalloc(sizeof *sp, MDL));
				if (!sp)
					log_fatal("no memory for server.\n");
				sp->next = servers;
				servers = sp;
				memcpy(&sp->to.sin6_addr,
				       &((struct sockaddr_in6 *)ai->ai_addr)->
				       sin6_addr,
				       sizeof(sp->to.sin6_addr));
				freeaddrinfo(ai);
			}
 		}
	}
	if (colocated_only < 0) {
		log_info("-S {node|link} is mandatory");
		usage();
	}

	/*
	 * If the user didn't specify a pid file directly
	 * find one from environment variables or defaults
	 */
	if (no_dhcrelay_pid == ISC_FALSE) {
		path_dhcrelay_pid = getenv("PATH_DHCCRA_PID");
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

	/* The interface is mandatory */
	if (if4 == NULL) {
		log_fatal("No interface specified.");
	}

	/* We need at least one server */
	if (servers == NULL) {
		log_fatal("No servers specified.");
	}

	/* Set up the server sockaddrs. */
	for (sp = servers; sp; sp = sp->next) {
		sp->to.sin6_port = local_port;
		sp->to.sin6_family = AF_INET6;
#ifdef HAVE_SA_LEN
		sp->to.sin6_len = sizeof sp->to;
#endif
	}

	/* Get the current time... */
	gettimeofday(&cur_tv, NULL);

	inaddr_any.s_addr = INADDR_ANY;

	/* Discover all the network interfaces. */
	local_family = AF_INET;
	discover_interfaces(DISCOVER_RELAY);

	/* Get the IPv6 sockets. */
	local_family = AF_INET6;
	discover_interfaces(DISCOVER_RUNNING);
	status = interface_allocate(&if6, MDL);
	if (status != ISC_R_SUCCESS)
		log_fatal("interface_allocate(v6): %s",
			  isc_result_totext(status));
	strcpy(if6->name, "ipv6");
	interface_snorf(if6, if4->flags);
	tmp = if6;
	interface_dereference(&tmp, MDL);
	if_register6(if6, 0);

	if6->rfdesc = getrecv6();
	status = omapi_register_io_object((omapi_object_t *)if6,
					  if_readsocket,
					  0, got_one_v6, 0, 0);
	if (status != ISC_R_SUCCESS)
		log_fatal("Can't register I/O handle for IPv6-transport: %s",
			  isc_result_totext (status));

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

static int
getrecv6() {
	struct sockaddr_in6 addr;
	int addr_len;
	int sock;
	int flag;

	sock = socket(PF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	if (sock < 0)
		log_fatal("Can't create IPv6-transport receive socket: %m");

	flag = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
		       (char *)&flag, sizeof(flag)) < 0)
		log_fatal("Can't set SO_REUSEADDR option on "
			  "IPv6-transport receive socket: %m");

#ifdef IPV6_V6ONLY
	flag = 1;
	if (setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY,
		       (char *)&flag, sizeof(flag)) < 0)
		log_fatal("Can't set IPV6_V6ONLY option on "
			  "IPv6-transport receive socket: %m");
#endif

	memset(&addr, 0, sizeof(addr));
	addr.sin6_family = AF_INET6;
#ifdef HAVE_SA_LEN
	addr.sin6_len = sizeof(addr);
#endif
	addr.sin6_port = remote_port;
	memcpy(&addr.sin6_addr, &local_address6, sizeof(addr.sin6_addr));
	addr_len = sizeof(addr);
	if (bind(sock, (struct sockaddr *)&addr, addr_len) < 0) {
		log_error("Can't bind to IPv6-transport receive port: %m");
		log_fatal("Please make sure there is"
			  "no other dhcp agent running .");
	}

	flag = 1;
#ifdef IPV6_RECVPKTINFO
	/* RFC3542 */
	if (setsockopt(sock, IPPROTO_IPV6, IPV6_RECVPKTINFO,
		       (char *)&flag, sizeof(flag)) < 0)
		log_fatal("Can't set IPV6_RECVPKTINFO option on "
			  "IPv6-transport receive socket: %m");
#else
	/* RFC2292 */
	if (setsockopt(sock, IPPROTO_IPV6, IPV6_PKTINFO,
		       (char *)&flag, sizeof(flag)) < 0)
		log_fatal("Can't set IPV6_PKTINFO option on "
			  "IPv6-transport receive socket: %m");
#endif

	return sock;
}

/* From IPv4 to IPv6 BOOTREQUEST: forward it to all the servers. */

static void
do_relay4to6(struct interface_info *ip, struct dhcp_packet *packet,
	     unsigned int length, unsigned int from_port, struct iaddr from,
	     struct hardware *hfrom) {
	struct server_list *sp;

	if (packet->hlen > sizeof packet->chaddr) {
		log_info("Discarding packet with invalid hlen, received on "
			 "%s v4 interface.", ip->name);
		return;
	}

	if (packet->op != BOOTREQUEST)
		return;

	/* only from a client */
	if (packet->giaddr.s_addr)
		return;

	/* check the hardware address for colocated constraint. */
	if (colocated_only && ip && hfrom &&
	    ((ip->hw_address.hlen != hfrom->hlen) ||
	     memcmp(ip->hw_address.hbuf, hfrom->hbuf, hfrom->hlen)))
		return;

	if (packet->hops < max_hop_count)
		packet->hops = packet->hops + 1;
	else
		return;

	for (sp = servers; sp; sp = sp->next) {
		if (sendto(if6->wfdesc,
			   (unsigned char *)packet,
			   length, 0,
			   (struct sockaddr *)&sp->to,
			   sizeof(sp->to)) < 0) {
			++client_packet_errors;
		} else {
			char addrbuf[MAX_ADDRESS_STRING_LEN];

			inet_ntop(AF_INET6, &sp->to.sin6_addr, addrbuf,
				  MAX_ADDRESS_STRING_LEN);
			log_debug("Forwarded BOOTREQUEST for %s to %s",
				  print_hw_addr(packet->htype, packet->hlen,
						packet->chaddr),
				  addrbuf);
			++client_packets_relayed;
		}
	}
}

/* From IPv6 to IPv4 BOOTREPLY: forward it to the client. */

static void
do_relay6to4(struct interface_info *ip, const char *msg,
	     int len, int from_port, const struct iaddr *from,
	     isc_boolean_t was_unicast) {
	struct dhcp_packet *packet;
	struct sockaddr_in to;
	struct hardware hto, *htop;
	struct in_addr local;
	unsigned int length;

	packet = (struct dhcp_packet *)msg;
	length = (unsigned int)len;

	if (packet->hlen > sizeof packet->chaddr) {
		log_info("Discarding packet with invalid hlen, received on "
			 "%s v6 interface.", ip->name);
		return;
	}

	if (packet->op != BOOTREPLY)
		return;

	memset(&to, 0, sizeof(to));
	to.sin_family = AF_INET;
#ifdef HAVE_SA_LEN
	to.sin_len = sizeof(to);
#endif
	if (!(packet->flags & htons(BOOTP_BROADCAST)) &&
		can_unicast_without_arp(if4)) {
		to.sin_addr = packet->yiaddr;
		to.sin_port = remote_port;

		/* and hardware address is not broadcast */
		htop = &hto;
	} else {
		to.sin_addr.s_addr = htonl(INADDR_BROADCAST);
		to.sin_port = remote_port;

		/* hardware address is broadcast */
		htop = NULL;
	}

	memcpy(&hto.hbuf[1], packet->chaddr, packet->hlen);
	hto.hbuf[0] = packet->htype;
	hto.hlen = packet->hlen + 1;

	/* relay agent options are illegal */
	if (find_relay_agent_options(packet, length))
		return;

	if (if4->address_count > 0)
		local = if4->addresses[0];
	else
		local = inaddr_any;
	if (send_packet(if4, NULL, packet, length, local, &to, htop) < 0) {
		++server_packet_errors;
	} else {
		log_debug("Forwarded BOOTREPLY for %s to %s",
		       print_hw_addr(packet->htype, packet->hlen,
				     packet->chaddr),
			  inet_ntoa(to.sin_addr));
		++server_packets_relayed;
	}
}

/* Find relay agent options */

static int
find_relay_agent_options(struct dhcp_packet *packet, unsigned length) {
	int is_dhcp = 0;
	u_int8_t *op, *nextop, *sp, *max;

	/* If there's no cookie, it's a bootp packet, so we should just
	   forward it unchanged. */
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
			return (0);

		      case DHO_DHCP_AGENT_OPTIONS:
			/* We shouldn't see a relay agent option in a
			   packet before we've seen the DHCP packet type,
			   but if we do, we have to leave it alone. */
			if (!is_dhcp)
				goto skip;

			return (1);

		      skip:
			/* Skip over other options. */
		      default:
			/* Fail if processing this option will exceed the
			 * buffer(op[1] is malformed).
			 */
			nextop = op + op[1] + 2;
			if (nextop > max)
				return (-1);

			if (sp != op) {
				memmove(sp, op, op[1] + 2);
				sp += op[1] + 2;
				op = nextop;
			} else
				op = sp = nextop;

			break;
		}
	}
	return (0);
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
