/* dhcp4o6.c

   DHCPv4 over DHCPv6 shared code... */

/*
 * Copyright (c) 2016 by Internet Systems Consortium, Inc. ("ISC")
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
 */

#include "dhcpd.h"

#ifdef DHCP4o6

int dhcp4o6_fd = -1;
omapi_object_t *dhcp4o6_object = NULL;
omapi_object_type_t *dhcp4o6_type = NULL;

static int dhcp4o6_readsocket(omapi_object_t *);

extern struct universe isc6_universe;

/*
 * DHCPv4 over DHCPv6 Inter Process Communication setup
 *
 * A UDP socket is created between ::1 port and ::1 port + 1
 * (port is given in network order, the DHCPv6 side is bound to port,
 *  the DHCPv4 side to port + 1. The socket descriptor is stored into
 *  dhcp4o6_fd and an OMAPI handler is registered. Any failure is fatal.)
 */
void dhcp4o6_setup(u_int16_t port) {
	struct sockaddr_in6 local6, remote6;
	int flag;
	isc_result_t status;

	/* Register DHCPv4 over DHCPv6 forwarding. */
	memset(&local6, 0, sizeof(local6));
	local6.sin6_family = AF_INET6;
	if (local_family == AF_INET6)
		local6.sin6_port = port;
	else
		local6.sin6_port = htons(ntohs(port) + 1);
	local6.sin6_addr.s6_addr[15] = 1;
#ifdef HAVE_SA_LEN
	local6.sin6_len = sizeof(local6);
#endif
	memset(&remote6, 0, sizeof(remote6));
	remote6.sin6_family = AF_INET6;
	if (local_family == AF_INET6)
		remote6.sin6_port = htons(ntohs(port) + 1);
	else
		remote6.sin6_port = port;
	remote6.sin6_addr.s6_addr[15] = 1;
#ifdef HAVE_SA_LEN
	remote6.sin6_len = sizeof(remote6);
#endif

	dhcp4o6_fd = socket(PF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	if (dhcp4o6_fd < 0)
		log_fatal("Can't create dhcp4o6 socket: %m");
	flag = 1;
	if (setsockopt(dhcp4o6_fd, SOL_SOCKET, SO_REUSEADDR,
		       (char *)&flag, sizeof(flag)) < 0)
		log_fatal("Can't set SO_REUSEADDR option "
			  "on dhcp4o6 socket: %m");
	if (bind(dhcp4o6_fd,
		 (struct sockaddr *)&local6,
		 sizeof(local6)) < 0)
		log_fatal("Can't bind dhcp4o6 socket: %m");
	if (connect(dhcp4o6_fd,
		    (struct sockaddr *)&remote6,
		    sizeof(remote6)) < 0)
		log_fatal("Can't connect dhcp4o6 socket: %m");

	/* Omapi stuff. */
	/* TODO: add tracing support. */
	status = omapi_object_type_register(&dhcp4o6_type,
					    "dhcp4o6",
					    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
					    sizeof(*dhcp4o6_object),
					    0, RC_MISC);
	if (status != ISC_R_SUCCESS)
		log_fatal("Can't register dhcp4o6 type: %s",
			  isc_result_totext(status));
	status = omapi_object_allocate(&dhcp4o6_object, dhcp4o6_type, 0, MDL);
	if (status != ISC_R_SUCCESS)
		log_fatal("Can't allocate dhcp4o6 object: %s",
			  isc_result_totext(status));
	status = omapi_register_io_object(dhcp4o6_object,
					  dhcp4o6_readsocket, 0,
					  dhcpv4o6_handler, 0, 0);
	if (status != ISC_R_SUCCESS)
		log_fatal("Can't register dhcp4o6 handle: %s",
			  isc_result_totext(status));
}

static int dhcp4o6_readsocket(omapi_object_t *h) {
	IGNORE_UNUSED(h);
	return dhcp4o6_fd;
}

/*
 * \brief Get parameters from the ISC vendor option
 *
 * DHCPv4-over-DHCPv6 Inter-Process Communication tool.
 *
 * Get the interface name and the source address from the ISC vendor option.
 * Note as a side effect the sub-options are removed on success.
 *
 * \param options the option_state
 * \param ifname the data_string which will receive the interface name
 * \param srcaddr the data_string which will receive the source address
 * \return the number of found sub-options
 */
int ipc4o6_get_params(struct option_state *options,
		      struct data_string *ifname,
		      struct data_string *srcaddr)
{
	struct option_cache *oc;

	oc = lookup_option(&isc6_universe, options, D4O6_INTERFACE);
	if (oc == NULL) {
		return (0);
	}
	memset(ifname, 0, sizeof(*ifname));
	if (!evaluate_option_cache(ifname, NULL, NULL, NULL,
				   options, NULL, &global_scope, oc, MDL)) {
		return (0);
	}

	oc = lookup_option(&isc6_universe, options, D4O6_SRC_ADDRESS);
	if (oc == NULL) {
		data_string_forget(ifname, MDL);
		return (1);
	}
	memset(srcaddr, 0, sizeof(*srcaddr));
	if (!evaluate_option_cache(srcaddr, NULL, NULL, NULL,
				   options, NULL, &global_scope, oc, MDL)) {
		data_string_forget(ifname, MDL);
		return (1);
	}
	if (srcaddr->len != 16) {
		data_string_forget(ifname, MDL);
		data_string_forget(srcaddr, MDL);
		return (1);
	}

	delete_option(&isc6_universe, options, D4O6_INTERFACE);
	delete_option(&isc6_universe, options, D4O6_SRC_ADDRESS);

	return (2);
}

/*
 * \brief Add the ISC vendor option with parameters
 *
 * DHCPv4-over-DHCPv6 Inter-Process Communication tool.
 *
 * Add the parameters to the ISC vendor option and store it.
 *
 * \param buf the (message) buffer
 * \param buflen the buffer length
 * \param ifname the interface name
 * \param srcaddr the source address
 * \return the amount of added data
 */
int ipc4o6_add_params(char *buf, int buflen,
		      struct data_string *ifname,
		      struct data_string *srcaddr)
{
	unsigned len = ifname->len + srcaddr->len;
	unsigned char *p = (unsigned char*)buf;

	/* Check buffer length */
	len = ifname->len + srcaddr->len;
	if (4 * 4 + len > buflen) {
		log_error("ipc4o6_add_params: underflow.");
		return (0);
	}

	/* Put header */
	putUShort(p, D6O_VENDOR_OPTS);
	p += 2;
	putUShort(p, 3 * 4 + len);
	p += 2;
	putULong(p, VENDOR_ISC_SUBOPTIONS);
	p += 4;

	/* Put interface name */
	putUShort(p, D4O6_INTERFACE);
	p += 2;
	putUShort(p, ifname->len);
	p += 2;
	memcpy(p, ifname->data, ifname->len);
	p += ifname->len;

	/* Put source address */
	putUShort(p, D4O6_SRC_ADDRESS);
	p += 2;
	putUShort(p, srcaddr->len);
	p += 2;
	memcpy(p, srcaddr->data, srcaddr->len);
	p += srcaddr->len;

	return ((int)((char *)p - buf));
}

/*
 * \brief Zap the ISC vendor option
 *
 * DHCPv4-over-DHCPv6 Inter-Process Communication tool.
 *
 * Zap the ISC vendor option from the message buffer
 *
 * \param raw the raw message
 */
void ipc4o6_zap_params(struct data_string *raw) {
	unsigned int offset;
	unsigned len;
	unsigned code;

	offset = (unsigned)(offsetof(struct dhcpv6_packet, options));
	if ((raw->data[0] == DHCPV6_RELAY_FORW) ||
	    (raw->data[0] == DHCPV6_RELAY_REPL)) {
		offset =
		    (unsigned)(offsetof(struct dhcpv6_relay_packet, options));
	}

	for (;;) {
		if (offset > raw->len) {
			log_error("ipc4o6_zap_params: overflow.");
			return;
		}
		if (offset == raw->len) {
			log_error("ipc4o6_zap_params: not found.");
			return;
		}
		if (offset + 4 > raw->len) {
			log_error("ipc4o6_zap_params: no header.");
			return;
		}
		code = getUShort(raw->data + offset);
		offset += 2;
		len = getUShort(raw->data + offset);
		offset += 2;
		if (code != D6O_VENDOR_OPTS) {
			offset += len;
			continue;
		}
		if (len < 4) {
			log_error("ipc4o6_zap_params: no enterprise code.");
			offset += len;
			continue;
		}
		code = getULong(raw->data + offset);
		if (code != VENDOR_ISC_SUBOPTIONS) {
			offset += len;
			continue;
		}

		/* Got it! */
		break;
	}

	/* If we are here we have the ISC vendor option
	   from offset - 4 to offset + len */
	if (offset + len > raw->len) {
		log_error("ipc4o6_zap_params: vsio overflow.");
	}
	if (offset + len >= raw->len) {
		/* Easy case: the option is the last one. */
		raw->len = offset - 4;
		return;
	}
	/* Hard case: zap it */
	memmove((unsigned char *)raw->data + offset - 4,
		raw->data + offset + len,
		raw->len - (offset + len));
	raw->len -= len + 4;

	return;
}
#endif /* DHCP4o6 */
