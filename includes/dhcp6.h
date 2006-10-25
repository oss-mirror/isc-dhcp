/* dhcp6.h

   DHCPv6 Protocol structures... */

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


/* DHCPv6 Option codes: */

#define D6O_CLIENTID				1 /* RFC3315 */
#define D6O_SERVERID				2
#define D6O_IA_NA				3
#define D6O_IA_TA				4
#define D6O_IAADDR				5
#define D6O_ORO					6
#define D6O_PREFERENCE				7
#define D6O_ELAPSED_TIME			8
#define D6O_RELAY_MSG				9
/* Option code 10 unassigned. */
#define D6O_AUTH				11
#define D6O_UNICAST				12
#define D6O_STATUS_CODE				13
#define D6O_RAPID_COMMIT			14
#define D6O_USER_CLASS				15
#define D6O_VENDOR_CLASS			16
#define D6O_VENDOR_OPTS				17
#define D6O_INTERFACE_ID			18
#define D6O_RECONF_MSG				19
#define D6O_RECONF_ACCEPT			20
#define D6O_SIP_SERVERS_DNS			21 /* RFC3319 */
#define D6O_SIP_SERVERS_ADDR			22 /* RFC3319 */
#define D6O_NAME_SERVERS			23 /* RFC3646 */
#define D6O_DOMAIN_SEARCH			24 /* RFC3646 */
#define D6O_IA_PD				25 /* RFC3633 */
#define D6O_IAPREFIX				26 /* RFC3633 */
#define D6O_NIS_SERVERS				27 /* RFC3898 */
#define D6O_NISP_SERVERS			28 /* RFC3898 */
#define D6O_NIS_DOMAIN_NAME			29 /* RFC3898 */
#define D6O_NISP_DOMAIN_NAME			30 /* RFC3898 */
#define D6O_SNTP_SERVERS			31 /* RFC4075 */
#define D6O_INFORMATION_REFRESH_TIME		32 /* lifetime */
#define D6O_BCMCS_SERVER_D			33 /* RFC4280 */
#define D6O_BCMCS_SERVER_A			34 /* RFC4280 */
/* 35 is unassigned */
#define D6O_GEOCONF_CIVIC			36 /* geopriv-dhcp-civil */
#define D6O_REMOTE_ID				37 /* dhcpv6-remoteid */
#define D6O_SUBSCRIBER_ID			38 /* RFC4580 */
#define D6O_CLIENT_FQDN				39 /* dhcpv6-fqdn */

/* 
 * Status Codes, from RFC 3315 section 24.4. 
 */
#define STATUS_Success		0
#define STATUS_UnspecFail	1
#define STATUS_NoAddrsAvail	2
#define STATUS_NoBinding	3
#define STATUS_NotOnLink	4 
#define STATUS_UseMulticast	5 

/* 
 * DHCPv6 message types, defined in section 5.3 of RFC 3315 
 */
#define DHCPV6_SOLICT 1
#define DHCPV6_ADVERTISE 2
#define DHCPV6_REQUEST 3
#define DHCPV6_CONFIRM 4
#define DHCPV6_RENEW 5
#define DHCPV6_REBIND 6
#define DHCPV6_REPLY 7
#define DHCPV6_RELEASE 8
#define DHCPV6_DECLINE 9
#define DHCPV6_RECONFIGURE 10
#define DHCPV6_INFORMATION_REQUEST 11
#define DHCPV6_RELAY_FORW 12
#define DHCPV6_RELAY_REPL 13

/* 
 * DHCPv6 well-known multicast addressess, from section 5.1 of RFC 3315 
 */
#define All_DHCP_Relay_Agents_and_Servers "FF02::1:2"
#define All_DHCP_Servers "FF05::1:3"

/* 
 * Normal packet format, defined in section 6 of RFC 3315 
 */
struct dhcpv6_packet {
	unsigned char msg_type;
	unsigned char transaction_id[3];
	unsigned char options[0];
};

/* 
 * Relay packet format, defined in section 7 of RFC 3315 
 */
struct dhcpv6_relay_packet {
	unsigned char msg_type;
	unsigned char hop_count;
	struct sockaddr_in6 link_address;
	struct sockaddr_in6 peer_address;
	unsigned char options[0];
};

