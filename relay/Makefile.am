AM_CPPFLAGS = -DLOCALSTATEDIR='"@localstatedir@"'

sbin_PROGRAMS = dhcrelay dhccra dhctra
dhcrelay_SOURCES = dhcrelay.c
dhcrelay_LDADD = ../common/libdhcp.a ../omapip/libomapi.a \
		 ../bind/lib/libdns.a ../bind/lib/libisc.a
dhccra_SOURCES = dhccra.c
dhccra_LDADD = ../common/libdhcp.a ../omapip/libomapi.a \
		 ../bind/lib/libdns.a ../bind/lib/libisc.a
dhctra_SOURCES = dhctra.c
dhctra_LDADD = ../common/libdhcp.a ../omapip/libomapi.a \
		 ../bind/lib/libdns.a ../bind/lib/libisc.a
man_MANS = dhcrelay.8 dhccra.8 dhctra.8
EXTRA_DIST = $(man_MANS)

