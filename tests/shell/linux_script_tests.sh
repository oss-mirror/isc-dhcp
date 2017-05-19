# Copyright (C) 2016-2017 Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.


# This is fake ip tool. The original ip tool in Linux comes from
# ip-route2 suite. This one is a fake one. It simply echoes all
# its parameters to a log file.
IP=/home/thomson/devel/dhcp-git/tests/shell/ip-echo

IP_LOG_FILE=/home/thomson/devel/dhcp-git/tests/ip-echo.log

SCRIPT_FILE=/home/thomson/devel/dhcp-git/client/scripts/linux

TMP_SCRIPT=/home/thomson/devel/dhcp-git/tests/linux

PROCS=""

# Import common test library.
. /home/thomson/devel/dhcp-git/tests/shell/dhcp_test_lib.sh

# Ok, before we start we need to update the script to use our ip tool, not
# the one in /sbin/ip.


cp -f ${SCRIPT_FILE} ${TMP_SCRIPT}
sed -ri -e "s,/sbin/ip,${IP},g" ${TMP_SCRIPT}

echo "Using script ${TMP_SCRIPT}"

script_preinit_test() {
    test_start "script.linux.preinit"

    rm -f ${IP_LOG_FILE}
    reason=PREINIT interface=iface0 ${TMP_SCRIPT}
    grep_file ${IP_LOG_FILE} "ip link set dev iface0 up" 1

    rm -f ${IP_LOG_FILE}
    reason=PREINIT interface=iface0 alias_ip_address=192.0.2.1 ${TMP_SCRIPT}
    grep_file ${IP_LOG_FILE} "ip link set dev iface0 up" 1
    grep_file ${IP_LOG_FILE} "ip -4 addr flush dev iface0 label iface0:0" 1

    test_finish 0
}

script_bound_test() {
    test_name=${1}
    reason=${2}
    test_start ${test_name}

    rm -f ${IP_LOG_FILE}
    
    reason=${reason} old_ip_address=192.0.2.2 \
          new_ip_address=192.0.2.3 new_routers=192.0.2.4 new_subnet_mask=255.255.255.0 \
          new_broadcast_address=192.0.2.255 interface=iface0 new_interface_mtu=1500 ${TMP_SCRIPT}

    grep_file ${IP_LOG_FILE} "ip -4 addr flush dev iface0 label iface0:0" 0
    grep_file ${IP_LOG_FILE} "ip -4 addr flush dev iface0 label iface0" 1
    grep_file ${IP_LOG_FILE} "ip -4 addr add 192.0.2.3/255.255.255.0 broadcast 192.0.2.255 dev iface0 label iface0" 1
    grep_file ${IP_LOG_FILE} "ip link set dev iface0 mtu 1500" 1
    grep_file ${IP_LOG_FILE} "ip -4 route add default via 192.0.2.4 dev iface0" 1

    test_finish 0
}

script_preinit_test
script_bound_test "script.linux.bound" BOUND
script_bound_test "script.linux.renew" RENEW
script_bound_test "script.linux.rebind" REBIND
script_bound_test "script.linux.reboot" REBOOT

rm -f ${TMP_SCRIPT}
