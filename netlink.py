import sys
import struct
import socket

#
# Base netlink constants (include/uapi/linux/netlink.h)
#
NETLINK_ROUTE = 0

#
# Request constants (include/uapi/linux/netlink.h)
#
NLM_F_REQUEST = 1
NLM_F_ACK = 4
NLM_F_EXCL = 0x200
NLM_F_CREATE = 0x400
NLM_F_DUMP = 0x300

#
# Message types (include/uapi/linux/netlink.h)
#
NLMSG_NOOP = 1
NLMSG_ERROR = 2
NLMSG_DONE = 3

#
# rtnetlink constants (include/uapi/linux/rtnetlink.h)
#
RTMGRP_LINK = 0x1
RTMGRP_IPV4_IFADDR = 0x10
RTMGRP_IPV4_ROUTE = 0x40

#
# Message types (include/uapi/linux/rtnetlink.h)
#
RTM_NEWLINK = 16
RTM_DELLINK = 17
RTM_NEWADDR = 20
RTM_DELADDR = 21
RTM_GETADDR = 22
RTM_NEWROUTE = 24
RTM_DELROUTE = 25
RTM_GETROUTE = 26
RTM_NEWNEIGH = 28
RTM_DELNEIGH = 29
RTM_NEWRULE = 32
RTM_DELRULE = 33
RTM_GETRULE = 34

#
# Routing message attributes (include/uapi/linux/rtnetlink.h)
#
RTA_UNSPEC = 0
RTA_DST = 1
RTA_SRC	= 2
RTA_IIF	= 3
RTA_OIF	= 4
RTA_GATEWAY = 5
RTA_PRIORITY= 6
RTA_PREFSRC = 7
RTA_METRICS	= 8
RTA_MULTIPATH = 9
RTA_PROTOINFO = 10
RTA_FLOW = 11
RTA_CACHEINFO = 12
RTA_SESSION = 13
RTA_MP_ALGO = 14
RTA_TABLE = 15
RTA_MARK = 16
RTA_MFC_STATS = 17
RTA_VIA = 18
RTA_NEWDST = 19
RTA_PREF = 20
RTA_ENCAP_TYPE = 21
RTA_ENCAP = 22
RTA_EXPIRES = 23
RTA_PAD = 24

#
# Link flags (include/uapi/linux/if_link.h)
#
IFLA_UNSPEC = 0
IFLA_ADDRESS = 1
IFLA_BROADCAST = 2
IFLA_IFNAME = 3
IFLA_MTU = 4
IFLA_LINK = 5
IFLA_QDISC = 6
IFLA_STATS = 7
IFLA_COST = 8
IFLA_PRIORITY = 9
IFLA_MASTER = 10
IFLA_WIRELESS = 11
IFLA_PROTINFO = 12
IFLA_TXQLEN = 13
IFLA_MAP = 14
IFLA_WEIGHT = 15
IFLA_OPERSTATE = 16
IFLA_LINKMODE = 17
IFLA_LINKINFO = 18
IFLA_NET_NS_PID = 19
IFLA_IFALIAS = 20
IFLA_NUM_VF = 21
IFLA_VFINFO_LIST = 22
IFLA_STATS64 = 23
IFLA_VF_PORTS = 24
IFLA_PORT_SELF = 25
IFLA_AF_SPEC = 26
IFLA_GROUP = 27
IFLA_NET_NS_FD = 28
IFLA_EXT_MASK = 29
IFLA_PROMISCUITY = 30
IFLA_NUM_TX_QUEUES = 31
IFLA_NUM_RX_QUEUES = 32
IFLA_CARRIER = 33
IFLA_PHYS_PORT_ID = 34
IFLA_CARRIER_CHANGES = 35
IFLA_PHYS_SWITCH_ID = 36
IFLA_LINK_NETNSID = 37
IFLA_PHYS_PORT_NAME = 38
IFLA_PROTO_DOWN = 39
IFLA_GSO_MAX_SEGS = 40
IFLA_GSO_MAX_SIZE = 41

#
# Address flags (include/uapi/linux/if_addr.h)
#
IFA_UNSPEC = 0
IFA_ADDRESS = 1
IFA_LOCAL = 2
IFA_LABEL = 3
IFA_BROADCAST = 4
IFA_ANYCAST = 5
IFA_CACHEINFO = 6
IFA_MULTICAST = 7
IFA_FLAGS = 8

#
# IFA_FLAGS values
#
IFA_F_SECONDARY	= 0x01
IFA_F_TEMPORARY	= IFA_F_SECONDARY
IFA_F_NODAD	= 0x02
IFA_F_OPTIMISTIC = 0x04
IFA_F_DADFAILED = 0x08
IFA_F_HOMEADDRESS =	0x10
IFA_F_DEPRECATED = 0x20
IFA_F_TENTATIVE	= 0x40
IFA_F_PERMANENT	= 0x80
IFA_F_MANAGETEMPADDR = 0x100
IFA_F_NOPREFIXROUTE	= 0x200
IFA_F_MCAUTOJOIN = 0x400
IFA_F_STABLE_PRIVACY = 0x800


def get_netlink_constant(value, prefix):
	""" Returns netlink constant name by value and prefix """
	thismodule = sys.modules[__name__]
	for name in dir(thismodule):
		if (name.startswith(prefix) and
				not name.startswith(prefix + "F_") and 	# skip IFA_F_* values
				name.isupper() and
				getattr(thismodule, name) == value):
			return name
	return value


def get_netlink_command(nlmsg):
	""" Return netlink event name by nlmsg_type """
	return get_netlink_constant(nlmsg.nlmsg_type, 'RTM_')


def netlink_decode(command, family, nla_type, nla_data):
	"""Decodes netlink attributes to Python types.

	Values for which the code knows the type (e.g., the fwmark ID in a
	RTM_NEWRULE command) are decoded to Python integers, strings, etc. Values
	of unknown type are returned as raw byte strings.

	Args:
		command: An integer.
			- If positive, the number of the rtnetlink command being carried out.
				This is used to interpret the attributes. For example, for an
				RTM_NEWROUTE command, attribute type 3 is the incoming interface and
				is an integer, but for a RTM_NEWRULE command, attribute type 3 is the
				incoming interface name and is a string.
			- If negative, one of the following (negative) values:
				- RTA_METRICS: Interpret as nested route metrics.
		family: The address family. Used to convert IP addresses into strings.
		nla_type: An integer, then netlink attribute type.
		nla_data: A byte string, the netlink attribute data.

	Returns:
		A tuple (name, data):
		 - name is a string (e.g., "FRA_PRIORITY") if we understood the attribute,
			 or an integer if we didn't.
		 - data can be an integer, a string, a nested dict of attributes as
			 returned by _ParseAttributes (e.g., for RTA_METRICS), a cstruct.Struct
			 (e.g., RTACacheinfo), etc. If we didn't understand the attribute, it
			 will be the raw byte string.
	"""
	if command.endswith("ADDR"):
		name = get_netlink_constant(nla_type, "IFA_")

	elif command.endswith("LINK"):
		name = get_netlink_constant(nla_type, "IFLA_")

	elif command.endswith("ROUTE"):
		name = get_netlink_constant(nla_type, "RTA_")

	else:
		# Don't know what this is. Leave it as an integer.
		name = nla_type

	if name in ["IFA_ADDRESS", "IFA_LOCAL",  "RTA_SRC", "RTA_DST", "RTA_GATEWAY", "RTA_PREFSRC", "RTA_UID"]:
		data = socket.inet_ntop(family, nla_data)

	elif name in ["RTA_IIF", "RTA_OIF", "RTA_TABLE", "IFLA_MTU", "IFLA_TXQLEN", "IFLA_GROUP",
		"IFLA_PROMISCUITY", "IFLA_NUM_TX_QUEUES", "IFLA_GSO_MAX_SEGS", "IFLA_GSO_MAX_SIZE",
		"IFLA_NUM_RX_QUEUES", "IFLA_LINK", "IFLA_CARRIER_CHANGES", "IFA_FLAGS"]:
		data = struct.unpack("=I", nla_data)[0]

	elif name in ["IFLA_OPERSTATE", "IFLA_LINKMODE", "IFLA_CARRIER", "IFLA_PROTO_DOWN"]:
		data = struct.unpack("=B", nla_data)[0]

	elif name in ["IFLA_IFNAME", "IFA_LABEL", "IFLA_QDISC"]:
		data = nla_data.strip('\x00')

	elif name in ["IFLA_ADDRESS", "IFLA_BROADCAST"]:
		data = ":".join(["{:02x}".format(x) for x in struct.unpack('=6B', nla_data)])

	else:
		data = nla_data

	return name, data


