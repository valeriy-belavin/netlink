from ctypes import *


class Base(object):
	_fields_ = []

	def __repr__(self):
		data = []
		for name, _ in self._fields_:
			data.append("{}={}".format(name, getattr(self, name)))
		return ", ".join(data)


class nlmsghdr(Structure, Base):
	_fields_ = [
		('nlmsg_len', c_uint32),
		('nlmsg_type', c_uint16),
		('nlmsg_flags', c_uint16),
		('nlmsg_seq', c_uint32),
		('nlmsg_pid', c_uint32),
	]


class rtmsg(Structure, Base):
	_fields_ = [
		('rtm_family', c_ubyte),
		('rtm_dst_len', c_ubyte),
		('rtm_src_len', c_ubyte),
		('rtm_tos', c_ubyte),
		('rtm_table', c_ubyte),
		('rtm_protocol', c_ubyte),
		('rtm_scope', c_ubyte),
		('rtm_type', c_ubyte),
		('rtm_flags', c_uint),
	]


class rtattr(Structure, Base):
	_fields_ = [
		('rta_len', c_ushort),
		('rta_type', c_ushort),
	]


class ifaddrmsg(Structure, Base):
	_fields_ = [
		('ifa_family', c_ubyte),
		('ifa_prefixlen', c_ubyte),
		('ifa_flags', c_ubyte),
		('ifa_scope', c_ubyte),
		('ifa_index', c_int),
	]


class ifinfomsg(Structure, Base):
	_fields_ = [
		('ifi_family', c_ubyte),
		('ifi_type', c_ushort),
		('ifi_index', c_int),
		('ifi_flags', c_uint),
		('ifi_change', c_uint),
	]


class rtnexthop(Structure, Base):
	_fields_ = [
		('rtnh_len', c_uint16),
		('rtnh_flags', c_ubyte),
		('rtnh_hops', c_ubyte),
		('rtnh_ifindex', c_int),
	]


def Pack(ctype_instance):
	buf = string_at(byref(ctype_instance), sizeof(ctype_instance))
	return buf


def Unpack(ctype, buf):
	cstring = create_string_buffer(buf)
	ctype_instance = cast(pointer(cstring), POINTER(ctype)).contents
	return ctype_instance

