from ctypes import *


class Base(object):
	_fields_ = []

	def __repr__(self):
		data = []
		for name, _ in self._fields_:
			data.append("{}={} ".format(name, getattr(self, name)))
		return "".join(data)


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


NLMSG_ALIGNTO = 4

'''
#define NLMSG_ALIGN(len) ( ((len)+NLMSG_ALIGNTO-1) & ~(NLMSG_ALIGNTO-1) )
'''
NLMSG_ALIGN = lambda length: (length + NLMSG_ALIGNTO - 1) & ~(NLMSG_ALIGNTO - 1)

'''
#define NLMSG_HDRLEN	 ((int) NLMSG_ALIGN(sizeof(struct nlmsghdr)))
'''
NLMSG_HDRLEN = NLMSG_ALIGN(sizeof(nlmsghdr))

'''
#define NLMSG_LENGTH(len) ((len) + NLMSG_HDRLEN)
'''
NLMSG_LENGTH = lambda length: length + NLMSG_HDRLEN

'''
#define NLMSG_SPACE(len) NLMSG_ALIGN(NLMSG_LENGTH(len))
'''
NLMSG_SPACE = lambda length: NLMSG_ALIGN(NLMSG_LENGTH(length))

'''
#define NLMSG_DATA(nlh)  ((void*)(((char*)nlh) + NLMSG_LENGTH(0)))
'''
NLMSG_DATA = lambda nlh: string_at(addressof(nlh) + NLMSG_LENGTH(0), size=nlh.nlmsg_len)

'''
#define NLMSG_NEXT(nlh,len)	 ((len) -= NLMSG_ALIGN((nlh)->nlmsg_len), \
				  (struct nlmsghdr*)(((char*)(nlh)) + NLMSG_ALIGN((nlh)->nlmsg_len)))
'''
def NLMSG_NEXT(nlh, length):
	length -= NLMSG_ALIGN(nlh.nlmsg_len)
	return cast(addressof(nlh) + NLMSG_ALIGN(nlh.nlmsg_len), POINTER(nlmsghdr)).contents, length

'''
#define NLMSG_OK(nlh,len) ((len) >= (int)sizeof(struct nlmsghdr) && \
			   (nlh)->nlmsg_len >= sizeof(struct nlmsghdr) && \
			   (nlh)->nlmsg_len <= (len))
'''
def NLMSG_OK(nlh, length):
	return (length >= sizeof(nlh) and
			nlh.nlmsg_len >= sizeof(nlh) and
			nlh.nlmsg_len <= length)

'''
#define NLMSG_PAYLOAD(nlh,len) ((nlh)->nlmsg_len - NLMSG_SPACE((len)))
'''
def NLMSG_PAYLOAD(nlh, length):
	return nlh.nlmsg_len - NLMSG_SPACE(length)


RTA_ALIGNTO	= 4

RTA_ALIGN = lambda length: (length + RTA_ALIGNTO - 1) & ~(RTA_ALIGNTO - 1)

'''
#define RTA_OK(rta,len) ((len) >= (int)sizeof(struct rtattr) && \
			 (rta)->rta_len >= sizeof(struct rtattr) && \
			 (rta)->rta_len <= (len))
'''
def RTA_OK(rta, length):
	return (length >= sizeof(rtattr) and
			rta.rta_len >= sizeof(rtattr) and
			rta.rta_len <= length)

'''
#define RTA_NEXT(rta,attrlen)	((attrlen) -= RTA_ALIGN((rta)->rta_len), \
				 (struct rtattr*)(((char*)(rta)) + RTA_ALIGN((rta)->rta_len)))
'''
def RTA_NEXT(rta, attrlen):
	attrlen -= RTA_ALIGN(rta.rta_len)
	rta = cast(addressof(rta) + RTA_ALIGN(rta.rta_len), POINTER(rtattr)).contents
	return rta, attrlen

'''
#define RTA_LENGTH(len)	(RTA_ALIGN(sizeof(struct rtattr)) + (len))
'''
RTA_LENGTH = lambda length: RTA_ALIGN(sizeof(rtattr) + length)

'''
#define RTA_DATA(rta)   ((void*)(((char*)(rta)) + RTA_LENGTH(0)))
'''
RTA_DATA = lambda rta, attrlen: string_at(addressof(rta) + RTA_LENGTH(0), size=attrlen)
#RTA_DATA = lambda rta, attrlen: cast(addressof(rta) + RTA_LENGTH(0), POINTER(c_char_p)).contents

'''
#define RTA_PAYLOAD(rta) ((int)((rta)->rta_len) - RTA_LENGTH(0))
'''
RTA_PAYLOAD = lambda rta: rta.rta_len - RTA_LENGTH(0)

'''
#define RTM_RTA(r)  ((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct rtmsg))))
'''
RTM_RTA = lambda r: cast(addressof(r) + NLMSG_ALIGN(sizeof(rtmsg)), POINTER(rtattr)).contents

'''
#define RTM_PAYLOAD(n) NLMSG_PAYLOAD(n,sizeof(struct rtmsg))
'''
RTM_PAYLOAD = lambda nlh: NLMSG_PAYLOAD(nlh, sizeof(rtmsg))

'''
#define IFA_RTA(r)  ((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct ifaddrmsg))))
'''
IFA_RTA = lambda r: cast(addressof(r) + NLMSG_ALIGN(sizeof(ifaddrmsg)), POINTER(rtattr)).contents

'''
#define IFA_PAYLOAD(n) NLMSG_PAYLOAD(n,sizeof(struct ifaddrmsg))
'''
IFA_PAYLOAD = lambda n: NLMSG_PAYLOAD(n, sizeof(ifaddrmsg))

'''
#define IFLA_RTA(r)  ((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct ifinfomsg))))
'''
IFLA_RTA = lambda r: cast(addressof(r) + NLMSG_ALIGN(sizeof(ifinfomsg)), POINTER(rtattr)).contents

'''
#define IFLA_PAYLOAD(n) NLMSG_PAYLOAD(n,sizeof(struct ifinfomsg))
'''
IFLA_PAYLOAD = lambda n: NLMSG_PAYLOAD(n, sizeof(ifinfomsg))

#
# Macros to handle hexthops
#

RTNH_ALIGNTO = 4

'''
#define RTNH_ALIGN(len) ( ((len)+RTNH_ALIGNTO-1) & ~(RTNH_ALIGNTO-1) )
'''
RTNH_ALIGN = lambda len: (len + RTNH_ALIGNTO - 1) & ~(RTNH_ALIGNTO - 1)

'''
#define RTNH_OK(rtnh,len) ((rtnh)->rtnh_len >= sizeof(struct rtnexthop) && \
			   ((int)(rtnh)->rtnh_len) <= (len))
'''
RTNH_OK = lambda rtnh, length: ((rtnh.rtnh_len >= sizeof(rtnexthop)) and
			   (rtnh.rtnh_len <= length))

'''
#define RTNH_NEXT(rtnh)	((struct rtnexthop*)(((char*)(rtnh)) + RTNH_ALIGN((rtnh)->rtnh_len)))
'''
def RTNH_NEXT(rtnh):
	return cast(addressof(rtnh) + RTNH_ALIGN(rtnh.rtnh_len), POINTER(rtnexthop)).contents

'''
#define RTNH_LENGTH(len) (RTNH_ALIGN(sizeof(struct rtnexthop)) + (len))
'''
RTNH_LENGTH = lambda length: RTNH_ALIGN(sizeof(rtnexthop)) + length

'''
#define RTNH_SPACE(len)	RTNH_ALIGN(RTNH_LENGTH(len))
'''
RTNH_SPACE = lambda length: RTNH_ALIGN(RTNH_LENGTH(length))

'''
#define RTNH_DATA(rtnh)   ((struct rtattr*)(((char*)(rtnh)) + RTNH_LENGTH(0)))
'''
def RTNH_DATA(rtnh):
	return cast(addressof(rtnh) + RTNH_LENGTH(0), POINTER(rtattr)).contents
	#return string_at(addressof(rtnh) + RTNH_LENGTH(0), size=length)

