import os
import time
import threading

from collections import deque
from macros import *
from netlink import *

import logging

logging.basicConfig(format="%(asctime)s - %(module)s - %(levelname)s - %(message)s")
LOG = logging.getLogger(__name__)
LOG.setLevel(logging.DEBUG)

BUFFSIZE = 65535
MAXLEN = 1000


def parse_rtattrs(rta, rtl):
	
	tb = []

	while RTA_OK(rta, rtl):

		if rta.rta_type == RTA_MULTIPATH:

			nh = Unpack(rtnexthop, RTA_DATA(rta, rtl))
			nh_len = RTA_PAYLOAD(rta);

			nh_tb = []
			while True:
				if nh_len < sizeof(rtnexthop):
					break
				if nh.rtnh_len > nh_len:
					break

				if nh.rtnh_len > sizeof(rtnexthop):
					result = parse_rtattrs(RTNH_DATA(nh), nh.rtnh_len - sizeof(rtnexthop))
					LOG.debug("nexthop: %r", nh)
					LOG.debug("nexthop attributes: %r", result)
					nh_tb.append((nh, result))

				nh_len -= NLMSG_ALIGN(nh.rtnh_len)
				nh = RTNH_NEXT(nh)

			tb.append((rta, nh_tb))

		else:
			attrlen = RTA_PAYLOAD(rta)
			attrdata = RTA_DATA(rta, attrlen)
			tb.append((rta, attrdata))

		rta, rtl = RTA_NEXT(rta, rtl)

	return tb


def process_netlink_mesage(data):

	nlh = Unpack(nlmsghdr, data)
	length = nlh.nlmsg_len

	while NLMSG_OK(nlh, length):
		if nlh.nlmsg_type == NLMSG_DONE:
			break

		if nlh.nlmsg_type == NLMSG_ERROR:
			break

		command = get_netlink_command(nlh)
		LOG.debug("Command: %s", command)
		LOG.debug("struct nlmsg: (%r)", nlh)
		
		if nlh.nlmsg_type in [RTM_NEWROUTE, RTM_DELROUTE]:
			nldata = Unpack(rtmsg, NLMSG_DATA(nlh))
			LOG.debug("struct rtmsg: (%r)", nldata)
			
			rta = RTM_RTA(nldata)
			rtl = RTM_PAYLOAD(nlh)

		elif nlh.nlmsg_type in [RTM_NEWLINK, RTM_DELLINK]:
			nldata = Unpack(ifinfomsg, NLMSG_DATA(nlh))
			LOG.debug("struct ifinfomsg: (%r)", nldata)

			rta = IFLA_RTA(nldata)
			rtl = IFLA_PAYLOAD(nlh)

		elif nlh.nlmsg_type in [RTM_NEWADDR, RTM_DELADDR]:
			nldata = Unpack(ifaddrmsg, NLMSG_DATA(nlh))
			LOG.debug("struct ifaddrmsg: (%r)", nldata)

			rta = IFA_RTA(nldata)
			rtl = IFA_PAYLOAD(nlh)
		
		else:
			break

		tb = parse_rtattrs(rta, rtl)

		LOG.debug("List of attributes:")
		for attr, v in tb:
			name, value = netlink_decode(command, socket.AF_INET, attr.rta_type, v)
			LOG.debug("%s (%d): %r", name, attr.rta_type, value)

		nlh, length = NLMSG_NEXT(nlh, length)


class Worker(threading.Thread):

	def __init__(self, queue):
		threading.Thread.__init__(self)
		self.queue = queue
		self.running = True
		self.daemon = True

	def run(self):
		while self.running:
			try:
				task = self.queue.popleft()
			except IndexError:
				time.sleep(.5)
				continue

			func, args = task[0], task[1:]

			try:
				func(*args)
			except Exception as e:
				LOG.error('Monitor got exception: %s' % e, exc_info=True)

	def terminate(self):
		self.running = False


class Monitor(threading.Thread):

	def __init__(self):
		threading.Thread.__init__(self)
		self.sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE)
		self.sock.bind((os.getpid(), RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV4_ROUTE))
		self.queue = deque(maxlen=MAXLEN)
		self.worker = Worker(self.queue)
		self.daemon = True
		self.running = True

	def cleanup(self):
		self.sock.close()

	def terminate(self):
		LOG.info("Terminate monitor")
		self.worker.terminate()
		self.running = False
		self.cleanup()

	def run(self):
		LOG.info("Monitor started...")

		self.worker.start()

		while self.running:
			try:
				data = self.sock.recv(BUFFSIZE)
				self.queue.append((process_netlink_mesage, data))
			except Exception as e:
				LOG.info("Got exception: %s", e, exc_info=True)
				continue


def main():

	netlink_monitor = Monitor()
	netlink_monitor.start()

	while True:
		try:
			time.sleep(1)
		except KeyboardInterrupt:
			netlink_monitor.terminate()
			break


if __name__ == "__main__":
	
	main()

