#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
description:
    time converisons
    ip/mac conversions
    reverse dns lookup

"""

import datetime
import time
import socket
import sys
import re
import multiprocessing

import eq_env


try:
     RE_APIPA = re.compile('^169\\.25[4|5]\\.\\d{1,3}\\.\\d{1,3}$')
except NameError:

    print '[!] cannot compile APIPA regexp'
    sys.exit(1)


def str2mac(s):
    """ ripped from scapy """

    return ('%02x:' * 6)[:-1] % tuple(map(ord, s))


def str2ip(s):
    """ ripped from scapy """

    return ('%s.' * 4)[:-1] % tuple(map(ord, s))


def arp_decode(arp):
    """ decodes arp packet src/dst mac/ip and returns a list """

    if eq_env.DEBUG:
        print '[d] decoding arp addresses'

    try:
        src_mac = str2mac(arp.sha)
        src_ip = str2ip(arp.spa)  # sha == MAC, spa == IP
        dst_mac = str2mac(arp.tha)
        dst_ip = str2ip(arp.tpa)  # tha == MAC, tpa == IP
    except OSError:

        print '[!] decoding arp addresses failed', sys.exc_info()[0]

    return (src_mac, src_ip, dst_mac, dst_ip)


def tm_now():
    """ returns datetime timestamp of now """

    return datetime.datetime.now()


def tm_now_unix():
    """ returns unix timestamp (seconds) of now """

    return int(datetime2unixtime(datetime.datetime.now()))


def tm_round_unix(unixtime):
    """ rounds unixtime to the nearest lower eq_env.TIMESLOT """

    try:
        unixtime = int(unixtime)
    except (TypeError, ValueError):
        print '[!] error while unixtime to datetime conversion'
        sys.exit(1)

    unixtime = unixtime - unixtime % eq_env.TIMESLOT
    return unixtime


def unixtime2datetime(unixtime):
    """ converts unixtime to datetime """

    try:
        unixtime = int(unixtime)
    except (TypeError, ValueError):
        print '[!] error while unixtime to datetime conversion'
        sys.exit(1)
    return datetime.datetime.fromtimestamp(unixtime)


def datetime2unixtime(time_in_datetime):
    """ converts datetime to unixtime """

    return int(time.mktime(time_in_datetime.timetuple()))


class ProcessCounter:

    def __init__(self, processes_running=0):
        self.processes_running = multiprocessing.Value('i', 
                processes_running)
        self.lock = multiprocessing.Lock()

    def inc(self):
        self.lock.acquire()
        self.processes_running.value += 1
        self.lock.release()

    def dec(self):
        self.lock.acquire()
        self.processes_running.value -= 1
        self.lock.release()

    def val(self):
        self.lock.acquire()
        result = self.processes_running.value
        self.lock.release()
        return result


def lookup(ipv4 = '0.0.0.0'):
    """ resolves ip address """

    # APIPA, no processing

    if RE_APIPA.match(ipv4):
        return 'apipa'

    # broadcast address

    if ipv4 == '0.0.0.0':
        return 'unassigned'
    try:
        (hostname, aliases, addresses) = socket.gethostbyaddr(ipv4)
    except socket.herror:
        if eq_env.DEBUG:
            print "[d] can't resolve %s" % ipv4
        hostname = ipv4
    except IndexError:
        if eq_env.DEBUG:
            print '[d] IndexError occured while resolving %s' % ipv4
        hostname = ipv4
    except socket.timeout:
        if eq_env.DEBUG:
            print '[d] socket timeout while resolving %s' % ipv4
        hostname = ipv4
    except socket.error:
        if eq_env.DEBUG:
            print '[d] socket error occured while resolving %s: ' % \
                ipv4
        hostname = ipv4
    return hostname


if __name__ == '__main__':
    print '[i] conversion module'
else:

    print '[i] conversion module loaded'

