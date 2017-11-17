#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
description:
    scanner class (ipv4 tcp only)

"""

import signal
import socket
import time
import errno
import re
import sys

import eq_env
from eq_cnv import tm_now_unix, tm_round_unix
import eq_db_ipv4

RE_APIPA = re.compile('^169\\.25[4|5]\\.\\d{1,3}\\.\\d{1,3}$')


class Scanner:

    """ Scanner class with SIGQUIT/SIGTERM signal handler """

    def __init__(self, ipv4, db_handle=False):
        if eq_env.DEBUG:
            print '[d] got %s ipv4 to scan' % ipv4

        self.ipv4 = ipv4
        self.scan_idle = eq_env.SCAN_IDLE

        if not db_handle:
            self.ipv4db = eq_db_ipv4.IPv4Database()
        else:
            self.ipv4db = db_handle

        signal.signal(signal.SIGQUIT, self.stop)
        signal.signal(signal.SIGTERM, self.stop)

    def stop(self, signum=None, frame=None):
        """ stops Scanner process """

        if eq_env.DEBUG:
            print '[d] stopping child Scanner process for %s' % self.ipv4
            print '[i] graceful quit: %s, %s' % (signum, frame)
        sys.exit(0)

    def scan_tcp_port(self, port):
        """ connect to the tcp port and return
            it's state
        """

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            sock.settimeout(eq_env.SCAN_TIMEOUT)

            result = errno.errorcode.get(sock.connect_ex((self.ipv4, 
                    port)))

            sock.settimeout(None)
            sock.close()
        except socket.gaierror:

            if eq_env.DEBUG:
                print '[i] error in hostname resolution for %s' % self.ipv4
            self.stop()
        except socket.error:

            if eq_env.DEBUG:
                print "[i] couldn't connect to %s" % self.ipv4
            self.stop()

        return result

    def start(self):
        """ start scan """

        try:
            if self.ipv4db.is_ipv4_active(self.ipv4) and self.ipv4 != \
                '0.0.0.0' and not RE_APIPA.match(self.ipv4) and not self.ipv4db.get_scan_lock(self.ipv4):

                self.ipv4db.set_scan_lock(self.ipv4, eq_env.GRACE_PERIOD)

                if eq_env.DEBUG:
                    print '[i] starting scan for %s' % self.ipv4

                scan_results = {}
                for (port, descr) in eq_env.SCAN_PORTS:

                    result = self.scan_tcp_port(port)
                    if result == None:
                        scan_results[port] = 'open'
                    elif result == 'ECONNREFUSED':
                        scan_results[port] = 'closed'
                    elif result == 'EALREADY':
                        scan_results[port] = 'unreachable'
                    elif result == 'EHOSTUNREACH':
                        scan_results[port] = 'unreachable'
                    else:
                        scan_results[port] = 'unknown %s' % result

                    # McAfee detects portscan (but no viruses)

                    time.sleep(self.scan_idle)

                # timestamp - scan complete

                unixtime_scan_round = tm_round_unix(tm_now_unix())

                # get the previous scan's timestamp

                unixtime_scan_prev = self.ipv4db.get_scan_last_unixtime(self.ipv4)

                # save scan results

                for (port, descr) in eq_env.SCAN_PORTS:
                    self.ipv4db.set_scan_tcp(self.ipv4, port, 
                            scan_results[port], unixtime_scan_round)

                # update scan timestamp

                self.ipv4db.set_scan_last_unixtime(self.ipv4, 
                        unixtime_scan_round)

                # delete or move previous scan

                for (port, descr) in eq_env.SCAN_PORTS:
                    self.ipv4db.delete_scan_tcp(self.ipv4, port, 
                            unixtime_scan_prev)

                # remove scan lock

                self.ipv4db.del_scan_lock(self.ipv4)

                return True  # scan finished
            else:

                if eq_env.DEBUG:
                    if self.ipv4 == '0.0.0.0':
                        print '[i] %s is excluded' % self.ipv4
                    if self.ipv4db.get_scan_lock(self.ipv4):
                        print '[i] %s has a lock' % self.ipv4
                    if not self.ipv4db.is_ipv4_active(self.ipv4):
                        print '[i] %s is inactive' % self.ipv4
                    if RE_APIPA.match(self.ipv4):
                        print '[i] %s is apipa' % self.ipv4
                return False  # scan was not run
        except KeyboardInterrupt:

            if eq_env.DEBUG:
                print '[d] KeyboardInterrupt in loop'
            self.stop()


if __name__ == '__main__':
    print '[i] ipv4 tcp scanner class'
else:

    print '[i] ipv4 tcp scanner class loaded'

