#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Init script skeleton for Python-based service control scripts
#
# chkconfig: 123456 99 99
# description: arpmonitor3
#
### BEGIN INIT INFO
# Provides: arpmonitor3
# Required-Start:
# Required-Stop:
# Default-Start:  34
# Default-Stop:  1256
# Short-Description: arpmonitor3
# Description: arpmonitor3
### END INIT INFO

"""
desc:
    arpmonitor worker

"""

import sys
import time
import signal
import multiprocessing
import datetime
import atexit
from daemon import runner

import lib.eq_env
import lib.eq_cls_pcapy


class Worker:

    def __init__(self, interface, vlan):
        self.interface = interface
        self.vlan = vlan
        signal.signal(signal.SIGQUIT, self.stop)
        signal.signal(signal.SIGTERM, self.stop)

        self.process = multiprocessing.Process(target=self.start)
        self.process.start()

    def start(self):
        """ to fork perfectly """

        try:
            listener = lib.eq_cls_pcapy.Listener(self.interface, self.vlan)
            listener.loop()
        except KeyboardInterrupt:
            listener.stop()

    def stop(self, signum=None, frame=None):
        """ gracefully quit """

        self.process.terminate()
        sys.exit(0)


class Daemonizer:

    """ make this unix service """

    def __init__(self):
        self.stdin_path = '/dev/null'
        self.stdout_path = '/opt/arpmonitor/log/stdout_arpmonitor3'
        self.stderr_path = '/opt/arpmonitor/log/stderr_arpmonitor3'
        self.pidfile_path = '/opt/arpmonitor/run/arpmonitor3.pid'
        self.pidfile_timeout = 2

    def run(self):
        """ what does the daemon do """

        worker = {}
        cnt = 0
        for (interface, vlan) in lib.eq_env.LISTENERS.iteritems():
            worker[cnt] = Worker(interface, vlan)
            print '[i] listener(%s) %s: %s started' % (cnt, interface, 
                    vlan)
            atexit.register(worker[cnt].stop)
            cnt += 1

        while True:
            print '[i] arpmonitor master heartbeat tick...'
            time.sleep(lib.eq_env.GRACE_PERIOD)


if __name__ == '__main__':

    daemon = Daemonizer()
    daemon_runner = runner.DaemonRunner(daemon)
    daemon_runner.do_action()
else:

    print "[i] I'm not a module!"

