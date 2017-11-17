#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Init script skeleton for Python-based service control scripts
#
# chkconfig: 123456 99 99
# description: arpmonitor3_queue scans discovered hardware
#
### BEGIN INIT INFO
# Provides: arpmonitor3_queue
# Required-Start:
# Required-Stop:
# Default-Start:  34
# Default-Stop:  1256
# Short-Description: ipv4queue refiller for arpmonitor3
# Description: arpmonitor3_queue scans discovered hardware
### END INIT INFO

"""
description:
    event processing and rescan

"""

import sys
import signal
import multiprocessing
import atexit
import time
from daemon import runner

import lib.eq_env
from lib.eq_cnv import tm_now_unix
import lib.eq_db_ipv4
import lib.eq_cls_ipv4scanner
import lib.eq_evaluate
import lib.eq_smtp


def queue_prio():
    """ get all the new(not yet known) macs and put their
        ipv4s into the priority scan queue
    """

    mac = db.pop_mac_new_list()
    while mac:
        ipv4s = db.q_mac_realtime_assigned_ips(mac)
        if ipv4s:
            ipv4s_scanned = False
            for ipv4 in ipv4s:
                if lib.eq_env.DEBUG:
                    print '[i] new mac - %s / %s will be scanned and evaluated' % \
                        (mac, ipv4)  # unique ipv4
                scan = lib.eq_cls_ipv4scanner.Scanner(ipv4, db_handle=db)
                if scan.start():
                    
                    #  at least one ipv4 must be scanned if the mac is new 

                    ipv4s_scanned = True
                    if lib.eq_env.DEBUG:
                        print '[i] evalution triggered for %s / %s' % (mac, 
                                ipv4)

                    # do the checks and send the mail eventually

                    (send_mail, check_result) = lib.eq_evaluate.evaluate(mac)
                    if send_mail:
                        lib.eq_smtp.sendmail( 
                            subject = "A3: %s (a new hardware found)" % (mac),
                            content = ('\n').join(check_result)) # check result is a list
                    else:
                        print '[i] mail was not send as the hardware %s passed the test' % \
                            mac

            if not ipv4s_scanned:
                if lib.eq_env.DEBUG:
                    print '[i] new mac - %s / %s returned to the prio queue' % \
                        (mac, ipv4)

                # no ipv4 assigned (yet) to the mac? 
                # then put the mac back to the queue

                db.put_mac_new_list(mac)
        mac = db.pop_mac_new_list()  # redis pops randomly


def queue_regular():
    """ get all the active macs, get their currently assigned ipv4s
        if ipv4 was not scanned within the GRACE_PERIOD, rescan 
    """

    for mac in db.q_mac_realtime_all_active():
        ipv4s = db.q_mac_realtime_assigned_ips(mac)
        if ipv4s:
            for ipv4 in ipv4s:
                last_scan_unixtime = db.get_scan_last_unixtime(ipv4)
                if last_scan_unixtime + lib.eq_env.GRACE_PERIOD < \
                    tm_now_unix():
                    if lib.eq_env.DEBUG:
                        print '[i] old mac - %s / %s will be rescanned' % \
                            (mac, ipv4)
                    scan = lib.eq_cls_ipv4scanner.Scanner(ipv4, 
                            db_handle=db)
                    scan.start()


class QueuePrio:

    """ priority queue wrapper """

    def __init__(self):
        signal.signal(signal.SIGQUIT, self.stop)
        signal.signal(signal.SIGTERM, self.stop)

        self.process = multiprocessing.Process(target=self.start)
        self.process.start()

    def start(self):
        try:
            while True:
                queue_prio()
                if lib.eq_env.DEBUG:
                    print '[i] priority queue goes to sleep'
                time.sleep(10)
                if lib.eq_env.DEBUG:
                    print '[i] priority queue woke up'
        except KeyboardInterrupt:

            if lib.eq_env.DEBUG:
                if lib.eq_env.DEBUG:
                    print '[d] KeyboardInterrupt in loop'
            self.stop()

    def stop(self, signum=None, frame=None):
        """ gracefully quit """

        try:
            self.process.terminate()
        except AttributeError:
            pass
        sys.exit(0)


class QueueRegular:

    """ provides wrapper for tcp-rescan function """

    def __init__(self):
        signal.signal(signal.SIGQUIT, self.stop)
        signal.signal(signal.SIGTERM, self.stop)

        self.process = multiprocessing.Process(target=self.start)
        self.process.start()

    def start(self):
        try:
            while True:
                queue_regular()
                time.sleep(lib.eq_env.GRACE_PERIOD)
        except KeyboardInterrupt:

            if lib.eq_env.DEBUG:
                print '[d] KeyboardInterrupt in loop'
            self.stop()

    def stop(self, signum=None, frame=None):
        """ gracefully quit, at least one process 
            must close db """

        db.disconnect()
        try:
            self.process.terminate()
        except AttributeError:
            pass
        sys.exit(0)


class Daemonizer:

    """ make this unix service """

    def __init__(self):
        self.stdin_path = '/dev/null'
        self.stdout_path = \
            '/opt/arpmonitor/log/stdout_arpmonitor3_queue'
        self.stderr_path = \
            '/opt/arpmonitor/log/stderr_arpmonitor3_queue'
        self.pidfile_path = '/opt/arpmonitor/run/ipv4queue.pid'
        self.pidfile_timeout = 5

    def run(self):
        """ what does the daemon do """

        mp_task_reg = {}
        for mp_task_reg_nr in range(1, lib.eq_env.QUEUE_REGULAR_PROCESSES):
            mp_task_reg[mp_task_reg_nr] = QueueRegular()
            atexit.register(mp_task_reg[mp_task_reg_nr].stop)

        mp_task_pri = {}
        for mp_task_pri_nr in range(1, lib.eq_env.QUEUE_PRIO_PROCESSES):
            mp_task_pri[mp_task_pri_nr] = QueuePrio()
            atexit.register(mp_task_pri[mp_task_pri_nr].stop)

        while True:
            print '[i] ipv4queue master heartbeat tick...'
            time.sleep(lib.eq_env.GRACE_PERIOD)


if __name__ == '__main__':

    db = lib.eq_db_ipv4.IPv4Database()

    daemon = Daemonizer()
    daemon_runner = runner.DaemonRunner(daemon)
    daemon_runner.do_action()
else:

    print "[i] I'm not a module!"

