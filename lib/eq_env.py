#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
description:
    standard interface for setting up the environment

history:
    0.1.0 - first version 
"""

__version__ = '0.9.0'
__author__ = 'nej'

import syslog

' DEBUG '
try:
    from eq_config import DEBUG
except ImportError:

    #DEBUG = False

    DEBUG = True
    print '[i] DEBUG is not configured, using defaults'

' INTERFACES & VLANS '
try:
    from eq_config import LISTENERS
except ImportError:
    LISTENERS = {'eth1': 'vlan1', 'eth2': 'vlan2', 'eth3': 'vlan3', 
                 'eth4': 'vlan4'}
    print '[i] INTERFACES & VLANS is not configured, using defaults'

' REDIS DATABASE '
try:
    from eq_config import REDIS_DB_ID
except ImportError:
    REDIS_DB_ID = 0

try:
    from eq_config import REDIS_SOCKET
except ImportError:
    REDIS_SOCKET = '/opt/arpmonitor/redis/redis.sock'

try:
    from eq_config import REDIS_HOST
except ImportError:
    REDIS_HOST = '127.0.0.1'

try:
    from eq_config import REDIS_PORT
except ImportError:
    REDIS_PORT = 6379

' BPF_FILTER '
try:
    from eq_config import BPF_FILTER
except ImportError:
    BPF_FILTER = 'arp'
    print '[i] BPF_FILTER is not configured, using defaults'

' PORTS TO SCAN '
try:
    from eq_config import SCAN_PORTS
except ImportError:
    SCAN_PORTS = (
        (135, ''), 
        (445, ''), 
        (3389, ''), 
        (4105, ''), 
        (4728, ''), 
        (5357, ''), 
        (7163, ''), 
        (8081, ''), 
        (49152, ''), 
        (49153, ''), 
        (49154, ''), 
        (55399, ''), 
        (61474, ''), 
        (62494, ''), 
        (22, ''), 
        (80, ''), 
        (443, ''), 
        (25, ''), 
        )

' IDLE INTERVAL FOR THE CONSQUENT SCAN '
try:
    from eq_config import SCAN_IDLE
except ImportError:
    SCAN_IDLE = 5  # idle (in seconds) before scanning next port

' SCAN TIMEOUT '
try:
    from eq_config import SCAN_TIMEOUT
except ImportError:
    SCAN_TIMEOUT = 2  # socket connect timeout in seconds

' SCAN(REGULAR QUEUE) PROCESSES_MAX '
try:
    from eq_config import QUEUE_REGULAR_PROCESSES
except ImportError:
    QUEUE_REGULAR_PROCESSES = 256

' SCAN(PRIORITYi QUEUE) PROCESSESS MAX '
try:
    from eq_config import QUEUE_PRIO_PROCESSES
except ImportError:
    QUEUE_PRIO_PROCESSES = 4

' SYSLOG_FACILITY & SYSLOG_PRIORITY '
try:
    from eq_config import SYSLOG_FACILITY
except ImportError:
    SYSLOG_FACILITY = syslog.LOG_USER
    print '[i] SYSLOG_FACILITY is not configured, using defaults'

try:
    from eq_config import SYSLOG_PRIORITY
except ImportError:
    SYSLOG_PRIORITY = syslog.LOG_INFO
    print '[i] SYSLOG_PRIORITY is not configured, using defaults'

' TIMESLOT '
try:
    from eq_config import TIMESLOT
except ImportError:

    # TIMESLOT 
    # (do not change this until you know
    # what you are doing!)

    TIMESLOT = 5 * 60

' GRACE_PERIOD & INACTIVITY_PERIOD (in seconds)'
try:
    from eq_config import GRACE_PERIOD
    ''' host not active longer than GRACE_PERIOD(s) is considered
        turned off. This is the only use. 
    '''
except ImportError:

    # GRACE_PERIOD is in seconds

    GRACE_PERIOD = 300  # 5 minutes
    print '[i] GRACE_PERIOD is not configured, using defaults'

try:
    from eq_config import INACTIVITY_PERIOD
    ''' if host is not active longer then INACTIVITY_PERIOD, all the
        host data is deleted from the database 
    '''
except ImportError:

    # INACTIVITY_PERIOD is in seconds
    # 86400 = a day

    INACTIVITY_PERIOD = (86400 * 31) * 3  # 3 months
    print '[i] INACTIVITY_PERIOD is not configured, using defaults'

try:
    from eq_config import NETFLOW_HISTORY_MAX
    ' maximal netflow backward lookup '
except ImportError:
    NETFLOW_HISTORY_MAX = 259200  # max 3 days of netflow history
    print '[i] NETFLOW_HISTORY_MAX is not configured, using defaults'

try:
    from eq_config import WARNING_TRESHOLD
    ' if the hardware gets the lower score then the \n        WARNING_TRESHOLD then the email alert is triggered '
except ImportError:
    WARNING_TRESHOLD = 35
    print '[i] WARNING_TRESHOLD is not configured, using defaults'

if __name__ == '__main__':
    print '[i] environment settings module'
else:
    print '[i] environment settings module loaded'

