#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
description:
    class used by ipv4scanner procesess
    inherits eq_db_mac.MACDatabase

"""

import eq_env
from eq_cnv import tm_round_unix, tm_now_unix
import eq_db_mac


class IPv4Database(eq_db_mac.MACDatabase):

    """ class instance for all IPv4 related 
        ipv4 scans, ipv4 queues...
    """

    ################################################################
    # ipv4 scan metadata (last finished ipv4 scan unixtime, 
    #                     ipv4 scan lock)
    # - metadata expires automatically

    def get_scan_last_unixtime(self, ipv4):
        """ return timestamp of the last 
            completed scan
        """

        unixtime_scan_last = self.redis.get('ipv4_tsla@' + ipv4)

        if not unixtime_scan_last:
            unixtime_scan_last = 0

        return int(unixtime_scan_last)

    def set_scan_last_unixtime(self, ipv4, unixtime):
        """ set timestamp of the last
            completed scan
        """

        self.redis.set('ipv4_tsla@' + ipv4, unixtime)
        self.redis.expire('ipv4_tsla@' + ipv4, eq_env.INACTIVITY_PERIOD)

    def get_scan_lock(self, ipv4):
        """ is a scan running on this ipv4? """

        result = False
        try:
            if self.redis.get('ipv4_srun@' + ipv4) == 'True':
                result = True
        except:
            pass
        return result

    def set_scan_lock(self, ipv4, expiration):
        """ lock to prevent dual scan """

        self.redis.set('ipv4_srun@' + ipv4, 'True')
        self.redis.expire('ipv4_srun@' + ipv4, expiration)

    def del_scan_lock(self, ipv4):
        """ unlock for the next scan """

        self.redis.delete('ipv4_srun@' + ipv4)

    ################################################################
    # storing scan results
    # - scan result data expires automatically

    def delete_scan_tcp(self, ipv4, port, unixtime):
        """ delete scan or move to static RDDBMS, save RAM """

        self.redis.delete('ipv4_tscn@' + ipv4 + ':' + str(port) + ':' + 
                          str(unixtime))

    def set_scan_tcp(self, ipv4, port, state, unixtime):
        """set tcp port scan result """

        self.redis.set('ipv4_tscn@' + ipv4 + ':' + str(port) + ':' + str(unixtime), 
                       state)
        self.redis.expire('ipv4_tscn@' + ipv4 + ':' + str(port) + ':' + 
                          str(unixtime), eq_env.INACTIVITY_PERIOD)

    ################################################################
    # getting the last tcp scan result(s)

    def get_last_tcp_port_state(self, ipv4, tcp_port):
        """ Return the last known state of the port
            or 'timeout' if the scan is outdated
        """

        last_scan_unixtime = self.get_scan_last_unixtime(ipv4)
        last_scan_unixtime_rounded = tm_round_unix(last_scan_unixtime)

        result = self.redis.get('ipv4_tscn@' + str(ipv4) + ':' + str(tcp_port) + 
                                ':' + str(last_scan_unixtime_rounded))

        if not result:
            result = 'outdated'
        return result

    def get_last_tcp_port_states(self, ipv4):
        """ Return the last known state of all ports
        """

        result_state = {}
        result_descr = {}
        for (port, descr) in eq_env.SCAN_PORTS:
            result_state[port] = self.get_last_tcp_port_state(ipv4, str(port))
            result_descr[port] = descr
        return (result_state, result_descr)

    ################################################################
    # ip addresses statistics (alive, known)

    def is_ipv4_active(self, ipv4):
        """ returns boolean """

        result = False
        unixtime_rounded = tm_round_unix(tm_now_unix() - eq_env.TIMESLOT)

        try:
            ipv4_tsls = self.redis.get('ipv4_tsls@' + ipv4)
            if ipv4_tsls:
                ipv4_tsls = int(ipv4_tsls)
                if ipv4_tsls > unixtime_rounded:
                    result = True
        except:
            pass
        return result

    def get_all_active_ipv4s(self):
        """ List all currently active ipv4s
            returns: list of ipv4s
        """

        active = []
        unixtime_rounded = tm_round_unix(tm_now_unix() - eq_env.TIMESLOT)

        for ipv4 in self.redis.keys('ipv4_tsls@*'):
            (db_key, ipv4) = ipv4.split('@')
            ipv4_tsls = self.redis.get('ipv4_tsls@' + ipv4)
            ipv4_tsls = int(ipv4_tsls)
            if ipv4_tsls > unixtime_rounded:
                active.append(ipv4)
        return active

    def get_all_known_ipv4s(self):
        """ List all currently known ipv4s
            returns: list of ipv4s
        """

        known = []
        for ipv4 in self.redis.keys('ipv4_tsls@*'):
            (db_key, ipv4) = ipv4.split('@')
            known.append(ipv4)
        return known

    ################################################################
    # ipv4 properties

    def get_last_fqdn(self, ipv4):
        """ get last known fqdn of the mac """

        assigned_fqdns = []

        unixtime_rounded = tm_round_unix(tm_now_unix() - eq_env.TIMESLOT)

        result = self.redis.hgetall('ipv4_fqdn@' + ipv4)
        for (fqdn, unixtime) in result.iteritems():
            unixtime = int(unixtime)
            if unixtime > unixtime_rounded:
                assigned_fqdns.append(fqdn)
        return assigned_fqdns


