#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
descr:
    database class 
    0.1.0 - first version, supports redis
"""

import sys
import time
import redis
import collections

import eq_env
import eq_cnv
from eq_cnv import tm_round_unix, lookup

DB_CONNECT_RETRY_INTERVAL = 10


class MACDatabase:

    """ class instance for all arp related """

    def __init__(self):
        self.redis = False
        if self.connect():
            print "[!] can't connect to the database"
            sys.exit(1)

    def connect(self):
        """ connect redis """

        while not self.redis_connect():
            print '[!] opening redis db failed, retrying...'
            time.sleep(DB_CONNECT_RETRY_INTERVAL)
        print '[i] redis db link established'

    def redis_connect(self):
        """ connect redis and test the link """

        result = True
        try:
            print '[i] opening db (socket way)'
            self.redis = redis.Redis(unix_socket_path=eq_env.REDIS_SOCKET, 
                    db=eq_env.REDIS_DB_ID)
        except TypeError:
            print '[i] socket not ready, trying TCP'
            self.redis = redis.Redis(host=eq_env.REDIS_HOST, port=eq_env.REDIS_PORT, 
                    db=eq_env.REDIS_DB_ID)
        try:
            self.redis.set('open', 'True')
        except redis.exceptions.ConnectionError:

            # database stopped

            print '[!] redis db seems to be stopped...'
            result = False
        except redis.exceptions.ResponseError:

            # database is loading

            print '[!] redis db seems to be loading...'
            result = False
        return result

    def disconnect(self):
        """ disconnect redis """

        # As far as I know Redis don't use this

        print '[i] disconnecting db', self.redis

    def put_mac_new_list(self, mac):
        """ PUT suspicious MAC to list """

        self.redis.lpush('mac_new', mac)

    def pop_mac_new_list(self):
        """ POP single MAC from list """

        mac = self.redis.rpop('mac_new')
        if mac:
            return mac
        else:
            return False

    def mac_update(self, unixtime, interface, mac, ipv4):
        """ Update records related to mac """

        if eq_env.DEBUG:
            print '[d]    in function update_ts(%s, %s, %s) attribute lastseen' % \
                (unixtime, mac, ipv4)
            print '[d]    is about to be updated'

        # Round unix timestamp to five minute slot

        unixtime_rounded = tm_round_unix(unixtime)

        # Increment interface MAC counter, re-set expiration

        self.redis.hincrby('mac_iface@' + interface, unixtime_rounded, 1)
        self.redis.expire('mac_iface@' + interface, eq_env.INACTIVITY_PERIOD)

        # Check if MAC is known

        if not self.redis.exists('mac_tsfs@' + mac):

            # We don't know this MAC

            self.put_mac_new_list(mac)
            self.redis.set('mac_tsfs@' + mac, unixtime)

        # Check if IPv4 is known

        if not self.redis.exists('ipv4_tsfs@' + ipv4):

            # We don't know this IPv4

            self.redis.set('ipv4_tsfs@' + ipv4, unixtime)

        # Update Last Seen timestamp on mac and ipv4

        self.redis.set('mac_tsls@' + mac, unixtime)
        self.redis.set('ipv4_tsls@' + ipv4, unixtime)

        # Insert ipv4 associated with mac, timestamp

        self.redis.hmset('mac_ipv4@' + mac, {ipv4: unixtime})

        # Insert mac associated with ipv4, timestamp

        self.redis.hmset('ipv4_mac@' + ipv4, {mac: unixtime})

        # Update timestamp om hostname (system should run nscd)

        hostname = lookup(ipv4)
        self.redis.hmset('mac_fqdn@' + mac, {hostname: unixtime})
        self.redis.hmset('ipv4_fqdn@' + ipv4, {hostname: unixtime})

        # Increment mac_cntr and ipv4_cntr

        self.redis.hincrby('mac_cntr@' + mac, unixtime_rounded, 1)
        self.redis.hincrby('ipv4_cntr@' + ipv4, unixtime_rounded, 1)

        # Re-set expiry counters

        self.redis.expire('mac_tsfs@' + mac, eq_env.INACTIVITY_PERIOD)
        self.redis.expire('mac_tsls@' + mac, eq_env.INACTIVITY_PERIOD)
        self.redis.expire('mac_ipv4@' + mac, eq_env.INACTIVITY_PERIOD)
        self.redis.expire('mac_fqdn@' + mac, eq_env.INACTIVITY_PERIOD)
        self.redis.expire('mac_cntr@' + mac, eq_env.INACTIVITY_PERIOD)

        self.redis.expire('ipv4_tsfs@' + ipv4, eq_env.INACTIVITY_PERIOD)
        self.redis.expire('ipv4_tsls@' + ipv4, eq_env.INACTIVITY_PERIOD)
        self.redis.expire('ipv4_mac@' + ipv4, eq_env.INACTIVITY_PERIOD)
        self.redis.expire('ipv4_fqdn@' + ipv4, eq_env.INACTIVITY_PERIOD)
        self.redis.expire('ipv4_cntr@' + ipv4, eq_env.INACTIVITY_PERIOD)

    def q_mac_realtime_all_known(self):
        """ List all currently known macs
            returns: list of macs
        """

        known = []
        for mac in self.redis.keys('mac_tsls@*'):
            (db_key, mac) = mac.split('@')
            known.append(mac)
        return known

    def q_mac_realtime_all_active(self):
        """ list all the active macs (now)
            returns: list of macs
        """

        active = []

        # First, get the initial unix timestamp from which we
        # will go back in time. We don't want compare with
        # early timeslot, therefore we go for the nearest
        # previous timeslot.

        unixtime_rounded = eq_cnv.tm_round_unix(eq_cnv.tm_now_unix() - 
                eq_env.TIMESLOT)

        for mac in self.redis.keys('mac_tsls@*'):
            (db_key, mac) = mac.split('@')
            mac_tsls = self.redis.get('mac_tsls@' + mac)
            mac_tsls = int(mac_tsls)
            if mac_tsls > unixtime_rounded:
                active.append(mac)
        return active

    def q_mac_realtime_active(self, mac):
        """ query if a single mac is active now 
            returns: boolean
        """

        result = False

        # First, get the initial unix timestamp from which we
        # will go back in time. We don't want compare with
        # early timeslot, therefore we go for the nearest
        # previous timeslot.

        unixtime_rounded = eq_cnv.tm_round_unix(eq_cnv.tm_now_unix() - 
                eq_env.TIMESLOT)
        mac_tsls = self.redis.get('mac_tsls@' + mac)
        if mac_tsls:
            mac_tsls = int(mac_tsls)
            if mac_tsls > unixtime_rounded:
                result = True
        return result

    def q_mac_realtime_session_duration(self, mac):
        """ Period during which the mac is active on the network 
            (backwards) starting by the current timestamp
            If the response is 0 then the mac is
            not considered active
            returns: duration of active session in !!!minutes!!!
        """

        mac_active_in_seconds = 0

        # First, get the initial unix timestamp from which we
        # will go back in time. We don't want compare with
        # early timeslot, therefore we go for the nearest
        # previous timeslot.

        unixtime_rounded = eq_cnv.tm_round_unix(eq_cnv.tm_now_unix() - 
                eq_env.TIMESLOT)

        # does the mac has any activity in timeslot (unixtime_rounded)?

        while self.redis.hget('mac_cntr@' + mac, unixtime_rounded):
            mac_active_in_seconds += eq_env.TIMESLOT

            # yes, try to rewind five minutes back yet

            unixtime_rounded = unixtime_rounded - eq_env.TIMESLOT

        # If the mac is active within timeslot which is NOW
        # add this to active time to the previously computed time

        unixtime_rounded = eq_cnv.tm_round_unix(eq_cnv.tm_now_unix())
        mac_tsls = self.redis.get('mac_tsls@' + mac)
        if mac_tsls:
            mac_tsls = int(mac_tsls)
            if mac_tsls:
                mac_tsls = mac_tsls
                if mac_tsls > unixtime_rounded:
                    mac_active_in_seconds = \
                        mac_active_in_seconds + mac_tsls - unixtime_rounded 

        return mac_active_in_seconds

    def q_mac_arp_activity(self, mac, seconds):
        """ resturs mac activity for selected time-range """

        unixtime_rounded = eq_cnv.tm_round_unix(eq_cnv.tm_now_unix() - 
                eq_env.TIMESLOT)

        unixtime_rounded_history = unixtime_rounded

        # travel back in time one week

        unixtime_rounded_history -= seconds

        result = []
        while not unixtime_rounded_history > unixtime_rounded:
            arp_count = self.redis.hget('mac_cntr@' + mac, 
                    unixtime_rounded_history)
            if arp_count:

                # javascript Flot requires milliseconds, unix time is in seconds

                result.append((unixtime_rounded_history * 1000, 
                              arp_count))
            else:

                # javascript Flot requires milliseconds, unix time is in seconds

                result.append((unixtime_rounded_history * 1000, 0))
            unixtime_rounded_history += eq_env.TIMESLOT
        return result

    def q_mac_realtime_assigned_ips(self, mac):
        """ List all IPs which mac used to communicate
            on within the last timeslot.
            returns: list of ips
        """

        assigned_ipv4s = []

        # First, get the initial unix timestamp from which we
        # will go back in time. We don't want compare with
        # early timeslot, therefore we go for the nearest
        # previous timeslot.

        unixtime_rounded = eq_cnv.tm_round_unix(eq_cnv.tm_now_unix() - 
                eq_env.TIMESLOT)

        result = self.redis.hgetall('mac_ipv4@' + str(mac))
        if result:
            for (ipv4, unixtime) in result.iteritems():
                unixtime = int(unixtime)
                if unixtime > unixtime_rounded:
                    assigned_ipv4s.append(ipv4)
        return assigned_ipv4s

    def q_mac_realtime_assigned_fqdns(self, mac):
        """ List all fqdn(s) which mac used to communicate
            on within the last timeslot.
            returns: list of fqdns
        """

        assigned_fqdns = []

        # First, get the initial unix timestamp from which we
        # will go back in time. We don't want compare with
        # early timeslot, therefore we go for the nearest
        # previous timeslot.

        unixtime_rounded = eq_cnv.tm_round_unix(eq_cnv.tm_now_unix() - 
                eq_env.TIMESLOT)

        result = {}
        result = self.redis.hgetall('mac_fqdn@' + mac)
        for (fqdn, unixtime) in result.iteritems():
            unixtime = int(unixtime)
            if unixtime > unixtime_rounded:
                assigned_fqdns.append(fqdn)
        return assigned_fqdns

    def q_mac_realtime_mac_cntr(self, mac):
        """ Return number of arp requests/replies
            for the past timeslot 
            returns: arp count (int)
        """

        # First, get the initial unix timestamp from which we
        # will go back in time. We don't want compare with
        # early timeslot, therefore we go for the nearest
        # previous timeslot.

        unixtime_rounded = eq_cnv.tm_round_unix(eq_cnv.tm_now_unix() - 
                eq_env.TIMESLOT)
        result = self.redis.hget('mac_cntr@' + mac, unixtime_rounded)
        if not result:
            result = 0
        return int(result)

    def q_mac_historical_known_since(self, mac):
        """ When this mac was first seen """

        result = self.redis.get('mac_tsfs@' + mac)
        if not result:
            result = False
        return result

    def q_mac_historical_all_ipv4s(self, mac):
        """ All the ipv4s a mac ever had assigned 
            retroactively (since beginning)
            retrurns: list (unixtime, ipv4)
        """

        assigned_ipv4s = []
        result = self.redis.hgetall('mac_ipv4@' + mac)
        for (ipv4, unixtime) in result.iteritems():
            unixtime = int(unixtime)
            assigned_ipv4s.append((unixtime, ipv4))
        return sorted(assigned_ipv4s)

    def q_mac_historical_all_fqdns(self, mac):
        """ All the fqdns a mac ever had assigned
            retroactively (since beginning)                  
            returns: list (unixtime, fqdn)
        """

        assigned_fqdns = []
        result = self.redis.hgetall('mac_fqdn@' + mac)
        for (fqdn, unixtime) in result.iteritems():
            unixtime = int(unixtime)
            assigned_fqdns.append((unixtime, fqdn))
        return sorted(assigned_fqdns)

    
    def mac_reset(self, mac):
        ''' resets/deletes the mac first seen
            attribute, so if the mac appears again
            the alert may be trigerred
        '''
        self.redis.delete('mac_tsfs@' + mac )


    def g_interface_statistics(self, interface, cycles):
        """ Get historical statistics for given interface 
            retunrs a list key = timestamp, val = value
        """

        # First, get the initial unix timestamp from which we
        # will go back in time. We don't want compare with
        # early timeslot, therefore we go for the nearest
        # previous timeslot.

        unixtime_rounded = eq_cnv.tm_round_unix(
                eq_cnv.tm_now_unix() - eq_env.TIMESLOT)
        result = []
        unixtime_rounded = unixtime_rounded - (cycles * eq_env.TIMESLOT)

        while cycles:
            val = self.redis.hget('mac_iface@' + interface, 
                                  unixtime_rounded)
            if val:
                val = int(val)
            else:
                val = 0
            result.append([unixtime_rounded * 1000, val])
            cycles -= 1
            unixtime_rounded += eq_env.TIMESLOT
        return result

    def suspect_get_related_connections(self):
        """ GET suspect's IP communication """


if __name__ == '__main__':
    print '[i] database interfacing module'
else:

    print '[i] database interfacing module loaded'

