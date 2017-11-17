#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
desc:
    all related to sniffing around, with pcapy
"""

import sys
import pcapy
import dpkt
import signal

import eq_env
from eq_cnv import arp_decode
import eq_db_mac

# didable debug in this module

eq_env.DEBUG = False


class Listener:

    """ Listener class with SIGQUIT/SIGTERM signal handler """

    def __init__(self, interface=None, vlan=None):
        self.interface = interface
        self.vlan = vlan
        self.pc = None
        self.macdb = eq_db_mac.MACDatabase()
        self.bind(self.interface)

        signal.signal(signal.SIGQUIT, self.stop)
        signal.signal(signal.SIGTERM, self.stop)

    def stop(self, signum=None, frame=None):
        """ stops Listener process """

        if eq_env.DEBUG:
            print '[d] stopping child Listener process bound on %s: %s, %s' % \
                (self.interface, signum, frame)

        # close macdb if needed

        self.macdb.disconnect()
        sys.exit(0)

    def bind(self, interface):
        """ binds Listener to interface """

        if eq_env.DEBUG:
            print '[d] entering function bind(%s)' % interface

        try:
            self.pc = pcapy.open_live(interface, 65536, False, 0)
        except pcapy.PcapError:

            print '[!] error binding interface %s:' % interface, sys.exc_info()[0]
            self.stop()

        if eq_env.DEBUG:
            print '[d] Setting BPF filter to "%s"' % eq_env.BPF_FILTER

        try:
            self.pc.setfilter(eq_env.BPF_FILTER)
        except OSError, err:

            print '[!] cannot set BPF filter:\n\t%s <- %s' % (eq_env.BPF_FILTER, 
                    err)
            sys.exit(1)

        if eq_env.DEBUG:
            print '[d] leaving function bind(%s)' % interface

    def loop(self):
        """ never ending loop for packet capturing """

        packet_limit = -1  # infinite
        try:
            self.pc.loop(packet_limit, self.recv_pkts)  # capture packets
        except KeyboardInterrupt:
            if eq_env.DEBUG:
                print '[d] KeyboardInterrupt in loop'

    def recv_pkts(self, hdr, pkt):
        """ process captured packet """

        if eq_env.DEBUG:
            print '[d] entering function listen ', self.pc

        try:

            # listen for arp
            # arp request has target MAC 00:00:00:00:00:00
            # but the ethernet frame itself has destination MAC ff:ff:ff:ff:ff:ff

            try:
                arp = dpkt.ethernet.Ethernet(pkt).arp
                (src_mac, src_ip, dst_mac, dst_ip) = arp_decode(arp)
            except (AttributeError, TypeError):

                if eq_env.DEBUG:
                    print '[!] invalid packet (not ARP)'

            if arp.op == dpkt.arp.ARP_OP_REQUEST:

                                                   # ARP request

                self.macdb.mac_update(unixtime=hdr.getts()[0], interface=
                        self.interface, mac=src_mac, ipv4=src_ip)

                if eq_env.DEBUG:
                    print '[d] arp request (%s) from: mac/ip %s/%s to: mac/ip %s/%s' % \
                        (self.interface, src_mac, src_ip, dst_mac, 
                         dst_ip)
            elif arp.op == dpkt.arp.ARP_OP_REPLY:

                                                   # ARP reply

                self.macdb.mac_update(unixtime=hdr.getts()[0], interface=
                        self.interface, mac=src_mac, ipv4=src_ip)

                if eq_env.DEBUG:
                    print '[d] arp reply   (%s) from: mac/ip %s/%s to: mac/ip %s/%s' % \
                        (self.interface, src_mac, src_ip, dst_mac, 
                         dst_ip)
            elif eq_env.DEBUG:

                print '[!] unexpected ARP op: %s' % str(arp.op)
        except OSError:

            print '[!] error in function listen ', self.pc, sys.exc_info()[0]
            sys.exit(1)

        if eq_env.DEBUG:
            print '[d] leaving function listen ', self.pc

        return True


if __name__ == '__main__':

    print '[i] pcapy listener module'
else:

    print '[i] pcapy listener module loaded'

