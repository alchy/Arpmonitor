#!/usr/bin/python
# -*- coding: utf-8 -*-

import sys

import lib.eq_env
from lib.eq_cnv import *
import lib.eq_db_ipv4

import ai.mac_eval
import ai.tcp_eval
import ai.hostname_eval

WARNING_TRESHOLD = lib.eq_env.WARNING_TRESHOLD
SPACES = '                     '


def evaluate(mac):
    try:
        result = []

        ################### mac statiscics ##################

        result.append('monitored mac address:')
        result.append(SPACES + '%s' % mac)
        result.append(SPACES)

        # query realtime is mac active

        result.append('is active (online):')
        result.append(SPACES + '%s' % redisdb.q_mac_realtime_active(mac))
        result.append(SPACES)

        # query realtime session durations

        result.append('session active (min):')
        result.append(SPACES + '%s' % redisdb.q_mac_realtime_session_duration(mac))
        result.append(SPACES)

        # query historical where the mac was first seen

        result.append('known to us since:')
        known_since = redisdb.q_mac_historical_known_since(mac)
        if known_since:
            result.append(SPACES + '%s' % unixtime2datetime(known_since))
        else:
            result.append(SPACES + 'unknown')
        result.append(SPACES)

        # query realtime ips a mac had assinged during the last timeslot

        result.append('IP(s) recorded in the past timeslot:')
        for ipv4 in redisdb.q_mac_realtime_assigned_ips(mac):
            result.append(SPACES + '%s' % ipv4)
        result.append(SPACES)

        # query realtime ifqdns a mac had assinged during the last timeslot

        result.append('FQDN(s) recorded in the past timeslot:')
        for fqdn in redisdb.q_mac_realtime_assigned_fqdns(mac):
            result.append(SPACES + '%s' % fqdn)
        result.append(SPACES)

        # all ipv4s registred for this mac

        result.append('all IP(s) assigned until now:')
        for (unixtime, ipv4) in redisdb.q_mac_historical_all_ipv4s(mac):
            result.append(SPACES + '%s - %s' % (unixtime2datetime(unixtime), 
                          ipv4))
        result.append(SPACES)

        # all fqdns for this mac

        result.append('all FQDN(s) assigned until now:')
        for (unixtime, fqdn) in redisdb.q_mac_historical_all_fqdns(mac):
            result.append(SPACES + '%s - %s' % (unixtime2datetime(unixtime), 
                          fqdn))
        result.append(SPACES)

        # ai evalution

        send_mail = True
        ai_mac_score = ai.mac_eval.ai_mac(mac)

        result.append(SPACES)
        result.append('mac %s address score:' % mac)
        result.append(SPACES + '%s' % ai_mac_score)

        for ipv4 in redisdb.q_mac_realtime_assigned_ips(mac):
            ai_ipv4_score = ai.tcp_eval.ai_ipv4(ipv4)
            result.append(SPACES)
            result.append('ipv4 %s address score:' % ipv4)
            result.append(SPACES + '%s' % ai_ipv4_score)
            for fqdn in redisdb.get_last_fqdn(ipv4):
                ai_hostname_score = ai.hostname_eval.ai_fqdn(fqdn)
                result.append(SPACES)
                result.append('hostname %s score:' % fqdn)
                result.append(SPACES + '%s' % ai_hostname_score)

                ai_total_score = ai_mac_score + ai_ipv4_score + \
                    ai_hostname_score + 1
                ai_total_score = ai_total_score / 3
                print '[i] ai_mac_score: %s, ai_ipv4_score: %s, ai_hostname_score: %s' % \
                    (ai_mac_score, ai_ipv4_score, ai_hostname_score)
                print '[i] ai total score is %s' % ai_total_score
                if ai_total_score > WARNING_TRESHOLD:
                    send_mail = False

        # query port scan results for the respecitve ipv4

        result.append(SPACES)
        for ipv4 in redisdb.q_mac_realtime_assigned_ips(mac):
            if ipv4 != '0.0.0.0':
                result.append('open tcp ports found:')
                result.append(SPACES + '%s' % unixtime2datetime(redisdb.get_scan_last_unixtime(ipv4)))
                result.append(SPACES)

                (ipv4_scan_results, port_descr) = redisdb.get_last_tcp_port_states(ipv4)
                for ipv4_scan_result in ipv4_scan_results:
                    if ipv4_scan_results[ipv4_scan_result] == 'open':
                        result.append(SPACES + '%s\t\t%s\t%s\t%s' % (ipv4, 
                                ipv4_scan_result, ipv4_scan_results[ipv4_scan_result], 
                                port_descr[ipv4_scan_result]))
                result.append(SPACES)
        result.append(SPACES)

        # deails on web

        result.append('please check the following url for more information:')
        result.append(SPACES + 
                      'https://myczsl0bl0secarp1.cz.money.ge.com/arpmonitor/mac/profile/?mac=%s' % 
                      mac)
        result.append(SPACES)

    except KeyboardInterrupt:
        sys.exit(0)

    return (send_mail, result)


redisdb = lib.eq_db_ipv4.IPv4Database()

