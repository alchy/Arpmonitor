#!/usr/bin/python
# -*- coding: utf-8 -*-

import sys
import os

sys.path.append('/opt/arpmonitor/lib/')
sys.path.append('/opt/arpmonitor/ai/')
sys.path.append('/usr/lib/python2.4/site-packages/pam-0.1.3-py2.4.egg')
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

import datetime
import re
import base64
import urllib2
import web
import pam
import redis
import simplejson as json

import eq_env
from eq_cnv import unixtime2datetime
import eq_db_ipv4

# ai imports

import mac_eval
import tcp_eval
import hostname_eval

# identify apipa address

RE_APIPA = re.compile('^169\\.25[4|5]\\.\\d{1,3}\\.\\d{1,3}$')

# netflow server

NETFLOW_SERVER = 'splsec1'

# connect to redis db on program start

ipv4db = eq_db_ipv4.IPv4Database()


def verify_the_param_is_a_mac(mac):
    ''' checks if the param is a mac '''

    if not mac:
        raise TypeError
    if not re.match("[0-9a-f]{2}([-:])[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", mac.lower()):
        raise TypeError

    return str(mac)


class Gauge:

    """ gauge page element interface class """

    def __init__(self, val, max):
        self.min = 0
        self.val = val
        self.max = max

    def dumps(self):
        dict = self.__dict__
        return dict


class JsonObject:

    """ serialize objects with name """

    def __init__(self):
        self.members = {}

    def add(self, name, object):
        (self.members)[name] = object.dumps()

    def dumps(self):
        return json.dumps(self.members)


urls = (
    '/json/engine/realtime/gauges/(.*)', 
    'Json_Engine_Realtime_Gauges', 

    '/json/engine/statistics/arp/interface/(.*)', 
    'Json_Engine_Statictics_ARP_Interface', 

    '/json/mac/list/registered/complete/(.*)', 
    'json_mac_list_registered_complete', 

    '/json/mac/list/active/complete/(.*)', 
    'json_mac_list_active_complete', 

    '/json/mac/list/active/excludes/(.*)', 
    'json_mac_list_active_excludes', 

    '/json/mac/ipv4/all/(.*)', 
    'json_mac_ipv4_all', 

    '/json/mac/hostname/all/(.*)', 
    'json_mac_hostname_all', 

    '/json/mac/scan/latest/(.*)', 
    'json_mac_scan_last', 

    '/json/mac/arp/stats/(.*)', 
    'json_mac_arp_stats', 

    '/json/mac/details/(.*)', 
    'json_mac_details', 

    '/json/mac/ai/score/(.*)', 
    'json_mac_ai_score', 

    '/json/mac/netflow/(.*)', 
    'json_mac_netflow', 

    '/page/mac/list/registered/complete/(.*)', 
    'page_mac_list_registered_complete', 

    '/page/mac/list/active/complete/(.*)', 
    'page_mac_list_active_complete', 

    '/page/mac/list/active/excludes/(.*)', 
    'page_mac_list_active_excludes', 

    '/mac/profile/(.*)', 
    'ProfileMAC', 

    '/function/mac/reset/(.*)',
    'mac_reset',

    '/(.*)', 
    'page_index', 
    )

# define application

app = web.application(urls, globals())

# where the templates are

render = web.template.render('/opt/arpmonitor/gui/templates/')

# globals (render in page)

(web.template.Template.globals)['render'] = render


class page_index:

    def GET(self, argv):
        return render.index()


class page_mac_list_active_complete:

    def GET(self, argv):
        return render.page_mac_list_active_complete()


class page_mac_list_active_excludes:

    def GET(self, argv):
        return render.page_mac_list_active_excludes()


class page_mac_list_registered_complete:

    def GET(self, argv):
        return render.page_mac_list_registered_complete()


class ProfileMAC:

    def GET(self, argv):
        return render.page_mac_profile()


class Json_Engine_Realtime_Gauges:

    def GET(self, argv):
        print '[d] engine gauges'
        serialize = JsonObject()

        # mac known/active

        serialize.add('g1', Gauge(len(ipv4db.q_mac_realtime_all_active()), 
                      len(ipv4db.q_mac_realtime_all_known())))

        # ip known/active

        serialize.add('g2', Gauge(len(ipv4db.get_all_active_ipv4s()), 
                      len(ipv4db.get_all_known_ipv4s())))

        web.header('Content-Type', 'application/json')
        return serialize.dumps()


class Json_Engine_Statictics_ARP_Interface:

    def GET(self, argv):
        print '[d] engine flot, argv(%s)' % argv
        interface = argv

        # check if interface is in LISTENERS, if yes, return

        response = {}
        response['data'] = ipv4db.g_interface_statistics(interface, 430)
        response['label'] = interface
        web.header('Content-Type', 'application/json')
        return json.dumps(response)


class json_mac_arp_stats:

    def GET(self, argv):
        print '[d] mac_arp_statistics, argv(%s)' % argv
        (mac, time_back_in_secs) = argv.split(',')
        try:
            mac = verify_the_param_is_a_mac(mac)
            time_back_in_secs = int(time_back_in_secs)
            print '[d] mac %s, time_back_in_secs %s' % (mac, 
                    time_back_in_secs)

            response = {}
            response['data'] = ipv4db.q_mac_arp_activity(mac, 
                    time_back_in_secs)
            response['label'] = mac
            response['color'] = '#7CA6BD'
            web.header('Content-Type', 'application/json')
            return json.dumps(response)

        except TypeError:
            return 


class json_mac_details:

    def GET(self, argv):
        print '[i] json_mac_details(%s)' % argv
        try:
            mac = verify_the_param_is_a_mac(argv)

            result = []
            obj = {}
            if ipv4db.q_mac_realtime_active(mac):
                obj['active'] = 'Yes'
            else:
                obj['active'] = 'No'
            obj['session'] = ipv4db.q_mac_realtime_session_duration(mac)
            obj['known_since'] = str(unixtime2datetime(ipv4db.q_mac_historical_known_since(mac)))
            return json.dumps(obj)

        except TypeError:
            return



class json_mac_ai_score:

    def GET(self, argv):
        print '[i] json_mac_ai_score, argv(%s)' % argv
        try:
            mac = verify_the_param_is_a_mac(argv)

            result_real = []
            result_max = []
            result_legend = []

            result_real.append(mac_eval.ai_mac(mac))
            result_max.append(100)
            result_legend.append('mac')

            for ipv4 in ipv4db.q_mac_realtime_assigned_ips(mac):
                result_real.append(tcp_eval.ai_ipv4(ipv4))
                result_max.append(0)
                result_legend.append('scan')

            for ipv4 in ipv4db.q_mac_realtime_assigned_ips(mac):
                for fqdn in ipv4db.get_last_fqdn(ipv4):
                    result_real.append(hostname_eval.ai_fqdn(fqdn))
                    result_max.append(0)
                    result_legend.append('name')

            obj = {}
            obj['score_real'] = result_real
            obj['score_max'] = result_max
            obj['score_legend'] = result_legend
            return json.dumps(obj)

        except TypeError:
            return



class json_mac_ipv4_all:

    def GET(self, argv):
        print '[d] mac_ipv4_all, argv(%s)' % argv
        try:
            mac = verify_the_param_is_a_mac(argv)

            result = []
            for (unixtime, ipv4) in ipv4db.q_mac_historical_all_ipv4s(mac):
                result.append(('%s' % unixtime2datetime(unixtime), ipv4))
            obj = {}
            obj['aaData'] = result
            return json.dumps(obj)
        
        except TypeError:
            return


class json_mac_hostname_all:

    def GET(self, argv):
        print '[d] mac_fqdn_all, argv(%s)' % argv
        try:
            mac = verify_the_param_is_a_mac(argv)

            result = []
            for (unixtime, ipv4) in ipv4db.q_mac_historical_all_fqdns(mac):
                result.append(('%s' % unixtime2datetime(unixtime), ipv4))
            obj = {}
            obj['aaData'] = result
            return json.dumps(obj)

        except TypeError:
            return


class json_mac_scan_last:

    def GET(self, argv):
        print '[d] mac_scan_last, argv(%s)' % argv
        try:
            mac = verify_the_param_is_a_mac(argv)

            result = []

            # query port scan results for the respecitve ipv4

            for ipv4 in ipv4db.q_mac_realtime_assigned_ips(mac):
                if ipv4 != '0.0.0.0':
                    last_scan_ts = ipv4db.get_scan_last_unixtime(ipv4)
                    if last_scan_ts:
                        (ipv4_scan_results, port_descr) = ipv4db.get_last_tcp_port_states(ipv4)
                        for ipv4_scan_result in ipv4_scan_results:
                            result.append(('%s' % unixtime2datetime(last_scan_ts), 
                                     '%s' % ipv4, '%s' % ipv4_scan_result, 
                                     '%s' % ipv4_scan_results[ipv4_scan_result], 
                                     '%s' % port_descr[ipv4_scan_result]))
            obj = {}
            obj['aaData'] = result
            return json.dumps(obj)

        except TypeError:
            return



def ai_evaluate(mac, ipv4, hostname):
    ipv4scan_score = tcp_eval.ai_ipv4(ipv4)
    hostname_score = hostname_eval.ai_fqdn(hostname)
    mac_score = mac_eval.ai_mac(mac)
    total_score = ipv4scan_score + hostname_score + mac_score
    total_score = total_score / 3
    result = (mac, ipv4, hostname, hostname_score, ipv4scan_score, 
              mac_score, total_score)
    print result
    return result


class json_mac_list_registered_complete:

    def GET(self, argv):
        print '[d] json_mac_list_complete'

        result = []
        for mac in ipv4db.q_mac_realtime_all_known():
            result.append((mac, 0, 0, 0, 0, 0, 0))

        obj = {}
        obj['aaData'] = result
        return json.dumps(obj)


class json_mac_list_active_complete:

    def GET(self, argv):
        print '[d] engine activemacs'

        result = []
        for mac in ipv4db.q_mac_realtime_all_active():
            for ipv4 in ipv4db.q_mac_realtime_assigned_ips(mac):
                for hostname in ipv4db.get_last_fqdn(ipv4):
                    result.append(ai_evaluate(mac, ipv4, hostname))

        obj = {}
        obj['aaData'] = result
        return json.dumps(obj)


class json_mac_list_active_excludes:

    def GET(self, argv):
        print '[d] json_mac_list_excludes'

        result = []
        for mac in ipv4db.q_mac_realtime_all_active():
            for ipv4 in ipv4db.q_mac_realtime_assigned_ips(mac):
                if ipv4 != '0.0.0.0' and not RE_APIPA.match(ipv4):
                    for hostname in ipv4db.get_last_fqdn(ipv4):
                        result.append(ai_evaluate(mac, ipv4, hostname))

        obj = {}
        obj['aaData'] = result
        return json.dumps(obj)


class json_mac_netflow:

    def GET(self, argv):
        get_data = web.input()
        try:
            mac = verify_the_param_is_a_mac(get_data.mac)

        except AttributeError:
            print '[!] AttributeError for json_mac_tcp_communication_initiated_by_host function'
            return web.notfound('404. Not found')
        except TypeError:
            print '[!] TypeError for json_mac_tcp_communication_initiated_by_host function'
            return web.notfound('404. Not found')

        print '[d] json_mac_tcp_communication_initiated_by_host( %s )' % \
            mac

        if ipv4db.q_mac_realtime_active(mac):
            session_duration = ipv4db.q_mac_realtime_session_duration(mac)
            if session_duration > eq_env.NETFLOW_HISTORY_MAX:
                session_duration = eq_env.NETFLOW_HISTORY_MAX
            ipv4_list = ipv4db.q_mac_realtime_assigned_ips(mac)

            for ipv4 in ipv4_list:
                print 'ipv4: %s' % ipv4

            get_request = 'http://' + NETFLOW_SERVER + \
                '/arpmonitor3/host_tcp_communication/'
            get_request += '?'
            get_request += 'ipv4=%s' % ipv4
            get_request += ';'
            get_request += 'session_duration=%s' % session_duration

            try:
                get_response = urllib2.urlopen(get_request)
                if get_response.msg == 'OK':
                    result = get_response.read()
                else:
                    result = '{ "nodes": [ { "id":, "1", ' + \
                        '"label": "no ok status reurned" } ], "edges": [ {} ] }'
            except urllib2.URLError:
                result = '{ "nodes": [ { "id":, "1", ' + \
                    '"label": "url error received from the netflow server" } ], "edges": [ {} ] }'
        else:
            result = \
                '{ "nodes": [ { "id":, "1", "label": "mac seems not to be active" } ], "edges": [ {} ] }'

        #req = urllib2.Request(gh_url)
        #password_manager = urllib2.HTTPPasswordMgrWithDefaultRealm()
        #password_manager.add_password(None, gh_url, 'user', 'pass')

        #auth_manager = urllib2.HTTPBasicAuthHandler(password_manager)
        #opener = urllib2.build_opener(auth_manager)

        #urllib2.install_opener(opener)
        #handler = urllib2.urlopen(req)

        #print handler.getcode()
        #print handler.headers.getheader('content-type')

        return result


class mac_reset:
    ''' reset the mac so the alert will be sent again
        if the mac returns online 
    ''' 

    def GET(self, argv):
        print '[d] mac_reset'
        try:
            mac = verify_the_param_is_a_mac(argv)
            ipv4db.mac_reset(mac)
        except TypeError:
        
            pass

        return render.page_mac_profile_mac_reset()


if __name__ == '__main__':
    app = web.application(urls, globals())
    app.run()
else:
    application = web.application(urls, globals()).wsgifunc()

