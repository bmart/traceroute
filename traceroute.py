#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Multi-source traceroute with geolocation information.
"""

import datetime
import json
import optparse
import os
import re
import signal
import sys
import urllib
import urllib2
from subprocess import Popen, PIPE
import requests
import netifaces
import time
from tinydb import TinyDB, where
import logging
USER_AGENT = "traceroute/1.0 (+https://github.com/bmart/traceroute)"

DB_FILE        = "./persistence.json"


# Logging setup
LOG_FILE       = "./traceroute.py.log" # TODO move to /var/log?
FORMAT         = '%(asctime)s %(name)-12s %(levelname)-8s %(message)s'
logging.basicConfig(format=FORMAT, filename=LOG_FILE, level=logging.DEBUG)
_logger = logging.getLogger('traceroute.py')





# global db reference
db            = TinyDB(DB_FILE)

# table references
webhook_cache       = db.table("webhook_offline")
hop_stats           = db.table("hop_stats")
hops_table          = db.table("hop_hosts")

# TODO set this via command-line 


class Thresholds(object):
    HOP_DIFFERENCE_THRESHOLD    = 20
    LATENCY_THRESHOLD           = 20



class Traceroute(object):
    """
    Multi-source traceroute instance.
    """
    def __init__(self, ip_address, source=None, country="US", tmp_dir="/tmp",
                 no_geo=False, timeout=120, debug=False):
        super(Traceroute, self).__init__()
        self.ip_address = ip_address
        self.source = source
        if self.source is None:
            json_file = open("sources.json", "r").read()
            sources = json.loads(json_file.replace("_IP_ADDRESS_", ip_address))
            self.source = sources[country]
        self.tmp_dir = tmp_dir

    

        self.no_geo = no_geo
        self.timeout = timeout
        self.debug = debug
        self.locations = {}
        self.hops = {}
        self.country = country


        # Localhost Specific operations happen here
        if self.country == 'LO':
            self.local_mode = True
            self.pub_ip     = self.__lookup_public_ip()
            self.ifaces     = self.__get_network_interface_info()
            self.routes     = self.__get_network_routes()
        else:
            self.local_mode = False


        # Store start/end times of the traceroute process
        self.probe_start = time.time() * 1000
        self.__run_traceroute() 
        self.probe_end   = time.time() * 1000


    def __run_traceroute(self):
        """
        Instead of running the actual traceroute command, we will fetch
        standard traceroute results from several publicly available webpages
        that are listed at traceroute.org. For each hop, we will then attach
        geolocation information to it.
        """
        self.print_debug("ip_address={0}".format(self.ip_address))

        # argh! removing cache for now
        #filename = "{}.{}.txt".format(self.ip_address, self.country)
        #filepath = os.path.join(self.tmp_dir, filename)

        if self.country == "LO":
            status_code, traceroute = self.execute_cmd(self.source['url'])
        else:
            status_code, traceroute = self.get_traceroute_output()
        if status_code != 0 and status_code != 200:
            return {'error': status_code}
        #open(filepath, "w").write(traceroute)
        #traceroute = open(filepath, "r").read()

        self.raw_string = traceroute 
        self.__get_hops(traceroute)



    def get_hops(self):
        """Return array of hop elements"""
        return self.hops

    def get_traceroute_output(self):
        """
        Fetches traceroute output from a webpage.
        """
        url = self.source['url']
        if 'post_data' in self.source:
            context = self.source['post_data']
        else:
            context = None
        status_code, content = self.urlopen(url, context=context)
        content = content.strip()
        regex = r'<pre.*?>(?P<traceroute>.*?)</pre>'
        pattern = re.compile(regex, re.DOTALL | re.IGNORECASE)
        try:
            traceroute = re.findall(pattern, content)[0].strip()
        except IndexError:
            # Manually append closing </pre> for partially downloaded page
            content = "{0}</pre>".format(content)
            traceroute = re.findall(pattern, content)[0].strip()
        return (status_code, traceroute)

    

    def __get_hops(self, traceroute):
        """
        Returns hops from traceroute output in an array of dicts each
        with hop number and the associated hosts data.
                hop_context = {
                    'hop_num': hop_num,
                    'hostname': host[0],
                    'ip_address': host[1],
                    'rtt': host[2],
                }
        """
        # This breaks up the line into hop num => host data
        #hop_pattern = '^(?P<hop_num>\w+)\s+(?P<hosts>.*)'
        hop_pattern = '^(?P<hop_num>[0-9]+)\s+(?P<hosts>.*)'
        # This matches hosts which are ip or dns mapped 
        host_pattern = '([\d\w.-]+\s+\(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\)\s+\d+\.\d+ ms)'
        # This is essentially the same as the previous pattern but breaks into usable chunks
        hop_element_pattern = '([\d\w.-]+)\s+\((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)\s+(\d+\.\d+ ms)'
        hp  = re.compile(hop_element_pattern)

        for entry in traceroute.split('\n'):
            entry = entry.strip()
            result = re.match(hop_pattern,entry)

            if result is None: # should only fail on first line
                continue
            hop         = result.groupdict()
            hop_num     = int(hop['hop_num'])
           
            hop_hosts   = re.findall(host_pattern, hop['hosts'])

            self.hops[hop_num] = []
            
            for host in hop_hosts:
                m = hp.search(host)
                (hostname, ip, ping_time) = m.groups()
                

                if self.no_geo:
                    self.hops[hop_num].append(
                        { 
                            'hostname'   : hostname,
                            'ip_address' : ip,
                            'rtt'        : ping_time
                        }
                    )
                else:
                    location = self.__get_geocoded_data(ip)
                    if location:
                        self.hops[hop_num].append(
                            { 
                                'hostname'   : hostname,
                                'ip_address' : ip,
                                'rtt'        : ping_time,
                                'latitude'   : location['latitude'],
                                'longitude'  : location['longitude']
                            }
                        )
                    else:
                        self.hops[hop_num].append(
                            { 
                                'hostname'   : hostname,
                                'ip_address' : ip,
                                'rtt'        : ping_time
                            }
                        )
                        



    def __get_geocoded_data(self, ip_address):
        """
            Returns a location hash with long/lat for a particular IP address
        """
        location = None
        if ip_address in self.locations:
            location = self.locations[ip_address]
        else:
            location = self.get_location(ip_address)
            self.locations[ip_address] = location
        
        return location


    def get_location(self, ip_address):
        """
        Returns geolocation information for the given IP address.
        """
        location = None
        url = "http://dazzlepod.com/ip/{0}.json".format(ip_address)
        status_code, json_data = self.urlopen(url)
        if status_code == 200 and json_data:
            tmp_location = json.loads(json_data)
            if 'latitude' in tmp_location and 'longitude' in tmp_location:
                location = tmp_location
        return location





    def execute_cmd(self, cmd):
        """
        Executes given command using subprocess.Popen().
        """
        stdout = ""
        returncode = -1
        process = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE)
        try:
            signal.signal(signal.SIGALRM, self.signal_handler)
            signal.alarm(self.timeout)
            stdout, stderr = process.communicate()
            returncode = process.returncode
            self.print_debug("cmd={0}, returncode={1}".format(cmd, returncode))
            if returncode != 0:
                self.print_debug("stderr={0}".format(stderr))
            signal.alarm(0)
        except Exception as err:
            self.print_debug(str(err))
        return (returncode, stdout)

    def __lookup_public_ip(self):
        """
        Retrieve public IP of this instance by calling ipify webservice
        """

        response = requests.get('https://api.ipify.org?format=json', timeout=self.timeout)

        if response.status_code == 200:
            ip_data = response.json()
            if 'ip' not in ip_data.keys():
                return 'Unable to determine IP'
            else:
                return  ip_data['ip']
        else:
            return 'Unable to determine IP'

    def __get_network_interface_info(self):
        """
        Private method. 
        Gather list of active interfaces  - localhost mode only. 
        """
        iface_list = []
        for i in netifaces.interfaces():
           addr = netifaces.ifaddresses(i)


           # clumsy way to filter which interfaces get added to list. If these elements raise KeyErrors, we skip
           try:
               iface_list.append( {i : { 
                    'ip_address' : addr[netifaces.AF_INET][0]['addr'],
                    'mac'        : addr[netifaces.AF_LINK][0]['addr']
               }})
           except KeyError,e:
	       pass
               self.print_debug("Key not found - _get_network_interface_info - {0}".format(addr))

        return iface_list


    def __get_network_routes(self):
        """
        Gather routes from netifaces module
        """
        routes = []

        gws = netifaces.gateways()
        for k in gws.keys():
            if k == 'default':
                continue

	    for r in gws[k]:
                (ip,interface,is_gateway) = r

                gw_name = "{0}".format(netifaces.address_families[k])

                routes.append({
                       gw_name : {
                            'ip_address' : ip,
                            'interface'  : interface,
			    'default'    : is_gateway
                       }
                
                    }
                )

        return routes

    def urlopen(self, url, context=None):
        """
        Fetches webpage.
        """
        status_code = 200
        request = urllib2.Request(url=url)
        request.add_header('User-Agent', USER_AGENT)
        if context:
            data = urllib.urlencode(context)
            request.add_data(data)
        content = ""
        try:
            response = urllib2.urlopen(request)
            self.print_debug("url={0}".format(response.geturl()))
            content = self.chunked_read(response)
        except urllib2.HTTPError as err:
            status_code = err.code
        except urllib2.URLError:
            pass
        return (status_code, content)

    def chunked_read(self, response):
        """
        Fetches response in chunks. A signal handler is attached to abort
        reading after set timeout.
        """
        content = ""
        max_bytes = 1 * 1024 * 1024  # Max. page size = 1MB
        read_bytes = 0
        bytes_per_read = 64  # Chunk size = 64 bytes
        try:
            signal.signal(signal.SIGALRM, self.signal_handler)
            signal.alarm(self.timeout)
            while read_bytes <= max_bytes:
                data = response.read(bytes_per_read)
                if not data:
                    break
                content += data
                read_bytes += bytes_per_read
                self.print_debug("read_bytes={0}, {1}".format(read_bytes, data))
            signal.alarm(0)
        except Exception as err:
            self.print_debug(str(err))
        return content

    def signal_handler(self, signum):
        """
        Raises exception when signal is caught.
        """
        raise Exception("Caught signal {0}".format(signum))

    def print_debug(self, msg):
        """
        Prints debug message to standard output.
        """
        if self.debug:
            print("[DEBUG {0}] {1}".format(datetime.datetime.now(), msg))

    def get_report(self):
        report = {}

        report['hops']        = self.hops
        report['probe_start'] = self.probe_start
        report['probe_end']   = self.probe_end
        if self.local_mode:
            report['pub_ip'] = self.pub_ip
            report['ifaces'] = self.ifaces
            report['routes'] = self.routes 
        if self.debug:
            report['raw']       = self.raw_string
        
        return report


############################################################################################
#
#  Utility Functions For Reporting and Command-line Usage.
#
############################################################################################

def post_result(webhook_url, report, timeout=120):
    """
    POST  traceroute report to specified website. Exceptions need to be caught in the caller
    """
    return requests.post(webhook_url, data=json.dumps(report), timeout=timeout)

def is_webhook_available(webhook_url):
    """ 
    Function to check if a webhook host is responding.
    Not 100% sure this will work...
    """
    try:
        data = urllib.urlopen(webhook_url)
        return True
    except Exception,e:
        _logger.warn("Webook offline or unavailable, application will cache report: {0}".format(e))
        return False


def cacheFull(webhook_cache):
    """check if cache contains webhook records"""
    
    return webhook_cache.__len__() > 0

def purgeAndDeleteCache(webhook_cache, url):
    """cycle through db, post results and delete db.
       TODO - only delete successful posts. Figure out later. 
    """
    
    totalRecords = webhook_cache.__len__() # not used currently. 
    _logger.info("Now posting offline cache")
    for data in webhook_cache.all():
        try:
            result = post_result(url, data) 
        except Exception,e:
            _logger.warn("Unable to post record from cache. Message was: {0}".format(e))
    # clear cache 
    webhook_cache.purge()
    _logger.info("Webhook cache cleared")

def exceeds_hop_latency(ping_time):
    """return true if hop time exceeds specified latency threshold"""
    # remote ' ms' from ping time
    ping_as_float = get_ms_as_float(ping_time)
    return ping_as_float >= Thresholds.LATENCY_THRESHOLD

def get_ms_as_float(ping_time):
    return float(ping_time.replace(" ms",""))

def analyze_hop_history(hop_list):
    """
    Analyze traceroute hop data for outstanding events. 
    Store/compare hop data in tinydb for next iteration
    Return an array of events or an empty array if none found

    Likely move traceroute class outside of this driver script. 
    """

    event_list = {}


    # Get previous hop results, or store some if non available
    if not hop_stats.all():
        _logger.info("First run, caching hops the first time")
        cache_traceroute_hops(hop_list)
        return event_list 
        # implication here is to wait until next call before anything really happens
        # So max threshold isn't reported immediately if it occurs here


    # Hop Latency Exceptions
    # Check for Hops in current list that exceed threshold
    
    # constants used in this function only
    MAX_THRESH_KEY      = "max_threshold_exceeded"
    HOP_COUNT_KEY       = "hop_count_change"
    HOP_TIME_DIFF_KEY   = "hop_time_diff"

    for hop in hop_list:
        for host in hop_list[hop]:
            if exceeds_hop_latency(host['rtt']):
                _logger.info("Hop Latency Exceeded for {0}".format(host))
                if MAX_THRESH_KEY not in event_list.keys():
                    event_list[MAX_THRESH_KEY] = []
                event_list[MAX_THRESH_KEY].append(hop_list[hop])

    # Total Hop Count Discrepancies
    
    res             = hop_stats.search(where('key') == 'num_hops')
    if len(res) > 0: # not sure why this would be zero, but putting here. 
        prev_hop_count  = res[0]['value']
        if prev_hop_count != len(hop_list):
            _logger.info("Hop count has changed from {0} to {1}".format(prev_hop_count, len(hop_list)))
            event_list[HOP_COUNT_KEY] = "Hop count changed from {0} to {1}".format(prev_hop_count, len(hop_list))


    # Hop differential comparison

    for hop in hop_list:
        for host in hop_list[hop]:
            curIp   = host['ip_address']
            curRtt = get_ms_as_float(host['rtt'])

            prevRes = hops_table.search(where('ip') == curIp)

            if len(prevRes) > 0:
                prevRes = prevRes[0] # just want element #1 - should only be 1 ?
                prevRtt = get_ms_as_float(prevRes['rtt'])
                rttDiff = curRtt - prevRtt
                if abs(rttDiff) > Thresholds.HOP_DIFFERENCE_THRESHOLD:
                    _logger.info("Hop time difference threshold exceeded. Current RTT {0}, Prev RTT {1} for host {2}".format(curRtt, prevRtt, host))
                    if HOP_TIME_DIFF_KEY not in event_list.keys():
                        event_list[HOP_TIME_DIFF_KEY] = []
                    event_list[HOP_TIME_DIFF_KEY].append({
                        'oldHop' : prevRes,
                        'newHop' : host
                    })
    




    return event_list

def cache_traceroute_hops(hop_list):
    """Store hop array in storage for next iteration comparisons"""

    hop_stats.purge()
    hop_stats.insert( { 'key' : 'num_hops', 'value' : len(hop_list) })
    hops_table.purge()

    for hop in hop_list:
        for host in hop_list[hop]:
        #clear table just in case
            obj = {
                    'ip' : host['ip_address'], 'rtt' : host['rtt'], 'hostname' : host['hostname']
            }
            hops_table.insert(obj)


def main():
    cmdparser = optparse.OptionParser("%prog --ip_address=IP_ADDRESS")
    cmdparser.add_option(
        "-i", "--ip_address", type="string", default="8.8.8.8",
        help="IP address of destination host (default: 8.8.8.8)")
    cmdparser.add_option(
        "-j", "--json_file", type="string", default="sources.json",
        help="List of sources in JSON file (default: sources.json)")
    cmdparser.add_option(
        "-c", "--country", type="choice", default="LO",
        choices=["LO", "BY", "CH", "JP", "RU", "UK", "US"],
        help=("Traceroute will be initiated from this country; choose 'LO' "
              "for localhost to run traceroute locally, 'BY' for Belarus, "
              "'CH' for Switzerland, 'JP' for Japan, 'RU' for Russia, 'UK' "
              "for United Kingdom or 'US' for United States (default: US)"))
    cmdparser.add_option(
        "-t", "--tmp_dir", type="string", default="/tmp",
        help=("Temporary directory to store downloaded traceroute results "
              "(default: /tmp)"))
    cmdparser.add_option(
        "-n", "--no_geo", action="store_true", default=False,
        help="No geolocation data (default: False)")
    cmdparser.add_option(
        "-s", "--timeout", type="int", default=120,
        help="Timeout in seconds for all downloads (default: 120)")
    cmdparser.add_option(
        "-d", "--debug", action="store_true", default=False,
        help="Show debug output (default: False)")

    cmdparser.add_option(
        "-w", "--webhook", type="string", default="",
        help="Specify URL to POST report payload rather than stdout")
    
    cmdparser.add_option(
        "--max_latency", type="float", default="20",
        help="Maximum latency whereby the system will trigger the webhook ( if requested ). ")

    cmdparser.add_option(
        "--hop_time_diff", type="float", default="20",
        help="If the time to reach a hop exceeds this value, trigger the webhook ( if requested ). ")
    

    options, _  = cmdparser.parse_args()
    json_file   = open(options.json_file, "r").read()
    sources     = json.loads(json_file.replace("_IP_ADDRESS_", options.ip_address))


    Thresholds.LATENCY_THRESHOLD        = options.max_latency
    Thresholds.HOP_DIFFERENCE_THRESHOLD = options.hop_time_diff

    # Get Hope info using Traceroute Object
    traceroute  = Traceroute(ip_address=options.ip_address,
                            source=sources[options.country],
                            country=options.country,
                            tmp_dir=options.tmp_dir,
                            no_geo=options.no_geo,
                            timeout=options.timeout,
                            debug=options.debug)

    # pull complete report -> Hop data plus meta info about the network
    report   = traceroute.get_report()


    if options.webhook != "":
       
        # If webhook is present, assume running in daemon/monitoring mode - analyze hops
        # TODO should we introduce a parameter to designate the daemon/monitor mode
        webhook_online = is_webhook_available(options.webhook)

        if cacheFull(webhook_cache) and webhook_online:
              purgeAndDeleteCache(webhook_cache, options.webhook)
        
        event_list = analyze_hop_history(traceroute.get_hops())

        # store current list for next time
        cache_traceroute_hops(traceroute.get_hops())


        if len(event_list) != 0:
            _logger.info("Events detected, will try to send to remote host if online, otherwise caching in persistent storage")
            # append section to report stating the issues or events leading to this alert
            report['event_source'] = event_list

            # check if remote host is available
            if webhook_online:
                
                try:
                    result = post_result(options.webhook, report, options.timeout)
                    _logger.info("Webhook POST Result: {}".format(result))
                    # TODO need to check that this value returns value HTTP code and cache result if invalid (404,501 etc)
                except Exception,e:
                    _logger.warn("Provided webhook {0} is invalid. Message was: {1}".format(options.webhook, e))
            else:
                _logger.info("Webhook unavailable, caching")
                #cache results until data is restored
                webhook_cache.insert(report)
    else:
        print(json.dumps(report, indent=4))
    return 0


if __name__ == '__main__':
    sys.exit(main())
