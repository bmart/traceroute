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

USER_AGENT = "traceroute/1.0 (+https://github.com/ayeowch/traceroute)"



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
        self.country = country

        if self.country == 'LO':
            self.local_mode = True
            self.pub_ip     = self._lookup_public_ip()
            self.ifaces     = self._get_network_interface_info()
        else:
            self.local_mode = False

        self.tmp_dir = tmp_dir
        self.no_geo = no_geo
        self.timeout = timeout
        self.debug = debug
        self.locations = {}
        self.hops = []

        self._initialize()

    def _initialize(self):
        """
        Instead of running the actual traceroute command, we will fetch
        standard traceroute results from several publicly available webpages
        that are listed at traceroute.org. For each hop, we will then attach
        geolocation information to it.
        """
        self.print_debug("ip_address={}".format(self.ip_address))

        filename = "{}.{}.txt".format(self.ip_address, self.country)
        filepath = os.path.join(self.tmp_dir, filename)

        if not os.path.exists(filepath):
            if self.country == "LO":
                status_code, traceroute = self.execute_cmd(self.source['url'])
            else:
                status_code, traceroute = self.get_traceroute_output()
            if status_code != 0 and status_code != 200:
                return {'error': status_code}
            open(filepath, "w").write(traceroute)
        traceroute = open(filepath, "r").read()

        # hop_num, hosts
        hops = self._get_hops(traceroute)

        # hop_num, hostname, ip_address, rtt
        self.hops = self._get_formatted_hops()

        if not self.no_geo:
            # hop_num, hostname, ip_address, rtt, latitude, longitude
            self.hops = self._get_geocoded_hops()

        self.hops = map(lambda h: {h.pop("hop_num") : h}, self.hops)

    def get_report(self):
        report_structure = {}

        report_structure['hops'] = self.hops
        if self.local_mode:
            report_structure['pub_ip'] = self.pub_ip
            report_structure['ifaces'] = self.ifaces
        
        return report_structure

    def _lookup_public_ip(self):

        #TODO Don't forget to put timeout from above here....
        response = requests.get('https://api.ipify.org?format=json')

        if response.status_code == 200:
            ip_data = response.json()
            if 'ip' not in ip_data.keys():
                return 'Unable to determine IP'
            else:
                return  ip_data['ip']
        else:
            return 'Unable to determine IP'

    def _get_network_interface_info(self):
        iface_list = []
        for i in netifaces.interfaces():
           addr = netifaces.ifaddresses(i)

           # only retrieve interfaces that are active
           if netifaces.AF_INET in addr.keys(): 
               iface_list.append( {i : { 
                    'ip_address' : addr[netifaces.AF_INET][0]['addr'],
                    'mac'        : addr[netifaces.AF_LINK][0]['addr']
               }})

        return iface_list





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
            content = "{}</pre>".format(content)
            traceroute = re.findall(pattern, content)[0].strip()
        return (status_code, traceroute)

    def _get_hops(self, traceroute):
        """
        Returns hops from traceroute output in an array of dicts each
        with hop number and the associated hosts data.
        """
        regex = r'^(?P<hop_num>\d+)(?P<hosts>.*?)$'
        lines = traceroute.split("\n")
        for line in lines:
            line = line.strip()
            hop = {}
            if not line:
                continue
            try:
                hop = re.match(regex, line).groupdict()
            except AttributeError:
                continue
            self.print_debug(hop)
            self.hops.append(hop)

    def _get_formatted_hops(self):
        """
        Hosts data from get_hops() is represented in a single string.
        We use this function to better represent the hosts data in a dict.
        """
        formatted_hops = []
        regex = r'(?P<h>[\w.-]+) \((?P<i>[\d.]+)\) (?P<r>\d{1,4}.\d{1,4} ms)'
        for hop in self.hops:
            hop_num = int(hop['hop_num'].strip())
            hosts = hop['hosts'].replace("  ", " ").strip()
            # Using re.findall(), we split the hosts, then for each host,
            # we store a tuple of hostname, IP address and the first RTT.
            hosts = re.findall(regex, hosts)
            for host in hosts:
                hop_context = {
                    'hop_num': hop_num,
                    'hostname': host[0],
                    'ip_address': host[1],
                    'rtt': host[2],
                }
                self.print_debug(hop_context)
                formatted_hops.append(hop_context)
        return formatted_hops


    def _get_geocoded_hops(self):
        """
        Returns hops from get_formatted_hops() with geolocation information
        for each hop.
        """
        geocoded_hops = []
        for hop in self.hops:
            ip_address = hop['ip_address']
            location = None
            if ip_address in self.locations:
                location = self.locations[ip_address]
            else:
                location = self.get_location(ip_address)
                self.locations[ip_address] = location
            if location:
                geocoded_hops.append({
                    'hop_num': hop['hop_num'],
                    'hostname': hop['hostname'],
                    'ip_address': hop['ip_address'],
                    'rtt': hop['rtt'],
                    'latitude': location['latitude'],
                    'longitude': location['longitude'],
                })
        return geocoded_hops

    def get_location(self, ip_address):
        """
        Returns geolocation information for the given IP address.
        """
        location = None
        url = "http://dazzlepod.com/ip/{}.json".format(ip_address)
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
            self.print_debug("cmd={}, returncode={}".format(cmd, returncode))
            if returncode != 0:
                self.print_debug("stderr={}".format(stderr))
            signal.alarm(0)
        except Exception as err:
            self.print_debug(str(err))
        return (returncode, stdout)

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
            self.print_debug("url={}".format(response.geturl()))
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
                self.print_debug("read_bytes={}, {}".format(read_bytes, data))
            signal.alarm(0)
        except Exception as err:
            self.print_debug(str(err))
        return content

    def signal_handler(self, signum):
        """
        Raises exception when signal is caught.
        """
        raise Exception("Caught signal {}".format(signum))

    def print_debug(self, msg):
        """
        Prints debug message to standard output.
        """
        if self.debug:
            print("[DEBUG {}] {}".format(datetime.datetime.now(), msg))


def main():
    cmdparser = optparse.OptionParser("%prog --ip_address=IP_ADDRESS")
    cmdparser.add_option(
        "-i", "--ip_address", type="string", default="8.8.8.8",
        help="IP address of destination host (default: 8.8.8.8)")
    cmdparser.add_option(
        "-j", "--json_file", type="string", default="sources.json",
        help="List of sources in JSON file (default: sources.json)")
    cmdparser.add_option(
        "-c", "--country", type="choice", default="US",
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
    options, _ = cmdparser.parse_args()
    json_file = open(options.json_file, "r").read()
    sources = json.loads(json_file.replace("_IP_ADDRESS_", options.ip_address))


    # Get Hope info using Traceroute Object
    traceroute = Traceroute(ip_address=options.ip_address,
                            source=sources[options.country],
                            country=options.country,
                            tmp_dir=options.tmp_dir,
                            no_geo=options.no_geo,
                            timeout=options.timeout,
                            debug=options.debug)
    """
        Pseudo-Code

        report = traceroute.get_report()

        print(json.dumps(report, indent=4)

    """

    
    report = traceroute.get_report()    


    print(json.dumps(report, indent=4))
    return 0


if __name__ == '__main__':
    sys.exit(main())
