# traceroute
Multi-source traceroute with geolocation information. Demo: [IP Address Lookup](https://dazzlepod.com/ip/) (under "Traceroute" tab)

## Features

This fork of traceroute.py expands on the existing functionality of the tool by adding the capability of 
running the script in daemon mode in order to track network stability over time and report events via a webhook capability. 

In addition, the report itself has been extended to not only show hop information, but also information about the network interfaces and configured
gateways of the host the script is run from. 

An init script/bash script has been provided to assist administrators in setting up this tool to run repeatedly and monitor an IP address sending alerts
to a provided web hook. 

Event reports are only fired based on 3 conditions:

1. A hop takes an unacceptable amount of time
2. A hop takes way more time than it did the previous time
3. The total number of hops to reach a host changes. 





![Using output from traceroute.py to plot hops on Google Map](https://raw.github.com/ayeowch/traceroute/master/screenshot.png)

## Prerequisites

1. python2.7
2. pip
3. virtualenv
4. traceroute (commandline version)
5. Might need to ensure you have gcc and python dev modules for your distribution

## Installation

1. Create a project root directory (proj_root herein) for the traceroute scripts to live. The init-script assumes /var/lib/python/traceroute. 
   The source can be cloned here.  This directory can be changed by editing init-script/traceroute.
2. Inside the proj_root directory , initialize a virtual environment to house python and the projects dependencies. Call the environment directory 'env'. 
3. Install dependencies listed in requirements.txt file. This can be done by activating the virtualenv in step 2 and running pip install -r requirements.txt
4. Copy 'traceroute.sh' from init-script into the project root dir (/var/lib/python/traceroute). Or create a symbolic link. At the end it should look like:
     bmartin@crappy-laptop:/var/lib/python/traceroute$ ls
     env  init-script  LICENSE  persistence.json  README.md  requirements.txt  screenshot.png  sources.json  traceroute.py  traceroute.sh

5. Copy 'traceroute' from init-script into the /etc/init.d folder. Ensure to make the traceroute script executable.
6. If Debian - Run the command: (tbd)

    update-rc-d traceroute defaults
    (might see some complaints)

7. If Centos, run this:
    chkconfig --level 35 traceroute on

8. For a quick test, run 
    /etc/init.d/traceroute start


## Usage


        Usage: traceroute.py --ip_address=IP_ADDRESS

        Options:
          -h, --help            show this help message and exit
          -i IP_ADDRESS, --ip_address=IP_ADDRESS
                                IP address of destination host (default: 8.8.8.8)
          -j JSON_FILE, --json_file=JSON_FILE
                                List of sources in JSON file (default: sources.json)
          -c COUNTRY, --country=COUNTRY
                                Traceroute will be initiated from this country; choose
                                'LO' for localhost to run traceroute locally, 'BY' for
                                Belarus, 'CH' for Switzerland, 'JP' for Japan, 'RU'
                                for Russia, 'UK' for United Kingdom or 'US' for United
                                States (default: US)
          -t TMP_DIR, --tmp_dir=TMP_DIR
                                Temporary directory to store downloaded traceroute
                                results (default: /tmp)
          -n, --no_geo          No geolocation data (default: False)
          -s TIMEOUT, --timeout=TIMEOUT
                                Timeout in seconds for all downloads (default: 120)
          -d, --debug           Show debug output (default: False)
          -w WEBHOOK, --webhook=WEBHOOK
                                Specify URL to POST report payload rather than stdout
          --max_latency=MAX_LATENCY
                                Maximum latency whereby the system will trigger the
                                webhook ( if requested ).
          --hop_time_diff=HOP_TIME_DIFF
                                If the time to reach a hop exceeds this value, trigger
                                the webhook ( if requested ).

Sample Output:

    {
        "ifaces": [
            {
                "lo": {
                    "mac": "00:00:00:00:00:00", 
                    "ip_address": "127.0.0.1"
                }
            }, 
            {
                "wlan0": {
                    "mac": "8c:70:5a:b4:4e:c0", 
                    "ip_address": "192.168.11.26"
                }
            }
        ], 
        "hops": {
            "1": [
                {
                    "rtt": "3.451 ms", 
                    "hostname": "192.168.11.1", 
                    "ip_address": "192.168.11.1"
                }
            ], 
            "2": [
                {
                    "rtt": "9.391 ms", 
                    "hostname": "10.124.4.1", 
                    "ip_address": "10.124.4.1"
                }
            ], 
            "3": [
                {
                    "latitude": 43.6425, 
                    "rtt": "23.226 ms", 
                    "hostname": "67.231.220.81", 
                    "ip_address": "67.231.220.81", 
                    "longitude": -79.3872
                }
            ], 
            "4": [
                {
                    "latitude": 43.6425, 
                    "rtt": "18.802 ms", 
                    "hostname": "so-4-0-0.gw02.ym.phub.net.cable.rogers.com", 
                    "ip_address": "66.185.82.125", 
                    "longitude": -79.3872
                }
            ], 
            "5": [
                {
                    "latitude": 43.6425, 
                    "rtt": "21.387 ms", 
                    "hostname": "2140.ae1.bdr01.tor2.man.teksavvy.com.packetflow.ca", 
                    "ip_address": "69.196.136.138", 
                    "longitude": -79.3872
                }, 
                {
                    "latitude": 43.6425, 
                    "rtt": "21.969 ms", 
                    "hostname": "69.196.136.169", 
                    "ip_address": "69.196.136.169", 
                    "longitude": -79.3872
                }, 
                {
                    "latitude": 43.6425, 
                    "rtt": "21.619 ms", 
                    "hostname": "69.196.136.81", 
                    "ip_address": "69.196.136.81", 
                    "longitude": -79.3872
                }
            ], 
            "6": [
                {
                    "latitude": 37.4192, 
                    "rtt": "22.286 ms", 
                    "hostname": "72.14.211.14", 
                    "ip_address": "72.14.211.14", 
                    "longitude": -122.0574
                }
            ], 
            "7": [
                {
                    "latitude": 37.4192, 
                    "rtt": "19.772 ms", 
                    "hostname": "209.85.255.232", 
                    "ip_address": "209.85.255.232", 
                    "longitude": -122.0574
                }
            ], 
            "8": [
                {
                    "latitude": 37.4192, 
                    "rtt": "19.994 ms", 
                    "hostname": "72.14.239.73", 
                    "ip_address": "72.14.239.73", 
                    "longitude": -122.0574
                }
            ], 
            "9": [
                {
                    "latitude": 37.4192, 
                    "rtt": "19.662 ms", 
                    "hostname": "yyz08s10-in-f31.1e100.net", 
                    "ip_address": "173.194.43.127", 
                    "longitude": -122.0574
                }
            ]
        }, 
        "probe_end": 1440124700797.208, 
        "pub_ip": "23.233.25.67", 
        "routes": [
            {
                "AF_INET": {
                    "interface": "wlan0", 
                    "default": true, 
                    "ip_address": "192.168.11.1"
                }
            }
        ], 
        "probe_start": 1440124697427.629
    }

       

