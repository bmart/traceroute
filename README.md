# traceroute
Multi-source traceroute with geolocation information. Demo: [IP Address Lookup](https://dazzlepod.com/ip/) (under "Traceroute" tab)

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

Try the following from your Python interpreter:

    >>> from traceroute import Traceroute
    >>> traceroute = Traceroute("8.8.8.8")
    >>> hops = traceroute.hops
    >>> hops
    [{'hostname': 'core-87-router', 'longitude': -74.6597, 'rtt': '2.208 ms', 'hop_num': 1, 'latitude': 40.3756, 'ip_address': '128.112.128.2'}, {'hostname': 'border-87-router', 'longitude': -74.6597, 'rtt': '0.422 ms', 'hop_num': 2, 'latitude': 40.3756, 'ip_address': '128.112.12.142'}, {'hostname': 'te0-0-1-1.204.rcr12.phl03.atlas.cogentco.com', 'longitude': -97.0, 'rtt': '3.775 ms', 'hop_num': 3, 'latitude': 38.0, 'ip_address': '38.122.150.1'}, {'hostname': 'te0-0-1-3.rcr21.phl01.atlas.cogentco.com', 'longitude': -97.0, 'rtt': '3.689 ms', 'hop_num': 4, 'latitude': 38.0, 'ip_address': '154.54.27.117'}, {'hostname': 'te0-0-1-3.rcr22.phl01.atlas.cogentco.com', 'longitude': -97.0, 'rtt': '4.340 ms', 'hop_num': 4, 'latitude': 38.0, 'ip_address': '66.28.4.233'}, {'hostname': 'te0-7-0-10.mpd22.dca01.atlas.cogentco.com', 'longitude': -97.0, 'rtt': '8.082 ms', 'hop_num': 5, 'latitude': 38.0, 'ip_address': '154.54.42.101'}, {'hostname': 'te0-7-0-10.ccr21.dca01.atlas.cogentco.com', 'longitude': -97.0, 'rtt': '7.860 ms', 'hop_num': 5, 'latitude': 38.0, 'ip_address': '154.54.42.89'}, {'hostname': 'be2112.ccr41.iad02.atlas.cogentco.com', 'longitude': -97.0, 'rtt': '8.628 ms', 'hop_num': 6, 'latitude': 38.0, 'ip_address': '154.54.5.233'}, {'hostname': '38.88.214.50', 'longitude': -97.0, 'rtt': '8.197 ms', 'hop_num': 7, 'latitude': 38.0, 'ip_address': '38.88.214.50'}, {'hostname': '209.85.255.1', 'longitude': -122.0574, 'rtt': '9.230 ms', 'hop_num': 8, 'latitude': 37.4192, 'ip_address': '209.85.255.1'}, {'hostname': '209.85.251.101', 'longitude': -122.0574, 'rtt': '9.719 ms', 'hop_num': 8, 'latitude': 37.4192, 'ip_address': '209.85.251.101'}, {'hostname': '216.239.51.11', 'longitude': -122.0574, 'rtt': '9.811 ms', 'hop_num': 9, 'latitude': 37.4192, 'ip_address': '216.239.51.11'}, {'hostname': '72.14.238.115', 'longitude': -122.0574, 'rtt': '10.142 ms', 'hop_num': 9, 'latitude': 37.4192, 'ip_address': '72.14.238.115'}, {'hostname': '216.239.51.101', 'longitude': -122.0574, 'rtt': '9.568 ms', 'hop_num': 9, 'latitude': 37.4192, 'ip_address': '216.239.51.101'}, {'hostname': 'google-public-dns-a.google.com', 'longitude': -122.0838, 'rtt': '9.127 ms', 'hop_num': 10, 'latitude': 37.386, 'ip_address': '8.8.8.8'}]
    >>>


You can also run the script directly by passing in the --ip_address option:

    $ python traceroute.py --help
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

    $ python traceroute.py --ip_address=8.8.8.8
    [
        {
            "hostname": "core-87-router",
            "longitude": -74.6597,
            "rtt": "3.035 ms",
            "hop_num": 1,
            "latitude": 40.3756,
            "ip_address": "128.112.128.2"
        },
        {
            "hostname": "border-87-router",
            "longitude": -74.6597,
            "rtt": "3.440 ms",
            "hop_num": 2,
            "latitude": 40.3756,
            "ip_address": "128.112.12.142"
        },
        {
            "hostname": "te0-0-1-1.204.rcr12.phl03.atlas.cogentco.com",
            "longitude": -97.0,
            "rtt": "3.588 ms",
            "hop_num": 3,
            "latitude": 38.0,
            "ip_address": "38.122.150.1"
        },
        {
            "hostname": "te0-0-1-3.rcr22.phl01.atlas.cogentco.com",
            "longitude": -97.0,
            "rtt": "3.441 ms",
            "hop_num": 4,
            "latitude": 38.0,
            "ip_address": "66.28.4.233"
        },
        {
            "hostname": "te0-7-0-10.mpd22.dca01.atlas.cogentco.com",
            "longitude": -97.0,
            "rtt": "7.455 ms",
            "hop_num": 5,
            "latitude": 38.0,
            "ip_address": "154.54.42.101"
        },
        {
            "hostname": "te0-7-0-10.ccr21.dca01.atlas.cogentco.com",
            "longitude": -97.0,
            "rtt": "7.573 ms",
            "hop_num": 5,
            "latitude": 38.0,
            "ip_address": "154.54.42.89"
        },
        {
            "hostname": "te0-7-0-10.mpd22.dca01.atlas.cogentco.com",
            "longitude": -97.0,
            "rtt": "7.521 ms",
            "hop_num": 5,
            "latitude": 38.0,
            "ip_address": "154.54.42.101"
        },
        {
            "hostname": "be2112.ccr41.iad02.atlas.cogentco.com",
            "longitude": -97.0,
            "rtt": "8.611 ms",
            "hop_num": 6,
            "latitude": 38.0,
            "ip_address": "154.54.5.233"
        },
        {
            "hostname": "be2176.ccr41.iad02.atlas.cogentco.com",
            "longitude": -97.0,
            "rtt": "8.640 ms",
            "hop_num": 6,
            "latitude": 38.0,
            "ip_address": "154.54.41.53"
        },
        {
            "hostname": "38.88.214.50",
            "longitude": -97.0,
            "rtt": "8.655 ms",
            "hop_num": 7,
            "latitude": 38.0,
            "ip_address": "38.88.214.50"
        },
        {
            "hostname": "209.85.251.101",
            "longitude": -122.0574,
            "rtt": "9.783 ms",
            "hop_num": 8,
            "latitude": 37.4192,
            "ip_address": "209.85.251.101"
        },
        {
            "hostname": "209.85.246.227",
            "longitude": -122.0574,
            "rtt": "9.313 ms",
            "hop_num": 8,
            "latitude": 37.4192,
            "ip_address": "209.85.246.227"
        },
        {
            "hostname": "209.85.246.225",
            "longitude": -122.0574,
            "rtt": "8.308 ms",
            "hop_num": 8,
            "latitude": 37.4192,
            "ip_address": "209.85.246.225"
        },
        {
            "hostname": "216.239.51.101",
            "longitude": -122.0574,
            "rtt": "12.102 ms",
            "hop_num": 9,
            "latitude": 37.4192,
            "ip_address": "216.239.51.101"
        },
        {
            "hostname": "216-239-51-13.google.com",
            "longitude": -122.0574,
            "rtt": "8.993 ms",
            "hop_num": 9,
            "latitude": 37.4192,
            "ip_address": "216.239.51.13"
        },
        {
            "hostname": "216.239.51.9",
            "longitude": -122.0574,
            "rtt": "8.731 ms",
            "hop_num": 9,
            "latitude": 37.4192,
            "ip_address": "216.239.51.9"
        },
        {
            "hostname": "google-public-dns-a.google.com",
            "longitude": -122.0838,
            "rtt": "8.775 ms",
            "hop_num": 10,
            "latitude": 37.386,
            "ip_address": "8.8.8.8"
        }
    ]
