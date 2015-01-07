#!/usr/bin/env python
# -*- coding: utf-8 -*-
import time
import json
import broken
import pluginmanager
from collections import OrderedDict
from SimpleXMLRPCServer import list_public_methods
from threading import Timer
import capabilities
# This whole capabilities stuff is a bad idea. And quite poorly executed. But I'm really tired right now and I want to have reaver stuff working...
import tempfile
import logging
import inspect
import netifaces
import os
import re
import csv
from aircrack import AircrackSession
debug = logging.getLogger(__name__).debug
logging.basicConfig(level=logging.DEBUG)

# Disabled for now
# pluginmanager.load_plugins("plugins.list")

def callback(future):
    if future.exception() is not None:
        debug("Got exception: %s" % future.exception())
    else:
        debug("Process returned %d" % future.result())

class AiroscriptSessionManager(object):
    """
    """
    def __init__(self, wifi_iface):
        self.session_list = {}
        self.wifi_iface = wifi_iface

    def create_session(self, name=False, sleep_time=2, scan_time=2):
        """
            Create a AiroscriptSession object and assigns it to session_list
            If no name provided it will take current time
            (used to create monitor wireless interface)
        """
        if not name:
            name = str(time.time()).replace('.', '')

        if not name in self.session_list:
            self.session_list[name] = AiroscriptSession({
                'name': name,
                'wifi': self.wifi_iface,
                'sleep_time': sleep_time,
                'scan_time': scan_time
            })
        else:
            raise Exception("Session name already taken")

        return self.session_list[name]

    def get_session(self, session_name):
        return self.session_list[session_name]

    def _listMethods(self):
        return list_public_methods(self)

    def _methodHelp(self, method):
        f = getattr(self, method)
        return inspect.getdoc(f)


class AiroscriptError(Exception):
    pass

class Airoscript(object):

    pids = {}

    def rebump(self, pid):
        """
            Launches sigint to a process.
            In airodump-ng this means updating the csv contents
        """
        return os.kill(pid, 2)

    def on_scan_bumped(self, pid):
        self.rebump(pid)
        time.sleep(1)
        # Periodically bump it.
        Timer(int(self.config['scan_time']), self.on_scan_bumped, (pid))
        return pluginmanager.trigger_event(
            "on_after_scan",
            target = self.target,
            session = self,
        )

    def end_scan(self):
        return os.kill(self.pids['airodump-ng'], 9)

    def scan(self, options=OrderedDict()):
        pluginmanager.trigger_event(
            "on_before_scan",
            target = self.target,
            session = self,
        )
        final_options = OrderedDict([
                ('dump_prefix', self.target_dir + "/" + self.config["name"]),
                ('wireless', self.mon_iface)
        ])
        final_options.update(options.items())

        result = self.aircrack.airodump(final_options, lambda x: True)

        # We wait default scan time and ask for airodump-ng to re-bump.
        # With this we can have an airodump-ng continuously scanning on background until we want to get to a fixed channel
        # TODO Maybe magic with fixed / hoping channels and different cards?
        pid = result.result().result.pid
        Timer(int(self.config['scan_time']), self.on_scan_bumped, (pid))
        self.pids['airodump-ng'] = pid

        clean_self = clean_to_xmlrpc(self, ['extra_capabilities'])
        clean_self['_target'] = clean_to_xmlrpc(clean_self['_target'], ['parent'])
        return clean_self

class AiroscriptSession(Airoscript):
    """
        Basic airoscript-ng object.
        This is the basic airoscript-ng object.
        An Airoscript object is composed of multiple sessions.
        TODO: Airoscript object might need to be swapped with this.
        Also, this one is the one that handles network interfaces.

    """
    def __init__(self, config={}):
        self.config = config
        self._target = Target()
        self._mon_iface = None
        self.target_dir = tempfile.mkdtemp()
        if not 'parameter_file' in self.config:
            self.config['parameter_file'] = "aircrack_base_parameters.json"
        self.parameters = json.load(open(self.config['parameter_file']))
        self.aircrack = AircrackSession(self.parameters)
        self.extra_capabilities = dict([(extra, getattr(getattr(capabilities, extra), 'main')(self)) for extra in capabilities.__all__ ])
        self.reaver_targets = []

    def list_wifi(self):
        # If the driver is not using the new stack, screw them.
        return [ iface for iface in netifaces.interfaces() if "wlan" in iface ]

    def setup_wifi(self, iface):
        self.config['wifi'] = iface
        os.environ['MON_PREFIX'] = self.config["name"]
        self.should_be_mon_iface = self.config["name"] + "0"
        self.mac_addr = netifaces.ifaddresses(self.config['wifi'])[netifaces.AF_LINK][0]['addr']

        if not self.should_be_mon_iface in netifaces.interfaces():
            self.aircrack.airmon(OrderedDict([('command',
                "start"), ('wireless', self.config["wifi"])]), self.set_mon_iface)
        else:
            self._mon_iface = self.should_be_mon_iface
        return self._mon_iface

    def get_mac_addr(self):
        return self.mac_addr

    @property
    def mon_iface(self):
        return self._mon_iface

    @mon_iface.setter
    def mon_iface(self, mon_iface):
        self._mon_iface = mon_iface

    def set_mon_iface(self, result):
        mon_result = result.communicate()
        for line in mon_result[0].splitlines():
            monitor_test = re.match('(.*)\((.*)monitor mode enabled on (.*)\)(.*)', line)
            if monitor_test:
                self._mon_iface = monitor_test.group(3)
                if not self.mon_iface == self.should_be_mon_iface:
                    debug("Monitor interface is called {} and should be called {}".format(
                        self.mon_iface, self.should_be_mon_iface))
        return True

    def del_mon_iface(self):
        return self.aircrack.launch("iw", [self.mon_iface, "del"])

    @property
    def target(self):
        return self.get_target

    def get_target(self):
        return clean_to_xmlrpc(self._target, ['properties', 'parent'])

    @target.setter
    def target(self, target):
        return self.set_target(target)

    def set_target(self, target):
        """
            This way we only have to do something like
            self.target = current_targets[10] and it'll automatically
            make an object from it.
        """
        if not isinstance(target, Target):
            if isinstance(target, list):
                target = dict(target)
            self._target = Target(self).from_dict(target)
        else:
            self._target = target

    @property
    def current_targets(self):
        return self.get_current_targets()

    def get_current_targets(self):
        aps = []
        clients = []

        scan_file = "{}/{}-01.csv".format(self.target_dir, self.config["name"])
        with open(scan_file) as f:
            dictcsv = [a for a in csv.DictReader(f, skipinitialspace=True)]

        if "reaver" in self.extra_capabilities:
            self.reaver_targets = self.extra_capabilities['reaver'].scan(scan_file)

        for element in dictcsv:
            element = element[None]
            if len(element) < 8:
                clients.append(element)
            else:
                aps.append(element)
        if len(aps) == 0:
            return False
        ap_headers = aps.pop(0)
        client_headers = [a.lstrip(" ") for a in clients.pop(0)]

        return {'clients': [zip(client_headers, client) for client in clients], 'aps': [Target(self).from_dict(dict(zip(ap_headers, ap))) for ap in aps]}

def clean_to_xmlrpc(element, to_clean):
    res = element.__dict__.copy()
    for el in to_clean:
        res.pop(el)
    return res

class Target(object):
    def __init__(self, parent=False):
        self.parent = parent
        self.properties = [
            'bssid',
            'essid',
            'power',
            'encryption',
            'associated',
        ]

        for element in self.properties:
            setattr(self.__class__, element, '')

    def from_dict(self, dict_):
        self.bssid = dict_['BSSID'].strip()
        self.essid = dict_['ESSID'].strip()
        self.power = dict_['Power'].strip()
        self.encryption = dict_['Privacy'].strip(),
        self.hackability = self.get_hackability()
        # A few todos:
        # Put here the rest of the data.
        # Order targets.
        # Create targets
        return clean_to_xmlrpc(self, ['properties', 'parent'])

    def get_hackability(self):
        points = 0
        techs = []
        for essid in broken.ESSIDS:
            if essid in self.essid:
                points += 50
        points += - (int(self.power) * 10)

        if self.encryption[0] in broken.PRIVACY:
            points += broken.PRIVACY[self.encryption[0]][0]
            techs += broken.PRIVACY[self.encryption[0]][1]

        if "reaver" in self.parent.extra_capabilities:
            if self.bssid in [ a['bssid'] for a in self.parent.reaver_targets]:
                points += 800
                techs.insert(1, "reaver")

        return {
            'name'  : broken.get_hackability_name(points/10),
            'value' : int(points/20),
            'techs' : techs
        }

    def __repr__(self):
        return clean_to_xmlrpc(self, ['parent'])

    @property
    def is_client(self):
        return getattr(self, "associated")

def main():
    logging.basicConfig(
        level=logging.debug,
        format=("%(relativeCreated)04d %(process)05d %(threadName)-10s "
                "%(levelname)-5s %(msg)s"))
