#!/usr/bin/env python
# -*- coding: utf-8 -*-
import time
import json
import broken
import pluginmanager
from collections import OrderedDict
from SimpleXMLRPCServer import list_public_methods
from threading import Timer
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

class Airoscript(object):
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

class AiroscriptSession(object):
    """
        config object:
            - name
            - wifi
    """
    def __init__(self, config={}):
        self.config = config
        self._target = Target()
        if not 'parameter_file' in self.config:
            self.config['parameter_file'] = "aircrack_base_parameters.json"
        self.parameters = json.load(open(self.config['parameter_file']))
        self.target_dir = tempfile.mkdtemp()
        self.aircrack = AircrackSession(self.parameters)
        os.environ['MON_PREFIX'] = self.config["name"] # FIXME This may cause concurrency problems if we put equal names. Appending time to the name of the session maybe?
        self.should_be_mon_iface = self.config["name"] + "0"
        self._mon_iface = None

        if not self.should_be_mon_iface in netifaces.interfaces():
            self.monitor_result = False # Still processing here. TODO Find a nicer way to do this. BUT NON BLOCKING. This has to be xmlrpc and FAST.
            self.aircrack.airmon(OrderedDict([('command',
                "start"), ('wireless', self.config["wifi"])]), self.set_mon_iface)
        else:
            self._mon_iface = self.should_be_mon_iface

    @property
    def mon_iface(self):
        return self._mon_iface

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
        _ = self._target.__dict__.copy()
        _.pop('properties')
        _.pop('parent')
        return _

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
        with open("{}/{}-01.csv".format(self.target_dir, self.config["name"])) as f:
            dictcsv = [a for a in csv.DictReader(f)]
        for element in dictcsv:
            if len(element[None]) < 8:
                clients.append(element[None])
            else:
                aps.append(element[None])

        ap_headers = aps.pop(0)
        client_headers = [a.lstrip(" ") for a in clients.pop(0)]

        return {'clients': [zip(client_headers, client) for client in clients], 'aps': [zip(ap_headers, ap) for ap in aps]}

    def rebump(self, pid):
        """
            Launches sigint to a process.
            In airodump-ng this means updating the csv contents
        """
        return os.kill(pid, 2)

    def on_scan(self, pid):
        self.rebump(pid)
        time.sleep(1)
        debug("Ok, now you can read current_targets")
        return pluginmanager.trigger_event(
            "on_after_scan",
            target = self.target,
            session = self,
        )

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
        Timer(int(self.config['scan_time']), self.on_scan, (result.result().result.pid))
        # I'm not sure this way of ensuring method chaining is really OK. Probably going to change it soon.
        # But the way it was returning the timer is bad for xmlrpc too, so this should probably just return True.
        # TODO: That ^.
        clean_return = self.__dict__.copy()
        clean_return.pop('extra_capabilities')
        t = clean_return['_target'].__dict__
        t.pop('parent')
        clean_return['_target'] = t
        return clean_return

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
        self.essid = dict_[' ESSID'].strip()
        self.power = dict_[' Power'].strip()
        self.encryption = dict_[' Privacy'].strip(),
        self.hackability = self.get_hackability()
        return self

    def get_hackability(self):
        points = 0
        for essid in broken.ESSIDS:
            if essid in self.essid:
                points += 50
        points += - int(self.power)

        if self.encryption in broken.PRIVACY:
            points += broken.PRIVACY[self.encryption]

        return {
            'name'  : broken.get_hackability_name(points/10),
            'value' : int(points/10)
        }

    def __repr__(self):
        return "Target object with data: {}".format(self.__dict__)

    @property
    def is_client(self):
        return getattr(self, "associated")

def main():
    logging.basicConfig(
        level=logging.debug,
        format=("%(relativeCreated)04d %(process)05d %(threadName)-10s "
                "%(levelname)-5s %(msg)s"))
