#!/usr/bin/env python
# -*- coding: utf-8 -*-
from datetime import time
import pluginmanager
from collections import OrderedDict
from threading import Timer
import tempfile
import logging
import subprocess
import netifaces
import os
import re
import json
import csv
from concurrent.futures import ThreadPoolExecutor as Pool
info = logging.getLogger(__name__).info
logging.basicConfig(level=logging.DEBUG)

def callback(future):
    if future.exception() is not None:
        info("Got exception: %s" % future.exception())
    else:
        info("Process returned %d" % future.result())

# TODO: Move this to a proper place
pluginmanager.load_plugins("plugins.list")

class Airoscript(object):
    def __init__(self, wifi_iface):
        # Base state, almost nothing should be done here.
        self.session_list = {}
        self.wifi_iface = wifi_iface

    def create_session(self, name):
        if not name in self.session_list:
            self.session_list[name] = Session({'name': name, 'wifi': self.wifi_iface})
        else:
            return False

        return self.session_list[name]


class Aircrack(object):
    """
        Each session should have one or many aircrack-ng objects.
        An aircrack-ng object should be able to execute ONE of EACH
        aircrack-ng suite processes.
        On callback,
    """
    def __init__(self, binary_path="/usr/sbin", preferences_file="aircrack_base_parameters.json"):
        """
            Dinamically creates a function for each aircrack-ng binary.
        """
        self.binary_path = binary_path
        _cmds = ['airodump', 'aircrack', 'airmon']
        self.cmds = dict(list(zip(_cmds, map(lambda x: x + "-ng", _cmds))))
        self.executing = {}

        with open(preferences_file, 'r') as _preferences_file:
            self.attributes = json.load(_preferences_file)

    def callback(self, command, callback, result):
        """
            Remove the finished process from self.executing.
        """
        self.executing.pop(command)
        return callback(result)

    def parse_parameters(self, _parameters={}, command="airodump-ng"):
        parameters = []
        if command in self.attributes:
            for name, param in self.attributes[command].iteritems():
                if param[1] and not name in _parameters:
                    if param[0]:
                        parameters.append(param[0])
                    if param[1] != True:
                        parameters.append(param[1])

            for name, param in _parameters.iteritems():
                if name in self.attributes[command]:
                    schema = self.attributes[command][name]
                    if not schema[1] and schema[0]:
                        parameters.append(schema[0])
                    parameters.append(param)
        return parameters

    def execute(self, command="airodump-ng", _parameters={}, callback=False, wait=False, direct=False):
        if not callback:
            info("Defaulting to info callback for command {} params {}".format(command, _parameters))
            callback = lambda x: info(x)

        if command in self.executing.keys():
            raise AiroscriptError('Cannot execute %s, it\'s already executing' %command)
        self.executing[command] = [ ]

        parameters = self.parse_parameters(_parameters, command)
        pool = Pool(max_workers=1)

        if direct:
            return subprocess.check_output([command] + parameters)

        f = pool.submit(subprocess.Popen, [command] + parameters,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        f.add_done_callback(callback) #lambda x: self.callback(command, callback, x))
        pool.shutdown(wait=wait)
        return f

    def airmon(self, params, callback):
        info("Calling airmon with callback {}".format(callback))
        return self.execute(command="airmon-ng", _parameters=params, callback=callback)

class AiroscriptError(Exception):
    pass

class Session(object):
    """
        config object:
            - name
            - wifi
    """
    def __init__(self, config={}):
        self.config = config
        self._target = Target()
        self.target_dir = tempfile.mkdtemp()
        self.aircrack = Aircrack()
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
        mon_result = result.result().communicate()
        for line in mon_result[0].splitlines():
            monitor_test = re.match('(.*)\((.*)monitor mode enabled on (.*)\)(.*)', line)
            if monitor_test:
                self._mon_iface = monitor_test.group(3)
                if not self.mon_iface == self.should_be_mon_iface:
                    info("Monitor interface is called {} and should be called {}".format(
                        self.mon_iface, self.should_be_mon_iface))
        return True

    @property
    def target(self):
        return self._target

    @target.setter
    def set_target(self, dict_):
        """
            This way we only have to do something like
            self.target = current_targets[10] and it'll automatically
            make an object from it.
        """
        self._target = Target().from_dict(dict_)

    @property
    def current_targets(self):
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
        client_headers = clients.pop(0)

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
        return pluginmanager.trigger_event(
            "on_after_scan",
            target = self.target,
            session = self,
        )

    def scan(self):
        pluginmanager.trigger_event(
            "on_before_scan",
            target = self.target,
            session = self,
        )

        result = self.aircrack.execute(
            'airodump-ng',
            OrderedDict([
                ('network', self.mon_iface),
                ('dump_prefix', self.target_dir + "/" + self.config["name"])
            ])
        )

        # We wait default scan time and ask for airodump-ng to re-bump.
        # With this we can have an airodump-ng continuously scanning on background until we want to get to a fixed channel
        # TODO Maybe magic with fixed / hoping channels and different cards?
        return Timer(int(self.config['scan_time']), self.on_scan, (result.result().pid))

    def crack(self):
        return


class Target(object):
    def __init__(self):
        self.properties = [
            'bssid',
            'essid',
            'power',
            'encryption',
            'associated'
        ]

        for element in self.properties:
            setattr(self.__class__, element, '')

    def from_dict(self, dict_):
        self.bssid = dict_['BSSID']
        self.essid = dict_[' ESSID']
        self.power = dict_[' Power']
        self.encryption = dict_[' Privacy'],
        # TODO Make magic for associated

    @property
    def is_client(self):
        return getattr(self, "associated")

def main():
    logging.basicConfig(
        level=logging.INFO,
        format=("%(relativeCreated)04d %(process)05d %(threadName)-10s "
                "%(levelname)-5s %(msg)s"))
