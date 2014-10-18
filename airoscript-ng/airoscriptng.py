#!/usr/bin/env python
# -*- coding: utf-8 -*-
from datetime import time
import pluginmanager
from collections import OrderedDict
from threading import Timer
import tempfile
import logging
import subprocess
import StringIO
import netifaces
import time
import os
import re
import csv
from concurrent.futures import ThreadPoolExecutor as Pool
info = logging.getLogger(__name__).info

def callback(future):
    if future.exception() is not None:
        info("Got exception: %s" % future.exception())
    else:
        info("Process returned %d" % future.result())

# TODO: Move this to a proper place
pluginmanager.load_plugins("plugins.list")

class Airoscript(object):
    def __init__(self):
        # Base state, almost nothing should be done here.
        self.session_list = {}

    def create_session(self, name):
        if not name in self.session_list:
            self.session_list['name'] = Session(time())
        else:
            return False

        return self.session_list['name']


class Aircrack(object):
    """
        Each session should have one or many aircrack-ng objects.
        An aircrack-ng object should be able to execute ONE of EACH
        aircrack-ng suite processes.
        On callback,
    """
    def __init__(self, binary_path="/usr/sbin"):
        """
            Dinamically creates a function for each aircrack-ng binary.
        """
        self.binary_path = binary_path
        _cmds = ['airodump', 'aircrack', 'airmon']
        self.cmds = dict(list(zip(_cmds, map(lambda x: x + "-ng", _cmds))))
        self.executing = {}
        for cmdname, cmd in self.cmds.iteritems():
            if not hasattr(self, cmdname):
                setattr(self.__class__, cmdname, lambda s, params: self.execute(cmd, params, callback))

        self.attributes = {
            'airodump-ng': {
                'ivs': ['--ivs', False],
                'gps': ['--gpsd', False],
                'filter_unassociated_clients': ['-a', True],
                'update' : ['--update', '20'],
                'ignore_one' : ['--ignore-negative-one', True],
                'network': ['mon0', True],
                'dump_prefix' : ['-w', '/tmp']
            }
        }

    def callback(self, command, callback, result):
        """
            Remove the finished process from self.executing.
        """
        self.executing.pop(command)
        print result
        return callback(result)

    def execute(self, command="airodump-ng", _parameters={}, callback=False):
        if not callback:
            callback = lambda x: info(x)
        parameters = []
        if command in self.attributes:
            for name, param in self.attributes[command].iteritems():
                if param[1] and not name in _parameters:
                    parameters.append(param[0])
                    if param[1] != True:
                        parameters.append(param[1])

            for name, param in _parameters.iteritems():
                if name in self.attributes[command]:
                    schema = self.attributes[command][name]
                    if schema[1] != True:
                        parameters.append(schema[0])
                    parameters.append(param)

            print parameters

        if command in self.executing.keys():
            raise AiroscriptError('Cannot execute %s, it\'s already executing' %command)

        self.executing[command] = [ ]

        pool = Pool(max_workers=1)

        # TODO Where should I put communication with the process? =/
        FNULL = open(os.devnull, 'w')
        f = pool.submit(subprocess.Popen, [command] + parameters,
                stdout=FNULL, stderr=FNULL, stdin=FNULL)
        f.add_done_callback(lambda x: self.callback(command, callback, x))
        pool.shutdown(wait=False)
        return f

class AiroscriptError(Exception):
    pass

class Session(object):
    def __init__(self, config={}):
        self.config = config
        self._target = Target()
        self.target_dir = tempfile.mkdtemp()
        self.aircrack = Aircrack()
        os.environ['MON_PREFIX'] = self.config["name"] # FIXME This may cause concurrency problems
        self.should_be_mon_iface = self.config["name"] + "0"

        if not self.should_be_mon_iface in netifaces.interfaces():
            self.monitor_result = self.aircrack.execute('airmon-ng', OrderedDict([('command',
                "start"), ('wireless', self.config["wifi"])]))
            self.mon_iface = [re.match('(.*)\(monitor mode enabled on (.*)\)', f).group(2) for f in self.monitor_result.result().communicate()[0].splitlines() if 'monitor mode enabled on' in f]
        else:
            self.mon_iface = self.should_be_mon_iface

        if not self.mon_iface == self.should_be_mon_iface:
           raise Exception("""Monitor interface is called %s and should be called
                   %s. Something fishy is happening with your wireless card,
                   have you put it MANUALLY in monitor mode with this session
                   name? Are you running multiple airoscript-ng with the same
                   session names?""" %(self.mon_iface, self.should_be_mon_iface))

    @property
    def target(self):
        return self._target

    @target.set
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

    @property
    def is_client(self):
        return getattr(self, "associated")

def main():
    logging.basicConfig(
        level=logging.INFO,
        format=("%(relativeCreated)04d %(process)05d %(threadName)-10s "
                "%(levelname)-5s %(msg)s"))


