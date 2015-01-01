#!/usr/bin/env python
# - encoding:utf-8 - #
import logging
import subprocess
debug = logging.getLogger(__name__).debug

class Executor(object):
    def __init__(self, command="airmon-ng", _parameters={}, callback=False, wait=False, shell=False, direct=False):
        self.command = command
        self.devnull = open('/dev/null', 'w')
        self.callback = callback
        parameters = _parameters

        logging.debug("Launching: {} {} {}".format(command, parameters, callback))

        if direct:
            self.result = subprocess.check_output([command] + parameters)
        else:
            self.result = subprocess.Popen([command] + parameters,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=shell)

def parse_parameters( attributes, _parameters={}, command="airodump-ng"):
    parameters = []
    if command in attributes:
        for name, param in attributes[command].iteritems():
            if param[1] and not name in _parameters:
                if param[0]:
                    parameters.append(param[0])
                if param[1] != True:
                    parameters.append(param[1])
        for name, param in _parameters.iteritems():
            if name in attributes[command]:
                schema = attributes[command][name]
                if schema[1] and schema[0]:
                    parameters.append(schema[0])
                parameters.append(param)
    # TODO FIXME DEFAULTS DONT WORK OK HERE
    return parameters


