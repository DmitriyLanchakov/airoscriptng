#!/usr/bin/env python
# - encoding:utf-8 - #
from concurrent.futures import ThreadPoolExecutor as Pool
import logging
import subprocess
debug = logging.getLogger(__name__).debug


class Executor(object):
    def __init__(self, command="airmon-ng", _parameters={},
                 callback=False, shell=False, direct=False):
        self.command = command
        self.devnull = open('/dev/null', 'w')
        self.callback = callback
        parameters = _parameters

        logging.debug("Launching: {} {} {}".format(
            command, parameters, callback))

        if direct:
            self.result = subprocess.check_output([command] + parameters)
        else:
            self.result = subprocess.Popen([command] + parameters,
                                           stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE,
                                           shell=shell)


def parse_parameters(attributes, _parameters={}, command="airodump-ng"):
    parameters = []
    if command in attributes:
        for name, param in attributes[command].iteritems():
            if param[1] and name not in _parameters:
                if param[0]:
                    parameters.append(param[0])
                if param[1] is not True:
                    parameters.append(param[1])
        for name, param in _parameters.iteritems():
            if name in attributes[command]:
                schema = attributes[command][name]
                if schema[1] and schema[0]:
                    parameters.append(schema[0])
                parameters.append(param)
    # TODO FIXME DEFAULTS DONT WORK OK HERE
    return parameters


class Aircrack(object):
    def __init__(self, attributes={}):
        """
            Dinamically creates a function for each aircrack-ng binary.
            This class should never use self.executing, that's work
            for the session handler one.
        """
        self.cmds = dict(zip([b.replace('-ng', '') for b in attributes.keys()],
                             attributes.keys()))
        self.attributes = attributes

        for name in self.cmds.keys():
            setattr(self, name, lambda x, y, name_=self.cmds[name]: self.execute(name_, _parameters=x, callback=y))

    def launch(self, *args, **kwargs):
        pool = Pool(max_workers=1)
        f = pool.submit(Executor, *args, **kwargs)
        f.add_done_callback(self.callback)
        pool.shutdown(wait=True)
        return f


class AircrackSession(Aircrack):
    """
        Each session should have one or many aircrack-ng objects.
        An aircrack-ng object should be able to execute ONE of EACH
        aircrack-ng suite processes.
        TODO: maybe exceptions to this.
    """

    executing = {}

    def callback(self, result):
        """
            Remove the finished process from self.executing.
        """
        result = result.result()
        self.executing.pop(result.command)
        if type(result.callback) != dict:
            return result.callback(result.result)
        return debug(result.result)

    def execute(self, *args, **kwargs):
        callback = kwargs['callback']
        command = args[0]
        kwargs['_parameters'] = parse_parameters(
            self.attributes, kwargs['_parameters'], command)
        if not callback:
            debug("Defaulting cb for command {} ".format(command))
            callback = lambda x: debug(x)

        if command in self.executing.keys():
            raise AircrackError('{} is already executing'.format(command))
        self.executing[command] = []
        return self.launch(*args, **kwargs)


class AircrackError(Exception):
    pass
