#!/usr/bin/env python
# - encoding:utf-8 - #
from concurrent.futures import ThreadPoolExecutor as Pool
from process_helpers import Executor, parse_parameters
import logging
debug = logging.getLogger(__name__).debug

class Aircrack(object):
    def __init__(self, attributes={}):
        """
            Dinamically creates a function for each aircrack-ng binary.
        """
        self.cmds = dict(zip([b.replace('-ng', '') for b in attributes.keys()], attributes.keys()))
        self.executing = {}
        self.attributes = attributes

        for name in self.cmds.keys():
            setattr(self, name, lambda x, y, name_=self.cmds[name]: self.execute(name_, _parameters=x, callback=y))

    def callback(self, result):
        """
            Remove the finished process from self.executing.
        """
        result = result.result()
        self.executing.pop(result.command)
        return result.callback(result.result)

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

    def callback(self, result):
        """
            Remove the finished process from self.executing.
        """
        result = result.result()
        self.executing.pop(result.command)
        return result.callback(result.result)

    def execute(self, *args, **kwargs):
        callback = kwargs['callback']
        command = args[0]
        kwargs['_parameters'] = parse_parameters(self.attributes, kwargs['_parameters'], command)
        if not callback:
            debug("Defaulting to debug callback for command {} ".format(command))
            callback = lambda x: debug(x)

        if command in self.executing.keys():
            raise AircrackError('Cannot execute %s, it\'s already executing' %command)
        self.executing[command] = [ ]
        return self.launch(*args, **kwargs)

class AircrackError(Exception):
    pass
