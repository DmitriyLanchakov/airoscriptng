#!/usr/bin/env python
# - encoding:utf-8 - #
from concurrent.futures import ThreadPoolExecutor as Pool
import logging
import itertools
import subprocess
debug = logging.getLogger(__name__).debug


class Executor(object):
    """
        Executor objects gets created to manage aircrack-ng execution.

        It's called from a threadpoolexecutor, this way the future returns this
        as result, having control of the commands called and callback.
    """
    def __init__(self, command="airmon-ng", _parameters={},
                 callback=False, shell=False, direct=False):
        """
            Initialize and execute process

            *If direct=True will call check_output instead of Popen*
        """
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
    """
        Main aircrack-ng parameter parsing from the json file is done here.

        :TODO: * Automatically generate the json this feeds on

        Parameter format is as follows:

        ::

            {
                'main_command': {
                    'name_in_airoscript' : ['--flag_in_aircrack', "default_value"]
                }
            }


        If default_value is True, it'll be assumed that is a flag that dont
        require an argument, and we want it by default enabled.

        If it's false, the same will be assumed, but will by default disabled.

        All parameters can be overriden
    """
    _attributes = attributes.copy()
    for name in attributes[command].keys():
        if name in _parameters:
            _attributes[command][name][-1] = _parameters[name]
        if attributes[command][name][-1] is False and name in _attributes[command]:
            _attributes[command].pop(name)

    for name in _attributes[command].keys():
        if _attributes[command][name][-1] is False:
            _attributes[command].pop(name)
        elif _attributes[command][name][-1] is True:
            del(_attributes[command][name][-1])

    return list(itertools.chain(*_attributes[command].values()))


class Aircrack(object):
    """
        Exports a method foreach aircrack-ng binary that gets an OrderedDict
        with the desired parameters as argument.

        Those parameters must match the ones specified in the json parameter
        file
    """
    def __init__(self, attributes={}):
        """
            Dinamically creates a function for each aircrack-ng binary.

            W: This class should never use self.executing, that's work
            for the session handler one.
        """
        self.cmds = dict(zip([b.replace('-ng', '') for b in attributes.keys()],
                             attributes.keys()))
        self.attributes = attributes

        for name in self.cmds.keys():
            setattr(self, name, lambda x, y, name_=self.cmds[name]: self.execute(name_, _parameters=x, callback=y))

    def callback(self, result):
        """
            Plain aircrack-ng just logs the output and calls custom user
            callback (hence this callback).

            An aircrack-ng session handler can be used to extend this class
            to avoid having multiple aircrack-ng processes loose
        """

        if type(result.callback) != dict:
            return result.callback(result.result)
        return debug(result.result)

    def launch(self, *args, **kwargs):
        """
            Launch a new pool with one thread for that one process.
            Then we call the callback.
        """
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

        :TODO:
            - Add some exceptions, there are processes of what we might
                want to have multiple instances running
    """

    executing = {}

    def callback(self, result):
        """
            * Remove the finished process from self.executing.
            * Then execute the user-defined callback if exists.
            * Otherwise just log output
        """
        result = result.result()
        self.executing.pop(result.command)
        if type(result.callback) != dict:
            return result.callback(result.result)
        return debug(result.result)

    def execute(self, *args, **kwargs):
        """
            Execute aircrack-ng command.

            - Parse parameters
            - Set up default callback
            - Check that proccess is not executing already
            - Then execute launch method.
        """
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
    """
        Base aircrack exception
    """
    pass
