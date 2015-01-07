#!/usr/bin/env python
# - encoding:utf-8 - #
from concurrent.futures import ThreadPoolExecutor as Pool
import logging
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
        :TODO:
            * Handle default parameters gracefully
            * Automatically generate the json this feeds on
    """
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
    return parameters


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
