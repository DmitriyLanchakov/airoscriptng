#!/usr/bin/env python
# -*- coding: utf-8 -*-
from SimpleXMLRPCServer import SimpleXMLRPCServer
from airoscriptng import AiroscriptSession

if __name__ == "__main__":
    server = SimpleXMLRPCServer(("localhost", 8000), allow_none=True)
    server.register_instance(AiroscriptSession({'name': 'one',
                                                'wifi': 'wlan0',
                                                'scan_time': '10'}
                                               ), allow_dotted_names=True)
    server.register_introspection_functions()
    server.serve_forever()
