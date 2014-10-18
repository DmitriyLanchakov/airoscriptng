#!/usr/bin/env python
# -*- coding: utf-8 -*-
from SimpleXMLRPCServer import SimpleXMLRPCServer
from SimpleXMLRPCServer import SimpleXMLRPCRequestHandler
from airoscriptng import Session

server = SimpleXMLRPCServer(("localhost", 8000))
server.register_instance(Session({'name':'one', 'wifi': 'wlan0', 'scan_time':'10'}))
