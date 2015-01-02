import xmlrpclib

proxy = xmlrpclib.ServerProxy('http://localhost:8000')
proxy.scan()
proxy.set_target(proxy.get_current_targets()['aps'][0])
print(proxy.get_target())
