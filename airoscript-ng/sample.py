import airoscriptng

a=airoscriptng.Airoscript('wlan0').create_session()
a.scan()

while True:
    try:
        print a.current_targets['aps'][0]
        break
    except:
        pass

a.target = a.current_targets['aps'][0]
print a.target


"""
Result is:
INFO:airoscriptng:Calling airmon with callback <bound method Session.set_mon_iface of <airoscriptng.Session object at 0x7fd74a909990>>
INFO:airoscriptng:Calling airodump wit params OrderedDict([('dump_prefix', '/tmp/tmpxqPVbv/141981761977'), ('wireless', '1419817619770')]) and callback <function <lambda> at 0x7fd747febf50>
[('BSSID', '5C:35:3B:E1:3D:1F'), (' First time seen', ' 2014-12-29 02:47:02'), (' Last time seen', ' 2014-12-29 02:47:05'), (' channel', '  9'), (' Speed', '  54'), (' Privacy', ' WPA2'), (' Cipher', ' CCMP TKIP'), (' Authentication', 'PSK'), (' Power', ' -59'), (' # beacons', '        6'), (' # IV', '        0'), (' LAN IP', '   0.  0.  0.  0'), (' ID-length', '   5'), (' ESSID', ' XayOn'), (' Key', ' ')]
"""
