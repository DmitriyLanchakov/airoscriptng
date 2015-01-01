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
