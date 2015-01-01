import airoscriptng

a=airoscriptng.Airoscript('wlan0').create_session().scan()
a.target = a.current_targets['aps'][0]
print a.target
