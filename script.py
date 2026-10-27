import configparser     #For User Config 
import sqlite3      #For Banned Ip List
import select
from systemd import journal
from datetime import datetime, timedelta

Time = datetime.now()
Tries = 0

#Sets up log reader
J = journal.Reader()
J.add_match('_SYSTEMD_UNIT=jellyfin.service')
#Reads end of log
J.log_level(journal.LOG_INFO)
J.seek_tail()
J.get_previous()

P = select.poll()
P.register(J, J.get_events())

while True:
    if P.poll(J.get_timeout_ms()):
        if J.process() == journal.APPEND:
            for entry in J:
                if "Authentication request" and "denied" in entry.get("MESSAGE", ""):
                    Check(entry)

def Check(entry):
    if entry.get("__REALTIME_TIMESTAMP", "") - timedelta(minutes=3) > Time:
        Time = entry.get("__REALTIME_TIMESTAMP")
        Tries = 1
    else:
        Tries+=1
    if Tries >=5:
        print('banned')
    
    


