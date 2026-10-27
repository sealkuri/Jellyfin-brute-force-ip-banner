import configparser     #For User Config 
import sqlite3      #For Banned Ip List
import select
from systemd import journal
from datetime import datetime, timedelta



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
                if entry.get("MESSAGE", "").split("] ").startswith("Authentication request"):
                    msg = entry.get("MESSAGE", "")
                    print(msg)



