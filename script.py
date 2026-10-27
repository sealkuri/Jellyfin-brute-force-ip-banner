import configparser     #For User Config 
import sqlite3      #For Banned Ip List
import select
from systemd import journal
from datetime import datetime, timedelta, timezone



class Check:
    def __init__(self):
        self.Time = datetime.now(timezone.utc).astimezone()
        self.Tries = 0

    def evaluate(self, TS, IP):
        if self.Time - TS >= timedelta(minutes=3):
            self.Time = TS
            self.Tries = 1
        else:
            self.Tries+=1
        if self.Tries >=5:
            print(IP)
    

class LogParser():
    def __init__(self):

        #Sets up log reader
        J = journal.Reader()
        J.add_match('_SYSTEMD_UNIT=jellyfin.service')
        #Reads end of log
        J.log_level(journal.LOG_INFO)
        J.seek_tail()
        J.get_previous()

        P = select.poll()
        P.register(J, J.get_events())
        
        CheckLog = Check()
        
        while True:
            if P.poll(J.get_timeout_ms()):
                if J.process() == journal.APPEND:
                    for entry in J:
                        if "Authentication request" and "denied" in entry.get("MESSAGE", ""):
                            
                            CheckLog.evaluate(entry.get("__REALTIME_TIMESTAMP", ""), entry.get("MESSAGE", "").split("IP: ")[1].split(")")[0].strip())

if __name__ == "__main__":
    LogParser()
