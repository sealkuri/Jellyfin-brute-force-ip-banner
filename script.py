import configparser     # For User Config 
import sqlite3      # For Banned Ip List
import os
import select
from requests import post
from systemd import journal
from datetime import datetime, timedelta, timezone

#TODO Add config and checks for whitelist
#TODO Add sqlite saving on banned ips
#TODO configure ssh thing

class readwrite:
    def __init__(self):
        CONFIG_FILE = 'config.ini'
        self.Config = configparser.ConfigParser()

        if not os.path.exists(CONFIG_FILE):
            self.Config['SETTINGS'] = {
                    'Time Window': '5',
                    'Max Attempts': '5'
                    }
            self.Config['Whitelist'] = {
                    'Allowed IPs': ''
                    }
            self.Config['NTFY'] = {
                    'Enabled': 'no',
                    'Server': 'https://ntfy.sh',
                    'Topic name': ''
                    }
            with open(CONFIG_FILE, "w", encoding="utf-8") as configfile:
                self.Config.write(configfile)
        
        else:
            self.Config.read(CONFIG_FILE, encoding="utf-8")
    
    def ConfSettings(self):
        return(self.Config['SETTINGS']['Time Window'],
               self.Config.getint('SETTINGS', 'Max Attempts'),
               self.Config.get('Whitelist', 'Allowed IPs'),
               self.Config.getboolean('NTFY', 'Enabled'),
               self.Config['NTFY']['Server'],
               self.Config['NTFY']['Topic name'])



class Check:
    def __init__(self):
        # Initializes Timestamp and Tries 
        self.Time = datetime.now(timezone.utc).astimezone()

        self.Tries = 0
        self.checks = 0

        file = readwrite()
        self.Window, self.Max, self.Whitelist, self.NTFY, self.NTFYServer, self.NTFYTopic = file.ConfSettings()

        self.Whitelist = self.Whitelist.splitlines()
        self.Window = timedelta(minutes=int(self.Window))

        self.IPs= {}


    def evaluate(self, TS, IP):
        # If latest Timestamp was within 3 minutes of the current failed login attempt
        if IP not in self.Whitelist:

            self.checks += 1

            if not IP in self.IPs or TS - self.IPs[IP]['TimeStamp'] > self.Window:
                self.IPs[IP] = {'TimeStamp':TS, 'Tries': 1 }
            
            else:
                self.IPs[IP]['Tries'] += 1
            if self.IPs[IP]['Tries'] >=self.Max:

                print(IP)
                if self.NTFY:
                    post(self.NTFYServer + '/' +  self.NTFYTopic,
                         data= (IP + " Has been banned.").encode(encoding='utf-8'))
    




class LogParser():      # Reads log stream for failed login attemps
    def __init__(self):

        # Initializes log reader for jellyfin
        J = journal.Reader()
        J.add_match('_SYSTEMD_UNIT=jellyfin.service')
        J.log_level(journal.LOG_INFO)
        # Reads end of log
        J.seek_tail()
        J.get_previous()

        P = select.poll()
        P.register(J, J.get_events())
        
        # Initialize Check Class
        CheckLog = Check()
        
        while True:
            if P.poll(J.get_timeout_ms()):
                if J.process() == journal.APPEND:
                    for entry in J:
                        # Checks to see if log entry is a failed login attempt
                        if "Authentication request" and "denied" in entry.get("MESSAGE", ""):
                            # Sends Check.evaluate() the failed attempt Timestamp and IP
                            
                            CheckLog.evaluate(entry.get("__REALTIME_TIMESTAMP", ""), entry.get("MESSAGE", "").split("IP: ")[1].split(")")[0].strip())

if __name__ == "__main__":
    LogParser()
