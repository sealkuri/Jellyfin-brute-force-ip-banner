import configparser  
import sqlite3      
import os       # For creating missing config and ban databas
import subprocess
import select
from requests import post, RequestException     # For ntfy notifications, comment out if not wanted
from systemd import journal
from datetime import datetime, timedelta

#TODO configure ssh thing

class ReadWrite:        
    def __init__(self):
        self.config = configparser.ConfigParser()
        BASE_DIR = os.path.dirname(os.path.abspath('__file__')
        CONFIG_FILE = os.path.join(basedir + 'config.ini')
        DATABASE = os.path.join(basedir + 'BannedIPs.db')

        if not os.path.exists(CONFIG_FILE):     # Create config for user to configure if it doesnt exist
            self.config['SETTINGS'] = {
                    'Time Window': '5',
                    'Max Attempts': '5'
                    }
            self.config['Whitelist'] = {
                    'Allowed IPs': ''
                    }
            self.config['NTFY'] = {
                    'Enabled': 'no',
                    'Server': 'https://ntfy.sh',
                    'Topic name': ''
                    }
            with open(CONFIG_FILE, "w", encoding="utf-8") as configfile:
                self.config.write(configfile)
        
        else:
            self.config.read(CONFIG_FILE, encoding="utf-8")

        self.conn = sqlite3.connect(DATABASE)
        self.conn.execute('''CREATE TABLE IF NOT EXISTS bans(
                          ip            TEXT PRIMARY KEY,
                          banned_at     INTEGER NOT NULL)''')

    def checkdb(self):
        return(row[0] for row in self.conn.execute('SELECT * ip FROM bans'))

    def updatedb(self, ip, timestamp):     # Adds ip and timestamp to database or later use in re-banning after a restart
        self.conn.execute('INSERT OR REPLACE INTO bans(ip, banned_at) VALUES (?, ?)',
                          (ip, int(timestamp.timestamp())))
        self.conn.commit()
            
    
    def confsettings(self):     
            return{'window': self.config.getint('SETTINGS', 'Time Window'),
               'max': self.config.getint('SETTINGS', 'Max Attempts'),
               'whitelist': self.config.get('Whitelist', 'Allowed IPs'),
               'ntfy': self.config.getboolean('NTFY', 'Enabled'),
               'ntfy link': self.config['NTFY']['Server'] + '/' + self.config['NTFY']['Topic name']}


class Check:
    def __init__(self):

        self.file = ReadWrite()
        conf = self.file.confsettings()
        # Initializes config values
        self.window = timedelta(minutes=conf['window'])
        self.max = conf['max']
        self.whitelist = conf['whitelist'].splitlines()
        self.ntfy = conf['ntfy']
        self.link = conf['ntfy link']
        
        for ip in self.file.checkdb():
            self.ban(ip)

        self.checks = 0
        self.ips = {}

    def ban(self, ip):      # Adds rule to iptables to drop all packages for ip
        rule = ["INPUT", "-s", ip, "-j", "DROP"]

        try:
            exists = subprocess.run(["iptables", "-c", *rule],
                                    capture_output=True, text=True, timeout=10).returncode == 0 
            
            if not exists:
                subprocess.run(["iptables", "-a", *rule],
                               check=True, text=True, capture_output=True, timeout=10)

        except (subprocess.CalledProcessError, FileNotFoundError,
                subprocess.TimeoutExpired) as error:
            print('Command failed:', getattr(error, 'stderr', None) or error)

    def prune(self, now):       # Gets rid of old IP attempts to save memory
        old = [ip for ip, timestamp in self.ips.items()
               if now - timestamp['TimeStamp'] > self.window]
        for ip in old:
            del self.ips[ip]


    def evaluate(self, ts, ip): 
        # If latest Timestamp was within window of the current failed login attempt
        if ip not in self.whitelist:
            self.checks += 1

            if not ip in self.ips or ts - self.ips[ip]['TimeStamp'] > self.window:      # Creates or resets attempt time and history if old or new
                self.ips[ip] = {'TimeStamp':ts, 'Tries': 1 }
            
            else:
                self.ips[ip]['Tries'] += 1

            if self.ips[ip]['Tries'] >=self.max:
                del self.ips[ip]

                self.file.updatedb(ip, ts)      # Adds ip and timestamp to sqlite3 database
                self.ban(ip)

                if self.ntfy:
                    try:
                        post(self.link, data = (ip + " Has been banned.")
                             .encode(encoding='utf-8'), timeout=5)

                    except RequestException as error:
                        print('NTFY failed:', error)

        if self.checks >= 100:
            self.prune(ts)
            self.checks = 0


class LogParser:      # Reads log stream for failed login attemps
    def __init__(self):

        self.checker = Check()
        # Initializes log reader for jellyfin.service to keep up with latest log entry
        self.reader = journal.Reader()
        self.reader.add_match('_SYSTEMD_UNIT=jellyfin.service')
        self.reader.log_level(journal.LOG_INFO)
        # Reads end of log
        self.reader.seek_tail()
        self.reader.get_previous()

        self.poller = select.poll()
        self.poller.register(self.reader, self.reader.get_events())
    
    def run(self):
        while True:
            if self.poller.poll(self.reader.get_timeout_ms()):      # Waits until there has been a change to the log

                if self.reader.process() == journal.APPEND:
                    for entry in self.reader:
                        msg = entry.get("MESSAGE", "")

                        if "Authentication request" in msg and "denied" in msg:
                            self.checker.evaluate(entry.get("__REALTIME_TIMESTAMP", ""),
                                                  entry.get("MESSAGE", "").split("IP: ", 1)[1].split(")", 1)[0].strip())

if __name__ == "__main__":
    LogParser().run()
