import configparser  
import sqlite3      # Used for making a database of banned ips to check and re-apply iptable rule after a reboot
import os       
import ipaddress
import subprocess
import select
from requests import post, RequestException     # For ntfy notifications, comment out if not wanted
from systemd import journal
from datetime import datetime, timedelta


class ReadWrite:        
    def __init__(self):
        self.config = configparser.ConfigParser()

        BASE_DIR = os.path.dirname(os.path.abspath('__file__'))
        CONFIG_FILE = os.path.join(BASE_DIR + 'config.ini')
        DATABASE = os.path.join(BASE_DIR + 'BannedIPs.db')

        if not os.path.exists(CONFIG_FILE):  
            self.config['SETTINGS'] = {
                    'Time Window': '5',
                    'Max Attempts': '5'
                    }
            self.config['SSH'] = {
                    'Enabled': 'no',
                    'User': '',
                    'Server': '',
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
        return(row[0] for row in self.conn.execute('SELECT ip FROM bans'))

    def updatedb(self, ip, timestamp): 
        self.conn.execute('INSERT OR REPLACE INTO bans(ip, banned_at) VALUES (?, ?)',
                          (ip, int(timestamp.timestamp())))
        self.conn.commit()
            
    def confsettings(self):     
            return{'window': self.config.getint('SETTINGS', 'Time Window'),
                   'max': self.config.getint('SETTINGS', 'Max Attempts'),
                   'ssh': self.config.getboolean('SSH', 'Enabled'),
                   'ssh command': self.config['SSH']['User'] + '@' + self.config['SSH']['Server'],
                   'whitelist': self.config.get('Whitelist', 'Allowed IPs'),
                   'ntfy': self.config.getboolean('NTFY', 'Enabled'),
                   'ntfy link': self.config['NTFY']['Server'] + '/' + self.config['NTFY']['Topic name']}


class Check:
    def __init__(self):

        self.file = ReadWrite()

        conf = self.file.confsettings()

        self.window = timedelta(minutes=conf['window'])
        self.max = conf['max']
        self.ssh = conf['ssh']
        self.ssh_command = conf['ssh command']
        self.whitelist = conf['whitelist'].splitlines()
        self.ntfy = conf['ntfy']
        self.link = conf['ntfy link']

        self.checks = 0
        self.ips = {}

        for ip in self.file.checkdb():      # Checks and re-applies bans 
            self.ban(ip)

    def ban(self, ip):
        rule = ["INPUT", "-s", ip, "-j", "DROP"]

        try:
            if self.ssh:
                exists = subprocess.run(["ssh", self.ssh_command, "iptables", "-c", *rule],
                                        capture_output=True,
                                        text=True,
                                        timeout=10).returncode == 0 
                if not exists:
                    subprocess.run(["sse", self.ssh_command, "iptables", "-a", *rule],
                                   check=True,
                                   text=True,
                                   capture_output=True,
                                   timeout=10)
            else:
                exists = subprocess.run(["iptables", "-c", *rule],
                                        capture_output=True,
                                        text=True,
                                        timeout=10).returncode == 0 
                if not exists:
                    subprocess.run(["iptables", "-a", *rule],
                                   check=True,
                                   text=True,
                                   capture_output=True,
                                   timeout=10)

        except (subprocess.CalledProcessError, FileNotFoundError,
                subprocess.TimeoutExpired) as error:
            print('Command failed:', getattr(error, 'stderr', None) or error)

    def prune(self, now):       # Gets rid of old IP attempts to save memory
        old = [ip for ip, timestamp in self.ips.items()
               if now - timestamp['TimeStamp'] > self.window]
        for ip in old:
            del self.ips[ip]
    
    def getip(self, ip):        # Validates for a real external ip adress
        try:
            return str(ipaddress.ip_address(ip))
        except (ValueError, IndexError):
            return None


    def evaluate(self, ts, ip): 
        ip = self.getip(ip)
        if ip is not None:

            if ip not in self.whitelist:
                if not ip in self.ips or ts - self.ips[ip]['TimeStamp'] > self.window:      # Creates or resets attempt time and history if old or new
                    self.ips[ip] = {'TimeStamp':ts, 'Tries': 1 }
                
                else:
                    self.ips[ip]['Tries'] += 1

                    if self.ips[ip]['Tries'] >=self.max:
                        del self.ips[ip]

                        self.file.updatedb(ip, ts)
                        self.ban(ip)

                        if self.ntfy:       # For ntfy notifications, comment out if not wanted
                            try:
                                post(self.link, data = (ip + " Has been banned.")
                                     .encode(encoding='utf-8'), timeout=5)

                            except RequestException as error:
                                print('NTFY failed:', error)
            
                self.checks += 1

                if self.checks >= 100:
                    self.prune(ts)
                    self.checks = 0


class LogParser:   
    def __init__(self):
        self.checker = Check()

        self.reader = journal.Reader()
        self.reader.add_match('_SYSTEMD_UNIT=jellyfin.service')
        self.reader.log_level(journal.LOG_INFO)
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
