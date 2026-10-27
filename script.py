import configparser
import json
import select
from systemd import journal
from datetime import datetime, timedelta




J = journal.Reader()
J.log_level(journal.LOG_INFO)
J.add_match('_SYSTEMD_UNIT=Jellyfin.service')

J.seek_tail()

P = select.poll()
P.register(J, select.POLLIN)

while True:
    if P.poll():
        if J.process() == journal.APPEND:
            for entry in J:
                print("whattt\n")




