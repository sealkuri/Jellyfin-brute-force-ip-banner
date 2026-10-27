import configparser
import json
import select
from systemd import journal
from datetime import datetime, timedelta




J = journal.Reader()
J.log_level(journal.LOG_INFO)
J.add_match('_SYSTEMD_UNIT=jellyfin.service')

J.seek_tail()
J.get_previous()

P = select.poll()
P.register(J, J.get_events())

while True:
    if P.poll(J.get_timeout_ms()):
        if J.process() == journal.APPEND:
            for entry in J:
                print("whattt")




