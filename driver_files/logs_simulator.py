import win32evtlog
import win32evtlogutil

# Connect to the local system log
server = 'localhost'
logtype = 'System'
hand = win32evtlog.OpenEventLog(server, logtype)

# Setup flags to read logs
flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
total = win32evtlog.GetNumberOfEventLogRecords(hand)

print(f"Total events in {logtype}: {total}")

# Read log events
events = win32evtlog.ReadEventLog(hand, flags, 0)

for ev_obj in events:
    # Use win32evtlogutil to get the human-readable message
    msg = win32evtlogutil.SafeFormatMessage(ev_obj, logtype)
    print(f"Event Time: {ev_obj.TimeGenerated}")
    print(f"Source: {ev_obj.SourceName}")
    print(f"Message: {msg}")
    print("-" * 200)

win32evtlog.CloseEventLog(hand)
