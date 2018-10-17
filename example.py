import sys
import time
import signal
from base import MiBand2

MAC = sys.argv[1]

band = MiBand2(MAC, debug=True)
band.setSecurityLevel(level="medium")

if len(sys.argv) > 2:
    if band.initialize():
        print("Init OK")
    band.set_heart_monitor_sleep_support(enabled=False)
    band.disconnect()
    sys.exit(0)
else:
    band.authenticate()

time.sleep(8)

def l(x):
    print('Realtime heart:', x)

signal.signal(signal.SIGINT, band.stop_heart_rate_realtime)
band.start_heart_rate_realtime(heart_measure_callback=l)
