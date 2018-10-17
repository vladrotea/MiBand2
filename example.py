import sys
import time
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


def b(x):
    print('Raw heart:', x)


def f(x):
    print('Raw accel heart:', x)

# band.start_heart_rate_realtime(heart_measure_callback=l)
band.start_raw_data_realtime(heart_measure_callback=l, heart_raw_callback=b, accel_raw_callback=f)
band.disconnect()
