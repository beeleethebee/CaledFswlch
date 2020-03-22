#!/usr/bin/env python3

import subprocess
import sys
import stat
import os

print("Installation des packets nécessaires ...")
subprocess.check_call([sys.executable, "-m", 'pip', "install", "fusepy"])
subprocess.check_call([sys.executable, "-m", 'pip', "install", "cryptography"])

st = os.stat('caledfswlch.py')
os.chmod('caledfswlch.py', st.st_mode | stat.S_IEXEC)
os.system("dos2unix caledfswlch.py")
