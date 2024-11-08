#!/usr/bin/python

import os
import datetime
import pyxhook
import platform

# Function for Linux-based OS
def linuxKeylogger():
        #log = f"{os.getcwd}/{datetime.now().strftime("%d-%m-%Y|%H:%M")}.log"

        print("Run Linux keylogger...")

# Function for Windows-based OS
def winKeylogger():
     
     print("Run Windows keylogger...")


def main():
    # Create object for 'osQuery' class and run it to determine OS
    OS = platform.system()
    print(f"{OS}")

    # Match case to run OS-dependant function
    match OS:
        case "Linux": linuxKeylogger() # Call Linux-based keylogger
        case 'Windows': pass # Call Windows-based keylogger
        case _: return "OS is not 'Windows' or 'Linux'."

if __name__ == "__main__":
    main()