#!/usr/bin/python
import time

"""
Testing the functionality and use of decorators in Python.
"""

def timer(func):
    x = time.time()
    func()
    print(f"Function took {time.time() - x} seconds to run.")

# "@timer" does the same thing as "timer(hello)" or "hello = timer(hello)"
@timer
def hello():
    print("Hello World!!!")

#timer(hello)
#hello = timer(hello)