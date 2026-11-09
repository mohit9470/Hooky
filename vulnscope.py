#!/usr/bin/env python3
"""Compatibility wrapper - the tool is now called **Hooky** and the main
entry point is ``hooky.py``.

Keeps every old ``python3 vulnscope.py ...`` invocation working: it simply
runs hooky.py with the same arguments.
"""
import os
import runpy
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

print("Note: 'vulnscope.py' is now 'hooky.py' (Hooky %s) - see "
      "'python3 hooky.py help'." % "2.1")
runpy.run_path(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "hooky.py"), run_name="__main__")
