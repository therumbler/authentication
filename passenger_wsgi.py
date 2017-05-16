#!/usr/bin/python2.7
import os
import sys

INTERP = "/home/auth2_user/auth.irumble.com/venv/bin/python"
if sys.executable != INTERP:
    os.execl(INTERP, INTERP, *sys.argv)

sys.path.append(os.getcwd())

#from flask import Flask

from app import application