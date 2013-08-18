import os
import subprocess

path=".\source"
dirList=os.listdir(path)
for fname in dirList:
    #subprocess.call(['python file_parser.py',fname])
    os.system("python file_parser.py " + fname)
