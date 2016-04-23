#!/usr/bin/python

import argparse
from os import popen, system, getuid
from sys import exit

parser = argparse.ArgumentParser(description='Install EliDecode and the dependencies')
parser.add_argument('--unicorn', dest='unicorn', help='install the unicorn-engine', required=False, action='store_true')
parser.add_argument('--capstone', dest='capstone', help='install the capstone-engine', required=False, action='store_true')
parser.add_argument('--decode', dest='decode', help='clone / update EliDecode', required=False, action='store_true')

args = parser.parse_args()

# Check if we are root
if getuid() != 0:
	print "Error: please run me as root to install unicorn and capstone..."
	exit(2)

# Check if git exist
if system('git version') != 0:
	print "Error: you need git"
	exit(1)

if args.unicorn:
	print "Cloning unicorn..."
	popen("git clone https://github.com/unicorn-engine/unicorn")
	print "Installing unicorn"
	popen("cd unicorn && ./make.sh install && cd bindings/python && sudo make install")
	print "Cleaning..."
	popen("rm -Rf unicorn")
	print "Done!"

if args.capstone:
	print "Cloning capstone..."
	popen("git clone https://github.com/aquynh/capstone")
	print "Installing capstone"
	popen("cd capstone && ./make.sh install && cd bindings/python && sudo make install")
	print "Cleaning..."
	popen("rm -Rf capstone")
	print "Done!"

if args.decode:
	print "Cloning EliDecode..."
	popen("https://github.com/DeveloppSoft/EliDecode")
	print "Done!"
