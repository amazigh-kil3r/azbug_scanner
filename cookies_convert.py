#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
from platform import system
import time
from time import time as timer

import sys


def clearscrn():
	if system() == 'Linux':
		os.system('clear')
	if system() == 'Windows':
		os.system('cls')
		os.system('color a')
		os.system('title [+] Powered By Trojan Kil3r Amazigh | Kabyle Hacker | Algeria Hacker | [+]')
clearscrn()

def slowprint(s):
    for c in s + '\n':
        sys.stdout.write(c)
        sys.stdout.flush()
        time.sleep(2. / 100)

def print_logo():
	bx = """
	\033[1;91m		

		 █████╗ ███╗   ███╗ █████╗ ███████╗██╗ ██████╗ ██╗  ██╗    ██╗  ██╗██╗██╗     ██████╗ ██████╗ \033[1;92m
		██╔══██╗████╗ ████║██╔══██╗╚══███╔╝██║██╔════╝ ██║  ██║    ██║ ██╔╝██║██║     ╚════██╗██╔══██╗ \033[1;93m	
		███████║██╔████╔██║███████║  ███╔╝ ██║██║  ███╗███████║    █████╔╝ ██║██║      █████╔╝██████╔╝ \033[1;94m	
		██╔══██║██║╚██╔╝██║██╔══██║ ███╔╝  ██║██║   ██║██╔══██║    ██╔═██╗ ██║██║      ╚═══██╗██╔══██╗ \033[1;96m	
		██║  ██║██║ ╚═╝ ██║██║  ██║███████╗██║╚██████╔╝██║  ██║    ██║  ██╗██║███████╗██████╔╝██║  ██║ \033[1;95m	
		╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝╚═╝ ╚═════╝ ╚═╝  ╚═╝    ╚═╝  ╚═╝╚═╝╚══════╝╚═════╝ ╚═╝  ╚═╝\033[1;95m	

\033[1;93m                                                                                                       
					🔰 Script Name : \033[1;91m| \033[1;92mA\033[1;93mu\033[1;96mt\033[1;95mo\033[1;96mm\033[1;91ma\033[1;92mt\033[1;93mi\033[1;96mo\033[1;95mn\033[1;94m_Scr\033[1;93mipt\033[1;92m |  \033[1;93m👻\033[1;96m
	                	Greetz To : \033[1;93mNo\033[0;92m\033[1;92m_One  \033[5;91m|D\033[5;92mz| \033[0;96m\033[1;96mResearcher \033[94mDz\033[90m \033[93m
	"""
	x = """

\033[91m
		   	
		  ___      _                    _____                                 \033[1;92m
		 / _ \    | |                  /  ___|                                \033[1;93m
		/ /_\ \___| |__  _   _  __ _   \ `--.  ___ __ _ _ __  _ __   ___ _ __ \033[1;94m
		|  _  |_  / '_ \| | | |/ _` |   `--. \/ __/ _` | '_ \| '_ \ / _ \ '__|\033[1;92m
		| | | |/ /| |_) | |_| | (_| |  /\__/ / (_| (_| | | | | | | |  __/ |   \033[1;96m
		\_| |_/___|_.__/ \__,_|\__, |  \____/ \___\__,_|_| |_|_| |_|\___|_|   \033[1;93m
		                        __/ |                                        \033[1;92m
		                       |___/                                         \033[1;94m

	\033[1;93m                                                                                                          
					🔰 Script Name : \033[1;91m| \033[1;92mA\033[1;93mu\033[1;96mt\033[1;95mo\033[1;96mm\033[1;91ma\033[1;92mt\033[1;93mi\033[1;96mo\033[1;95mn\033[1;94m_Scr\033[1;93mipt\033[1;92m |  \033[1;93m👻\033[1;96m
	                	Greetz To : \033[1;93mNo\033[0;92m\033[1;92m_One  \033[5;91m|D\033[5;92mz| \033[0;96m\033[1;96mResearcher \033[94mDz\033[90m \033[93m
	"""
	if system() == 'Windows':
		print(x)
		slowprint("\t\t\t\t\tPowered By : Trojan Kil3r Amazigh " + "\n\t\t\t\t\t\t            Contact Me : twitter.com/Kil3rdz")
	else:
		print(bx)
		slowprint("\t\t\t\t\tPowered By : Trojan Kil3r Amazigh " + "\n\t\t\t\t\t\t            Contact Me : twitter.com/Kil3rdz")
print_logo()

if sys.version_info < (3, 0):
    sys.stdout.write("\033[1;96m[-] \033[1;91;40mSorry, This Script requires Python 3.x :(\n\n")
    sys.exit(1)

from http.cookies import SimpleCookie
azbug = input("\n\t\033[1;96m[\033[1;92m+\033[1;96m] \033[1;92mPut Your Cookies :) : ")
cookie = SimpleCookie()
cookie.load(azbug)
cookies = {}
for key, azbug2 in cookie.items():
    cookies[key] = azbug2.value
print("\n\033[1;95;40m* Cookie Converted Success : \033[1;96;40m\n\n" + str(cookies) + "\n\033[0m")
print("   \033[1;93;40m[!] \033[1;91;40mNote: \033[1;94;40mCopy The Converted Cookies, And Past It In Script (azbug.py) in cookies = {''} !\033[0m\n")