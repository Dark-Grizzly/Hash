#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
# Coded By Gr1zzly

import sys
import time
import math
import os
import hashlib
import string
import re

try:
	import argparse
	from wordlist import Generator
	from colorama import Fore, init
	from pyfiglet import print_figlet
	from requests import get, ConnectionError
	from threading import Thread, Event
except ImportError:
	sys.exit('\n[-] საჭირო მოდულები ვერ მოიძებნა\n[*] მოდულების დასაყენებლად გაუშვით შემდეგი ბრძანება:\n-------------------------------\n$ sudo pip3 install -r modules.txt\n')

init()
print(Fore.RED)
os.system('cls' if os.name == 'nt' else 'clear')
print_figlet('Hash', font='big')
start_time = time.time()
bf_counter = 0

parser = argparse.ArgumentParser()
parser.add_argument('--hash', help='ჰეში', required=True)
parser.add_argument('-t', '--thread', help='მოხდეს ნაკადების გამოყენება', action='store_true', default=False)
parser.add_argument('-d', '--debug', help='Debug რეჟიმის გააქტიურება', action='store_true', default=False)
parser.add_argument('-k', '--keywords', default=f'{string.digits}{string.ascii_letters}', help='სიმბოლოები რომლებიც გამოყენებულ იქნება ავტო გენერირებადი სიტყვათა სიისთვის')
parser.add_argument('-w', '--wordlist', default=False, help='ვორდლისტი რომლითაც მოხდება სკანირება [სურვილისამებრ]')
parser.add_argument('-m', '--min', type=int, help='ავტოგენერირებადი ვორდლისტის მინიმალური სიგრძე', default=1)
parser.add_argument('-M', '--max', type=int, help='ავტოგენერირებადი ვორდლისტის მაქსიმალური სიგრძე', default=16)

def encrypt(string, htype):
    if htype == 'md5':
        return hashlib.md5(string.encode()).hexdigest()
    elif htype == 'sha1':
        return hashlib.sha1(string.encode()).hexdigest()
    elif htype == 'sha224':
        return hashlib.sha224(string.encode()).hexdigest()
    elif htype == 'sha256':
        return hashlib.sha256(string.encode()).hexdigest()
    elif htype == 'sha384':
        return hashlib.sha384(string.encode()).hexdigest()
    elif htype == 'sha512':
        return hashlib.sha512(string.encode()).hexdigest()
    else:
        return False

def identify(h):
    result = list()
    for items in (("Blowfish(Eggdrop)", "^\+[a-zA-Z0-9\/\.]{12}$"),("Blowfish(OpenBSD)", "^\$2a\$[0-9]{0,2}?\$[a-zA-Z0-9\/\.]{53}$"),("Blowfish crypt", "^\$2[axy]{0,1}\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{1,}$"),(("DES(Unix)", "DES crypt", "DES hash(Traditional)"), "^.{0,2}[a-zA-Z0-9\/\.]{11}$"),("MD5", "^\$1\$.{0,8}\$[a-zA-Z0-9\/\.]{22}$"),(("MD5", "Apache MD5"), "^\$apr1\$.{0,8}\$[a-zA-Z0-9\/\.]{22}$"),("MD5", "^[a-fA-F0-9]{32}:[a-z0-9]{8}$"),("MD5", "^[a-fA-F0-9]{32}$"),(("MD5 crypt", "FreeBSD MD5", "Cisco-IOS MD5"), "^\$1\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{1,}$"),("MD5 apache crypt", "^\$apr1\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{1,}$"),("MD5", "^[a-fA-F0-9]{32}:[a-zA-Z0-9]{16,32}$"), ("MD5", "^\$P\$[a-zA-Z0-9\/\.]{31}$"),("MD5", "^\$H\$[a-zA-Z0-9\/\.]{31}$"),("MD5", "^[a-zA-Z0-9\/\.]{16}$"),(("MD5", "xt:Commerce"), "^[a-fA-F0-9]{32}:[a-zA-Z0-9]{2}$"),("MD5", "^[a-fA-F0-9]{51}$"),("MD5", "^[a-fA-F0-9]{32}:.{5}$"),("MD5", "^[a-fA-F0-9]{32}:[0-9]{32}:[a-fA-F0-9]{2}$"),("Juniper Netscreen/SSG (ScreenOS)", "^[a-zA-Z0-9]{30}:[a-zA-Z0-9]{4,}$"),("Fortigate (FortiOS)", "^[a-fA-F0-9]{47}$"),("Minecraft(Authme)", "^\$sha\$[a-zA-Z0-9]{0,16}\$[a-fA-F0-9]{64}$"),("Lotus Domino", "^\(?[a-zA-Z0-9\+\/]{20}\)?$"),("Lineage II C4", "^0x[a-fA-F0-9]{32}$"),("CRC-96(ZIP)", "^[a-fA-F0-9]{24}$"),("NT crypt", "^\$3\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{1,}$"), ("Skein-1024", "^[a-fA-F0-9]{256}$"),(("RIPEMD-320", "RIPEMD-320(HMAC)"), "^[A-Fa-f0-9]{80}$"),("EPi hash", "^0x[A-F0-9]{60}$"),("EPiServer 6.x < v4", "^\$episerver\$\*0\*[a-zA-Z0-9]{22}==\*[a-zA-Z0-9\+]{27}$"), ("EPiServer 6.x >= v4", "^\$episerver\$\*1\*[a-zA-Z0-9]{22}==\*[a-zA-Z0-9]{43}$"),("Cisco IOS SHA256", "^[a-zA-Z0-9]{43}$"),("SHA1", "^sha1\$.{0,32}\$[a-fA-F0-9]{40}$"),("SHA1 crypt", "^\$4\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{1,}$"),("SHA1", "^[a-fA-F0-9]{40}$"),(("SHA1", "Netscape LDAP SHA", "NSLDAP"), "^\{SHA\}[a-zA-Z0-9+/]{27}=$"),("SHA1", "^\{SSHA\}[a-zA-Z0-9+/]{28,}[=]{0,3}$"),("SHA512", "^\$S\$[a-zA-Z0-9\/\.]{52}$"),("SHA512 crypt", "^\$6\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{1,}$"),("SHA256", "^sha256\$.{0,32}\$[a-fA-F0-9]{64}$"),("SHA256 crypt", "^\$5\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{1,}$"),("SHA384", "^sha384\$.{0,32}\$[a-fA-F0-9]{96}$"),("SHA256", "^\$5\$.{0,22}\$[a-zA-Z0-9\/\.]{43,69}$"),("SHA512", "^\$6\$.{0,22}\$[a-zA-Z0-9\/\.]{86}$"),(("SHA384", "SHA3-384", "Skein-512(384)", "Skein-1024(384)"), "^[a-fA-F0-9]{96}$"),(("SHA512", "SHA512", "SHA3-512", "Whirlpool", "SALSA-10", "SALSA-20", "Keccak-512", "Skein-512","Skein-1024(512)"), "^[a-fA-F0-9]{128}$"),("SSHA1", "^({SSHA})?[a-zA-Z0-9\+\/]{32,38}?(==)?$"),(("SSHA1", "Netscape LDAP SSHA", "NSLDAPS"), "^\{SSHA\}[a-zA-Z0-9]{32,38}?(==)?$"),(("SSHA512", "LDAP {SSHA512}"), "^\{SSHA512\}[a-zA-Z0-9+]{96}$"),("Oracle 11g", "^S:[A-Z0-9]{60}$"),("SMF >= v1.1", "^[a-fA-F0-9]{40}:[0-9]{8}&"),("MySQL 5.x", "^\*[a-f0-9]{40}$"),(("MySQL 3.x", "DES(Oracle)", "LM", "VNC", "FNV-164"), "^[a-fA-F0-9]{16}$"),("OSX v10.7", "^[a-fA-F0-9]{136}$"),("OSX v10.8", "^\$ml\$[a-fA-F0-9$]{199}$"),("SAM(LM_Hash:NT_Hash)", "^[a-fA-F0-9]{32}:[a-fA-F0-9]{32}$"),("MSSQL(2000)", "^0x0100[a-f0-9]{0,8}?[a-f0-9]{80}$"),(("MSSQL(2005)", "MSSQL(2008)"), "^0x0100[a-f0-9]{0,8}?[a-f0-9]{40}$"),("MSSQL(2012)", "^0x02[a-f0-9]{0,10}?[a-f0-9]{128}$"),(("substr(md5($pass),0,16)", "substr(md5($pass),16,16)", "substr(md5($pass),8,16)", "CRC-64"),"^[a-fA-F0-9./]{16}$"),(("MySQL 4.x", "SHA1", "HAVAL-160", "SHA1", "SHA1", "TIGER-160", "RIPEMD-160","RIPEMD-160(HMAC)","TIGER-160(HMAC)", "Skein-256(160)", "Skein-512(160)"), "^[a-f0-9]{40}$"),(("SHA256", "SHA256", "SHA-3(Keccak)", "GOST R 34.11-94", "RIPEMD-256", "HAVAL-256", "Snefru-256","Snefru-256(HMAC)", "RIPEMD-256(HMAC)", "Keccak-256", "Skein-256", "Skein-512(256)"), "^[a-fA-F0-9]{64}$"),(("SHA1", "HAVAL-192", "OSX v10.4, v10.5, v10.6", "Tiger-192", "TIGER-192(HMAC)"), "^[a-fA-F0-9]{48}$"),(("SHA224", "SHA224", "HAVAL-224", "Keccak-224", "Skein-256(224)", "Skein-512(224)"), "^[a-fA-F0-9]{56}$"),(("Adler32", "FNV-32", "ELF-32", "Joaat", "CRC-32", "CRC-32B", "GHash-32-3", "GHash-32-5", "FCS-32", "Fletcher-32","XOR-32"), "^[a-fA-F0-9]{8}$"),(("CRC-16-CCITT", "CRC-16", "FCS-16"), "^[a-fA-F0-9]{4}$"),(("MD5", "MD5", "MD5", "RIPEMD-128", "RIPEMD-128(HMAC)", "Tiger-128", "Tiger-128(HMAC)","RAdmin v2.x", "NTLM", "Domain Cached Credentials(DCC)", "Domain Cached Credentials 2(DCC2)", "MD4", "MD2","MD4(HMAC)", "MD2(HMAC)", "Snefru-128", "Snefru-128(HMAC)", "HAVAL-128", "HAVAL-128(HMAC)", "Skein-256(128)","Skein-512(128)", "MSCASH2"), "^[0-9A-Fa-f]{32}$")):
        if re.match(items[1], h):
            try:
                result.append(items[0])
            except KeyError:
                return False
    return (result[0] if len(result) > 0 else False)


class Bruteforce(Thread):
	def __init__(self, 
				_hash, 
				minimal, 
				maximal,
				keywords, 
				hash_type, 
				th_id, 
				dbg,
				multi_th=False):
		super(Bruteforce, self).__init__()
		self.hash = _hash
		self.hash_type = hash_type
		self.min = minimal
		self.max = maximal
		self.keys = keywords[0]
		self.th_id = th_id
		self.dbg = dbg
		self.multi_th = multi_th
		self.done = False
		self.setDaemon(True)

	def run(self):
		global bf_counter, start_time
		try:
			generator = Generator(self.keys)
			for each in generator.generate(int(self.min), int(self.max)):
				if self.hash == encrypt(each, self.hash_type.lower()):
					print(f'\r{Fore.LIGHTGREEN_EX}[+][{bf_counter}] იეაჰ ბეიბი.. გავშიფრე: {each} -- {int(time.time() - start_time)}s\n')
					os._exit(0)
				else:
					if self.dbg and not self.multi_th:
						sys.stdout.write('\r%s[-][%i][%i] არ ემთხვევა: %s -- %is%s' % 
							(Fore.YELLOW, bf_counter, int(self.th_id), each, int(time.time() - start_time), Fore.GREEN))
					bf_counter += 1
		except Exception as err:
			print(f'[-] Thread-{self.th_id}: {err}')


class Hash(object):
	def __init__(self, 
				_hash,
				minimal = 1,
				maximal = 16,
				keywords = None,
				threading = False,
				debug = False,
				wordlist = False):
		super(Hash, self).__init__()
		self.hash = _hash.lower()
		self.threads = list()
		self.min = minimal
		self.max = maximal
		self.keys = keywords,
		self.wordlist = wordlist
		self.hash_len = len(self.hash)
		self.hash_type = identify(self.hash)
		self.start_time = time.time()
		self.use_threads = threading
		self.attemp_counter = 0
		self.debug_mode = debug
		self.config = {
			'url': 'https://md5decrypt.net/en/Api/api.php?hash={}&hash_type={}&email={}&code={}',
			'headers': {'User-Agent': 'Hash!'},
			'email': 'thedarkgrizzly@gmail.com',
			'code': 'e617c7e86645a36e'
        }

	def check_if_match(self, _cont, _hash):
		return _hash == encrypt(_cont, self.hash_type.lower())

	def check_online(self, _hash, hash_type):
		try:
		    response = get(self.config['url'].format(
	    	        _hash[0] if isinstance(_hash, tuple) else _hash,
	        	    hash_type.lower(),
	            	self.config['email'],
	            	self.config['code']),
	        	headers=self.config['headers'])

		    if response.status_code == 200 and 'ERROR CODE :' not in response.text and response.text != '':
		    	return response.text.strip()

		except ConnectionError:
			print(f'{Fore.YELLOW}[-] ინტერნეტი არ არის...{Fore.GREEN}')
			return False

		except Exception as err:
			if self.debug_mode:
				print(f'{Fore.YELLOW}[-] შეცდომა: {err}{Fore.GREEN}')
			return False


	def run(self):
		print('%s[*] ჰეში: %s\n[*] ჰეშის ტიპი: %s\n[*] ჰეშის სიგრძე: %i' %
			(Fore.GREEN, self.hash, self.hash_type if self.hash_type else f'{Fore.RED}ხუივოზნაეტ{Fore.GREEN}', self.hash_len))
		
		if not self.hash_type:
			print(f'{Fore.YELLOW}\n[-] ამ ტიპის ჰეშს ვერ გავშიფრავ{Fore.GREEN}\n')
			sys.exit(1)

		print('[*] ვამოწმებ ონლაინ ბაზებში...')
		online_response = self.check_online(self.hash, self.hash_type)
		if online_response:
			print('[+] იეაჰ ბეიბი.. გავშიფრე: %s' % (online_response))
			sys.exit(0)
		else:
			print(f'{Fore.YELLOW}[-] ვაახ, ბაზაში ვერაფერი ვნახე{Fore.GREEN}')

		if self.wordlist:
			if os.path.exists(self.wordlist):
				w_file = open(self.wordlist, 'r', encoding='utf-8')
				for content in w_file.read().split('\n'):
					if self.check_if_match(content, self.hash):
						print('\r[+][%i] იეაჰ ბეიბი.. გავშიფრე: %s' % (self.attemp_counter, content))
						break
					else:
						sys.stdout.write('\r[!][%i] არ ემთხვევა: %s' % (self.attemp_counter, content))
						sys.stdout.flush()
						self.attemp_counter += 1
			else:
				print(f'{Fore.YELLOW}\n[-] Wordlist არ არსებობს{Fore.GREEN}\n')
				sys.exit(2)
		else:
			print('[*] მოკლედ იწყება Bruteforce :))\n[*] შეტევა დაიწყო, გთხოოვთ დაიცადოთ')
			if self.use_threads:
				tosplit = 3
				th_id = 1
				mylist = [x for x in range(self.min, self.max + 1)]
				print(f'[*] ნაკადების რაოდენობა: {math.ceil(len(mylist) / tosplit)}')
				for index in range(0, len(mylist), tosplit):
					minimal = mylist[index:index + tosplit][0]
					maximal = mylist[index:index + tosplit][-1]
					try:
						bf = Bruteforce(_hash=self.hash,
							minimal=minimal,
							maximal=maximal,
							keywords=self.keys,
							hash_type=self.hash_type,
							th_id=th_id,
							multi_th = True,
							dbg=self.debug_mode)
						self.threads.append(bf)
						bf.start()
						th_id += 1
					except Exception as err:
						if self.debug_mode:
							print(err)

				for bf in self.threads:
					bf.join()
						
			else:
				print('[*] ნაკადების რაოდენობა: 1')
				bf = Bruteforce(
					_hash=self.hash,
					minimal=self.min,
					maximal=self.max,
					keywords=self.keys,
					hash_type=self.hash_type, 
					th_id=1,
					dbg=self.debug_mode)

				bf.start()
				bf.join()



if __name__ == '__main__':
	try:
		data = parser.parse_args()
		Hash = Hash(data.hash, 
					debug=data.debug,
					minimal=data.min, 
					maximal=data.max, 
					keywords=data.keywords, 
					wordlist=data.wordlist,
					threading=data.thread).run()
	except Exception as err:
		if data.debug:
			sys.exit(err)
		else:
			sys.exit(f'\n{Fore.YELLOW}[!] რაღაც შეცდომაა სანახავად გამოიყენეთ --debug{Fore.GREEN}')
	except KeyboardInterrupt:
		sys.exit(f'\n{Fore.YELLOW}[!] დაფიქსირდა CTRL + C{Fore.GREEN}')
