import pyfiglet
import hashlib
from colorama import init
from colorama import Fore, Back, Style
from virustotal_python import Virustotal
import requests
from pathlib import Path
from pprint import pprint
import os
init(convert=True)
try:
    with open('VirusTotal_APIKey.txt') as f:
        data = f.readlines()
    f.close()
    APIKey = ''.join(data)
except:
    createfile = open("VirusTotal_APIKey.txt", "a")
    print(Fore.LIGHTYELLOW_EX,"[Warning] Enter your VirusTotal API Key \n")
    APIKeyInput = input("")
    createfile.truncate(0)
    createfile.writelines(APIKeyInput)
    createfile.close()
    print(Fore.WHITE)
    os.system('cls' if os.name == 'nt' else 'clear')
while(1):
    ascii_banner = pyfiglet.figlet_format("Lightning")
    print(Fore.CYAN + ascii_banner)
    print(Fore.MAGENTA , "[Fast Virus Scanner] - Created by Nemesis0U \n \n")
    print(Fore.WHITE)
    BUF_SIZE = 65536
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    print("Enter path of a file to scan")
    FilePath = input("")
    print("\n")
    with open(FilePath, 'rb') as f:
        while True:
          data = f.read(BUF_SIZE)
          if not data:
              break
          sha1.update(data)
          sha256.update(data)
    SHA1_of_file = sha1.hexdigest()
    SHA256_of_file = sha256.hexdigest()
    print("File Name: ", Path(FilePath).stem)
    print("SHA1: " , SHA1_of_file)
    print("SHA256: " , SHA256_of_file)
    try:
        with Virustotal(API_KEY=APIKey, API_VERSION="v3") as vtotal:
             resp = vtotal.request(f"files/{SHA256_of_file}")
             serverresponse = str(resp.data)
             print("Scan Results: \n")
             if((serverresponse.count("'category': 'malicious'")) >= 5):
                 print(Fore.LIGHTRED_EX,"This file is flagged by " , (serverresponse.count("'category': 'malicious'")) , " antivirus softwares as malicious")
             elif((serverresponse.count("'category': 'malicious'")) >= 2):
                print(Fore.LIGHTYELLOW_EX ,"This file is flagged by " , (serverresponse.count("'category': 'malicious'")) , " antivirus softwares as malicious")
             elif((serverresponse.count("'category': 'malicious'")) == 1):
                 print(Fore.LIGHTWHITE_EX ,"This file is flagged by " , (serverresponse.count("'category': 'malicious'")) , " antivirus software as malicious")
             else:
                 print(Fore.LIGHTGREEN_EX ,"This file is flagged by " , (serverresponse.count("'category': 'malicious'")) , " antivirus softwares as malicious")
        print(Fore.WHITE)
    except:
        print("File not found in VirusTotal, sending it for analysis...")
        with Virustotal(API_KEY=APIKey, API_VERSION="v3") as vtotal:
         FilePathConverted = {"file": (os.path.basename(FilePath), open(os.path.abspath(FilePath).replace("\\\\","\\"), "rb"))}
         resp = vtotal.request("files", files=FilePathConverted, method="POST")
         serverresponse = str(resp.data)
         print("File successfully sent for analysis, re-scan it to get results")
    wait = input("Press any key to continue \n")
    os.system('cls' if os.name == 'nt' else 'clear')