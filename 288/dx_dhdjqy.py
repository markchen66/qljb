# main_script.py
import os
import re
import sys
import ssl
import time
import json
import execjs
import base64
import random
import certifi
import aiohttp
import asyncio
import datetime
import requests
import binascii
import threading
from lxml import etree
from http import cookiejar
from Crypto.Cipher import AES
from Crypto.Cipher import DES3
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Util.Padding import pad, unpad
from aiohttp import ClientSession, TCPConnector
from concurrent.futures import ThreadPoolExecutor

import gjc  # 替换为 gjc 模块

run_num = os.environ.get('reqNUM') or "40"
diffValue = 2

MAX_RETRIES = 3
RATE_LIMIT = 10  # 每秒请求数限制

class RateLimiter:
    def __init__(self, rate_limit):
        self.rate_limit = rate_limit
        self.tokens = rate_limit
        self.updated_at = time.monotonic()

    async def acquire(self):
        while self.tokens < 1:
            self.add_new_tokens()
            await asyncio.sleep(0.1)
        self.tokens -= 1

    def add_new_tokens(self):
        now = time.monotonic()
        time_since_update = now - self.updated_at
        new_tokens = time_since_update * self.rate_limit
        if new_tokens > 1:
            self.tokens = min(self.tokens + new_tokens, self.rate_limit)
            self.updated_at = now

class AsyncSessionManager:
    def __init__(self):
        self.session = None
        self.connector = None

    async def __aenter__(self):
        ssl_context = ssl.create_default_context(cafile=certifi.where())
        ssl_context.set_ciphers('DEFAULT@SECLEVEL=1')
        ssl_context.check_hostname = False  # 禁用主机名验证
        ssl_context.verify_mode = ssl.CERT_NONE  # 禁用证书验证
        self.connector = TCPConnector(ssl=ssl_context, limit=1000)
        self.session = ClientSession(connector=self.connector)
        return self.session

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.session.close()
        await self.connector.close()

async def retry_request(session, method, url, **kwargs):
    for attempt in range(MAX_RETRIES):
        try:
            await asyncio.sleep(1)
            async with session.request(method, url, **kwargs) as response:
                return await response.json() 
        except (aiohttp.ClientConnectionError, aiohttp.ServerTimeoutError) as e:
            print(f"请求失败，第 {attempt + 1} 次重试: {e}")
            if attempt == MAX_RETRIES - 1:
                raise 
            await asyncio.sleep(2 ** attempt)

class BlockAll(cookiejar.CookiePolicy):
    return_ok = set_ok = domain_return_ok = path_return_ok = lambda self, *args, **kwargs: False
    netscape = True
    rfc2965 = hide_cookie2 = False
    
def printn(m):  
    print(f'\n{m}')

context = ssl.create_default_context()
context.set_ciphers('DEFAULT@SECLEVEL=1')  # 低安全级别0/1
context.check_hostname = False  # 禁用主机
context.verify_mode = ssl.CERT_NONE  # 禁用证书

class DESAdapter(requests.adapters.HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        kwargs['ssl_context'] = context
        return super().init_poolmanager(*args, **kwargs)

requests.DEFAULT_RETRIES = 0
requests.packages.urllib3.disable_warnings()
ss = requests.session()
ss.headers = {"User-Agent": "Mozilla/5.0 (Linux; Android 13; 22081212C Build/TKQ1.220829.002) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.97 Mobile Safari/537.36", "Referer": "https://wapact.189.cn:9001/JinDouMall/JinDouMall_independentDetails.html"}    
ss.mount('https://', DESAdapter())       
ss.cookies.set_policy(BlockAll())
runTime = 0
sleepTime = 1
key = b'1234567`90koiuyhgtfrdews'
iv = 8 * b'\0'

public_key_b64 = '''-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDBkLT15ThVgz6/NOl6s8GNPofdWzWbCkWnkaAm7O2LjkM1H7dMvzkiqdxU02jamGRHLX/ZNMCXHnPcW/sDhiFCBN18qFvy8g6VYb9QtroI09e176s+ZCtiv7hbin2cCTj99iUpnEloZm19lwHyo69u5UMiPMpq0/XKBO8lYhN/gwIDAQAB
-----END PUBLIC KEY-----'''

public_key_data = '''-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC+ugG5A8cZ3FqUKDwM57GM4io6JGcStivT8UdGt67PEOihLZTw3P7371+N47PrmsCpnTRzbTgcupKtUv8ImZalYk65dU8rjC/ridwhw9ffW2LBwvkEnDkkKKRi2liWIItDftJVBiWOh17o6gfbPoNrWORcAdcbpk2L+udld5kZNwIDAQAB
-----END PUBLIC KEY-----'''

def get_first_three(value):
    # 处理数字情况
    if isinstance(value, (int, float)):
        return int(str(value)[:3])
    elif isinstance(value, str):
        return str(value)
    else:
        raise TypeError("error")

def run_Time(hour, miute, second):    
    date = datetime.datetime.now()
    date_zero = datetime.datetime.now().replace(year=date.year, month=date.month, day=date.day, hour=hour, minute=miute, second=second)
    date_zero_time = int(time.mktime(date_zero.timetuple()))
    return date_zero_time

def encrypt(text):    
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(text.encode(), DES3.block_size))
    return ciphertext.hex()

def decrypt(text):
    ciphertext = bytes.fromhex(text)
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), DES3.block_size)
    return plaintext.decode()
    
def b64(plaintext):
    public_key = RSA.import_key(public_key_b64)
    cipher = PKCS1_v1_5.new(public_key)
    ciphertext = cipher.encrypt(plaintext.encode())
    return base64.b64encode(ciphertext).decode()
    
def encrypt_para(plaintext):
    if not isinstance(plaintext, str):
        plaintext = json.dumps(plaintext)
    public_key = RSA.import_key(public_key_data)  
    cipher = PKCS1_v1_5.new(public_key)
    ciphertext = cipher.encrypt(plaintext.encode())
    return binascii.hexlify(ciphertext).decode() 

def encode_phone(text):
    encoded_chars = []
    for char in text:
        encoded_chars.append(chr(ord(char) + 2))
    return ''.join(encoded_chars)

def getApiTime(api_url):
    try:
        with requests.get(api_url) as response:
            if not response or not response.text:
                return time.time()
            json_data = json.loads(response.text)
            if json_data.get("api") and json_data.get("api") not in ("time"):
                timestamp_str = json_data.get('data', {}).get('t', '')
            else:
                timestamp_str = json_data.get('currentTime', {}) 
            timestamp = int(timestamp_str) / 1000.0  # 将毫秒转为秒
            difftime = time.time() - timestamp
            return difftime
    except Exception as e:
        print(f"获取时间失败: {e}")
        return 0

def userLoginNormal(phone, password):
    alphabet = 'abcdef0123456789'
    uuid = [''.join(random.sample(alphabet, 8)), ''.join(random.sample(alphabet, 4)), '4' + ''.join(random.sample(alphabet, 3)), ''.join(random.sample(alphabet, 4)), ''.join(random.sample(alphabet, 12))]
    timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    loginAuthCipherAsymmertric = 'iPhone 14 15.4.' + uuid[0] + uuid[1] + phone + timestamp + password[:6] + '0$$$0.'

    data = {
        "headerInfos": {
            "code": "userLoginNormal",
            "timestamp": timestamp,
            "broadAccount": "",
            "broadToken": "",
            "clientType": "#9.6.1#channel50#iPhone 14 Pro Max#",
            "shopId": "20002",
            "source": "110003",
            "sourcePassword": "Sid98s",
            "token": "",
            "userLoginName": phone
        },
        "content": {
            "attach": "test",
            "fieldData": {
                "loginType": "4",
                "accountType": "",
                "loginAuthCipherAsymmertric": b64(loginAuthCipherAsymmertric),
                "deviceUid": uuid[0] + uuid[1] + uuid[2],
                "phoneNum": encode_phone(phone),
                "isChinatelecom": "0",
                "systemVersion": "15.4.0",
                "authentication": password
            }
        }
    }

    try:
        r = ss.post('https://appgologin.189.cn:9031/login/client/userLoginNormal', json=data, verify=certifi.where()).json()
        l = r['responseData']['data']['loginSuccessResult']
        if l:
            ticket = get_ticket(phone, l['userId'], l['token'])
            return ticket
    except (KeyError, TypeError, requests.exceptions.RequestException) as e:
        print(f"{phone} 登录失败: {e}")
        return False

    return False
        
async def exchangeForDay(phone, session, run_Time, rid):
    cs = 0  # 初始化计数器
    while cs < run_Time:  # 控制运行次数
        success = await conversionRights(phone, rid, session, run_Time)
        if success:  # 只有请求成功后才增加计数
            cs += 1
            print(f"{get_first_three(phone)} 兑换 {cs}/{run_Time} 次")
        if sleepTime: 
            await asyncio.sleep(sleepTime)

def get_ticket(phone, userId, token):
    r = ss.post('https://appgologin.189.cn:9031/map/clientXML', data='<Request><HeaderInfos><Code>getSingle</Code><Timestamp>' + datetime.datetime.now().strftime("%Y%m%d%H%M%S") + '</Timestamp><BroadAccount></BroadAccount><BroadToken></BroadToken><ClientType>#9.6.1#channel50#iPhone 14 Pro Max#</ClientType><ShopId>20002</ShopId><Source>110003</Source><SourcePassword>Sid98s</SourcePassword><Token>' + token + '</Token><UserLoginName>' + phone + '</UserLoginName></HeaderInfos><Content><Attach>test</Attach><FieldData><TargetId>' + encrypt(userId) + '</TargetId><Url>4a6862274835b451</Url></FieldData></Content></Request>', headers={'user-agent': 'CtClient;10.4.1;Android;13;22081212C;NTQzNzgx!#!MTgwNTg1'}, verify=certifi.where())
    tk = re.findall('<Ticket>(.*?)</Ticket>', r.text)
    if len(tk) == 0:        
        return False
    return decrypt(tk[0])

async def exchange(s, phone, title, aid, jsexec, ckvalue):
    try:
        url = "https://wapact.189.cn:9001/gateway/stand/detailNew/exchange"
        get_url = await asyncio.to_thread(jsexec.call, "getUrl", "POST", url)
        async with s.post(get_url, cookies=ckvalue, json={"activityId": aid}) as response:
            pass
    except Exception as e:
        print(e)

async def check(s, item, ckvalue):
    checkGoods = s.get('https://wapact.189.cn:9001/gateway/stand/detailNew/check?activityId=' + item, cookies=ckvalue).json()
    return checkGoods

async def conversionRights(phone, aid, session, run_Time):
    value = {
        "phone": phone,
        "rightsId": aid
    }
    # 使用 gjc.get_rs 获取 Cookie
    cookies = await gjc.get_rs('https://wapside.189.cn:9001/jt-sign/paradise/conversionRights', session)
    if not cookies:
        print("Failed to get cookies from gjc.get_rs")
        return

    now = datetime.datetime.now()
    target_time = now.replace(hour=23, minute=59, second=59, microsecond=500000)
    
    # 计算时间差（秒）
    time_diff = (target_time - now).total_seconds()

    # 判断是否在设定时间的 5 分钟之内
    if 0 < time_diff <= 300:  # 5 分钟 = 300 秒
        print(f"{get_first_three(phone)} 当前时间在 5分钟之内，等待 {time_diff} 秒")
        await asyncio.sleep(time_diff)
    elif time_diff > 300:
        print(f"{get_first_three(phone)} 当前时间不在 5 分钟之内，直接运行")
    # else:
    #     print(f"{get_first_three(phone)} 当前时间已超过，直接运行")

    # 加密请求参数
    paraV = encrypt_para(value)

    # 发送请求
    response = await session.post(
        'https://wapside.189.cn:9001/jt-sign/paradise/conversionRights',
        json={"para": paraV},
        cookies=cookies
    )

    # 处理响应
    if response:
        login = await response.json()
        printn(f"{get_first_three(phone)},{str(datetime.datetime.now())[11:23]}:{login} ")
        return True  # 请求成功，返回 True
    else:
        printn(f"{get_first_three(phone)}, 跳过response对象为空!")
        return False  # 请求失败，返回 False

def run_conversion_rights(phone, aid, session, loop):
    asyncio.run_coroutine_threadsafe(conversionRights(phone, aid, session), loop)
    
async def getLevelRightsList(phone, session):
    value = {
        "phone": phone
    }
    paraV = encrypt_para(value)
    max_retries = 3  # 最大重试次数
    retries = 0

    while retries < max_retries:
        try:
            # 使用 gjc.get_rs 获取 Cookie
            cookies = await gjc.get_rs('https://wapside.189.cn:9001/jt-sign/paradise/getLevelRightsList', session)
            if not cookies:
                print("Failed to get cookies from gjc.get_rs")
                return None

            response = await session.post(
                'https://wapside.189.cn:9001/jt-sign/paradise/getLevelRightsList',
                json={"para": paraV},
                cookies=cookies
            )
            data = await response.json()

            if data.get('code') == 401:
                print(f"获取失败:{data},原因大概是sign过期了")
                return None

            current_level = data.get('currentLevel')
            if current_level is None:
                print(f"获取失败: 'currentLevel' 不存在于返回的数据中")
                return None

            current_level = int(current_level)
            key_name = 'V' + str(current_level)
            ids = [item['id'] for item in data.get(key_name, []) if item.get('name') == '话费']
            if ids:
                print(f"{get_first_three(phone)}获取到了rightsId: {ids[0]}")
                valueTest = {
                    "phone": phone
                }
                paraVTest = encrypt_para(value)
                
                cookies = await gjc.get_rs('https://wapside.189.cn:9001/jt-sign/paradise/getParadiseInfo', session)
                if not cookies:
                    print("Failed to get cookies from gjc.get_rs")
                    return None

                responseTest = await session.post(
                    'https://wapside.189.cn:9001/jt-sign/paradise/getParadiseInfo',
                    json={"para": paraV},
                    cookies=cookies
                )
                if responseTest.status == 200:
                    try:
                        response_json = await responseTest.json()
                        loginTest = response_json
                        rights = loginTest.get('rights')
                        if rights['rightsSize'] == 1:
                            ids.clear()
                    except json.JSONDecodeError:
                        print(f"{get_first_three(phone)} getParadiseInfo 返回数据不是有效的 JSON 格式: {responseTest.text}")
                else:
                    print(f"{get_first_three(phone)} getParadiseInfo 请求失败，状态码: {responseTest.status}, 响应内容: {responseTest.text}")
            return ids

        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            retries += 1
            print(f"{get_first_three(phone)} 请求失败，重试 {retries}/{max_retries}... 错误信息: {e}")
            await asyncio.sleep(2 ** retries)  # 指数退避等待

    print(f"{get_first_three(phone)} 达到最大重试次数，放弃请求")
    return None

async def getSign(ticket, session):
    try:
        # 使用 gjc.get_rs 获取 Cookie
        cookies = await gjc.get_rs('https://wapside.189.cn:9001/jt-sign/ssoHomLogin', session)
        if not cookies:
            print("Failed to get cookies from gjc.get_rs")
            return None

        response_data = await session.get('https://wapside.189.cn:9001/jt-sign/ssoHomLogin?ticket=' + ticket, cookies=cookies)
        response_json = await response_data.json()
        if response_json.get('resoultCode') == '0':
            sign = response_json.get('sign')
            return sign
        else:
            print(f"获取sign失败[{response_json.get('resoultCode')}]: {response_json}")
    except Exception as e:
        print(e)
    return None

async def login_request(ss, url, payload):
    global ckvalue, js_codeRead
    url = "https://wapact.189.cn:9001/unified/user/login"
    headers = {
        'Accept': 'application/json, text/javascript, */*; q=0.01',
        'Accept-Language': 'zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
        'Origin': 'https://wapact.189.cn:9001',
        'Pragma': 'no-cache',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-origin',
        'X-Requested-With': 'XMLHttpRequest',
        'sec-ch-ua': '"Not/A)Brand";v="8", "Chromium";v="126", "Android WebView";v="126"',
        'sec-ch-ua-mobile': '?1',
        'sec-ch-ua-platform': '"Android"',
        'Content-Type': 'application/json;charset=UTF-8'
    }
    response = await ss.post(url, headers=headers, data=json.dumps(payload))
    rsCK = re.findall('yiUIIlbdQT3fO=([^;]+)', response.headers['Set-Cookie'])[0]
    if response.status == 412:
        print("检测到瑞数特征码412,正在尝试调用js")
    else:
        print("未检测到瑞数.")
        return response, None, rsCK
    html = etree.HTML(response.text)
    arg1 = html.xpath('//meta/@content')[-1]
    arg2 = html.xpath('//script/text()')[0]
    arg3 = html.xpath('//meta/@id')[-1]
    js_code = js_codeRead.replace("contentCODE", arg1).replace('"tsCODE"', arg2).replace('"tsID"', f'"{arg3}"')
    
    jsexec = execjs.compile(js_code)
    ck = await asyncio.to_thread(jsexec.call, "getck")
    get_url = await asyncio.to_thread(jsexec.call, "getUrl", "POST", url)
    
    def parse_cookies(ck):
        cookies = {}
        for part in ck.split(';'):
            part = part.strip()
            if '=' in part:
                key, value = part.split('=', 1)
                if 'path' not in key and 'expires' not in key and 'Secure' not in key and 'SameSite' not in key:
                    cookies[key] = value
        return cookies
    ck = parse_cookies(ck)
    ck["yiUIIlbdQT3fO"] = rsCK
    ckvalue = ck
    res = await ss.post(get_url, headers=headers, data=json.dumps(payload), cookies=ckvalue)
    if res.status == 200:
        print("瑞数返回状态码200,开始下一步.")
        return res, jsexec, ckvalue
    else:
        print("瑞数破解失败,调用重试机制")
        return res, jsexec, None
    return res, jsexec, ckvalue

async def qgNight(phone, ticket, timeValue, isTrue):
    async with AsyncSessionManager() as session:
        sign = await getSign(ticket, session)
        if sign:
            # 使用 update 方法更新 headers
            session.headers.update({
                "User-Agent": "Mozilla/5.0 (Linux; Android 13; 22081212C Build/TKQ1.220829.002) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.97 Mobile Safari/537.36",
                "sign": sign
            })
        else:
            print("未能获取sign。")
            return

        rightsId = await getLevelRightsList(phone, session)
        if rightsId:
            print(f"{get_first_three(phone)}准备兑换登记权益")
        else:
            print(f"{get_first_three(phone)}已兑换或未达到LV3及以上")
            return

        if isTrue:
            runTime2 = run_Time(23, 58, 59)
            nt = time.time() + runTime
            now = datetime.datetime.fromtimestamp(nt)
            rt2 = datetime.datetime.fromtimestamp(runTime2)
            print(f"兑换时间：{str(rt2)[11:23]}, 当前时间：{str(now)[11:23]}")

            time_diff = (rt2 - now).total_seconds()

            if time_diff > 0 and time_diff <= 600:  # 5分钟内等待
                print(f"兑换>>> 等待时间秒: {time_diff}")
                await asyncio.sleep(time_diff)
            elif time_diff > 600:  # 超过5分钟直接运行
                print("距离设定时间超过10分钟，直接运行兑换操作。")

        # printn(f"{str(datetime.datetime.now())[11:23]} 时间到开始兑换每天一次的")
        await exchangeForDay(phone, session, 10, rightsId[0])

async def main(timeValue, isTRUE):
    global runTime, js_codeRead
    tasks = []
    phone_list = re.split('\n|&', chinaTelecomAccount)
    print("读取到手机号个数共 >>>", len(phone_list))

    # 限制并发数为 5
    semaphore = asyncio.Semaphore(30)

    async def limited_task(phoneV):
        async with semaphore:
            value = phoneV.split('#')
            phone, password = value[0], value[1]
            printn(f'{get_first_three(phone)}开始登录')
            ticket = await asyncio.to_thread(userLoginNormal, phone, password)
            if ticket:
                await qgNight(phone, ticket, timeValue, isTRUE)
            else:
                printn(f'{phone} 登录失败')

    tasks = [limited_task(phoneV) for phoneV in phone_list]
    await asyncio.gather(*tasks)

chinaTelecomAccount = os.environ.get('chinaTelecomAccount')    
if __name__ == "__main__":
    wttime = run_Time(23, 59, 59)  # 设置为凌晨场次
    isTRUE = True  # isTRUE等于False则表示忽略所有直接运行
    global timeValue, timeDiff
    timeValue = getApiTime("https://acs.m.taobao.com/gw/mtop.common.getTimestamp/")
    timeDiff = timeValue if timeValue > 0 else 0
    print(f"当前本地时间: {str(datetime.datetime.now())[11:23]}, 与网络时间差异：{timeDiff}")
    asyncio.run(main(timeDiff, isTRUE))