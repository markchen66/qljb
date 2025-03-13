import sys
import asyncio
import aiohttp
import os
import execjs
import requests
import re
import time
import json
import random
import datetime
import base64
import ssl
import execjs
import os
import sys
from ldap3.core.tls import check_hostname
import datetime_b
from bs4 import BeautifulSoup
from loguru import logger
from lxml import etree
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.strxor import strxor
from Crypto.Cipher import AES
from http import cookiejar  # Python 2: import cookielib as cookiejar
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.ssl_ import create_urllib3_context

class BlockAll(cookiejar.CookiePolicy):
    return_ok = set_ok = domain_return_ok = path_return_ok = lambda self, *args, **kwargs: False
    netscape = True
    rfc2965 = hide_cookie2 = False

def printn(m):  
    print(f'\n{m}')

ORIGIN_CIPHERS = ('DEFAULT@SECLEVEL=1')

class DESAdapter(HTTPAdapter):
    def __init__(self, *args, **kwargs):
        CIPHERS = ORIGIN_CIPHERS.split(':')
        random.shuffle(CIPHERS)
        CIPHERS = ':'.join(CIPHERS)
        self.CIPHERS = CIPHERS + ':!aNULL:!eNULL:!MD5'
        super().__init__(*args, **kwargs)
 
    def init_poolmanager(self, *args, **kwargs):
        context = create_urllib3_context(ciphers=self.CIPHERS)
        context.check_hostname = False
        kwargs['ssl_context'] = context

        return super(DESAdapter, self).init_poolmanager(*args, **kwargs)
 
    def proxy_manager_for(self, *args, **kwargs):
        context = create_urllib3_context(ciphers=self.CIPHERS)
        context.check_hostname = False
        kwargs['ssl_context'] = context
        return super(DESAdapter, self).proxy_manager_for(*args, **kwargs)

requests.packages.urllib3.disable_warnings()
ssl_context = ssl.create_default_context()
ssl_context.set_ciphers("DEFAULT@SECLEVEL=1")  # Set security level to allow smaller DH keys    
ss = requests.session()
ss.headers={"User-Agent":"Mozilla/5.0 (Linux; Android 13; 22081212C Build/TKQ1.220829.002) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.97 Mobile Safari/537.36","Referer":"https://wapact.189.cn:9001/JinDouMall/JinDouMall_independentDetails.html"}    
ss.mount('https://', DESAdapter())       
ss.cookies.set_policy(BlockAll())
yc = 1
wt = 0
kswt = 0.9
yf = datetime.datetime.now().strftime("%Y%m")
ip_list = []
jp = {"9": {}, "13": {}}
try:
    with open('电信金豆换话费.log') as fr:
        dhjl = json.load(fr)
except :
    dhjl = {}
if yf not in dhjl:
    dhjl[yf] = {}
load_token_file = 'chinaTelecom_cache.json'
try:
    with open(load_token_file, 'r') as f:
        load_token = json.load(f)
except:
    load_token = {}

errcode = {
    "0":"兑换成功",
    "412":"兑换次数已达上限",
    "413":"商品已兑完",
    "420":"未知错误",
    "410":"该活动已失效~",
    "Y0001":"当前等级不足，去升级兑当前话费",
    "Y0002":"使用翼相连网络600分钟或连接并拓展网络500分钟可兑换此奖品",
    "Y0003":"使用翼相连共享流量400M或共享WIFI：2GB可兑换此奖品",
    "Y0004":"使用翼相连共享流量2GB可兑换此奖品",
    "Y0005":"当前等级不足，去升级兑当前话费",
    "E0001":"您的网龄不足10年，暂不能兑换"
}

key = b'1234567`90koiuyhgtfrdews'
iv = 8 * b'\0'

public_key_b64 = '''-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDBkLT15ThVgz6/NOl6s8GNPofdWzWbCkWnkaAm7O2LjkM1H7dMvzkiqdxU02jamGRHLX/ZNMCXHnPcW/sDhiFCBN18qFvy8g6VYb9QtroI09e176s+ZCtiv7hbin2cCTj99iUpnEloZm19lwHyo69u5UMiPMpq0/XKBO8lYhN/gwIDAQAB
-----END PUBLIC KEY-----'''

public_key_data = '''-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC+ugG5A8cZ3FqUKDwM57GM4io6JGcStivT8UdGt67PEOihLZTw3P7371+N47PrmsCpnTRzbTgcupKtUv8ImZalYk65dU8rjC/ridwhw9ffW2LBwvkEnDkkKKRi2liWIItDftJVBiWOh17o6gfbPoNrWORcAdcbpk2L+udld5kZNwIDAQAB
-----END PUBLIC KEY-----'''

def get_network_time():
    return datetime.datetime.now()  # 返回本地时间

def t(h):
    date = get_network_time()
    date_zero = date.replace(hour=h, minute=59, second=35)
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
    public_key = RSA.import_key(public_key_data)
    cipher = PKCS1_v1_5.new(public_key)
    ciphertext = cipher.encrypt(plaintext.encode())
    return ciphertext.hex()

def encode_phone(text):
    encoded_chars = []
    for char in text:
        encoded_chars.append(chr(ord(char) + 2))
    return ''.join(encoded_chars)

def ophone(t):
    key = b'34d7cb0bcdf07523'
    utf8_key = key.decode('utf-8')
    utf8_t = t.encode('utf-8')
    cipher = AES.new(key, AES.MODE_ECB) 
    ciphertext = cipher.encrypt(pad(utf8_t, AES.block_size)) 
    return ciphertext.hex() 

def send(uid,content):
    r = requests.post('https://wxpusher.zjiecode.com/api/send/message',json={"appToken":appToken,"content":content,"contentType":1,"uids":[uid]}).json()
    return r

def userLoginNormal(phone,password):
    alphabet = 'abcdef0123456789'
    uuid = [''.join(random.sample(alphabet, 8)),''.join(random.sample(alphabet, 4)),'4'+''.join(random.sample(alphabet, 3)),''.join(random.sample(alphabet, 4)),''.join(random.sample(alphabet, 12))]
    timestamp=datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    loginAuthCipherAsymmertric = 'iPhone 14 15.4.' + uuid[0] + uuid[1] + phone + timestamp + password[:6] + '0$$$0.'
    
    r = ss.post('https://appgologin.189.cn:9031/login/client/userLoginNormal',json={"headerInfos": {"code": "userLoginNormal", "timestamp": timestamp, "broadAccount": "", "broadToken": "", "clientType": "#9.6.1#channel50#iPhone 14 Pro Max#", "shopId": "20002", "source": "110003", "sourcePassword": "Sid98s", "token": "", "userLoginName": phone}, "content": {"attach": "test", "fieldData": {"loginType": "4", "accountType": "", "loginAuthCipherAsymmertric": b64(loginAuthCipherAsymmertric), "deviceUid": uuid[0] + uuid[1] + uuid[2], "phoneNum": encode_phone(phone), "isChinatelecom": "0", "systemVersion": "15.4.0", "authentication": password}}}).json()

    l = r['responseData']['data']['loginSuccessResult']
    
    if l:
        load_token[phone] = l
        with open(load_token_file, 'w') as f:
            json.dump(load_token, f)
        ticket = get_ticket(phone,l['userId'],l['token']) 
        return ticket
       
    return False

def get_ticket(phone,userId,token):
    r = ss.post('https://appgologin.189.cn:9031/map/clientXML',data='<Request><HeaderInfos><Code>getSingle</Code><Timestamp>'+datetime.datetime.now().strftime("%Y%m%d%H%M%S")+'</Timestamp><BroadAccount></BroadAccount><BroadToken></BroadToken><ClientType>#9.6.1#channel50#iPhone 14 Pro Max#</ClientType><ShopId>20002</ShopId><Source>110003</Source><SourcePassword>Sid98s</SourcePassword><Token>'+token+'</Token><UserLoginName>'+phone+'</UserLoginName></HeaderInfos><Content><Attach>test</Attach><FieldData><TargetId>'+encrypt(userId)+'</TargetId><Url>4a6862274835b451</Url></FieldData></Content></Request>',headers={'user-agent': 'CtClient;10.4.1;Android;13;22081212C;NTQzNzgx!#!MTgwNTg1'})

    tk = re.findall('<Ticket>(.*?)</Ticket>',r.text)
    if len(tk) == 0:        
        return False
    #print(tk)
    return decrypt(tk[0])
    
async def exchange(phone, s, title, aid, uid, amount):
    global h  # 使用全局变量 h
    try:
        tt = time.time()
        start_time = time.time()  # 记录开始时间
        cookies = await datetime_b.get_rs('https://wapact.189.cn:9001/gateway/standExchange/detailNew/exchange', s, md='post')
        end_time = time.time()  # 记录结束时间
        print(f"{phone} 获取到 {title} 的cookies，用时: {end_time - start_time:.3f} 秒")

        # 获取当前时间
        now = datetime.datetime.now()
        print(f"当前时间: {now.strftime('%Y-%m-%d %H:%M:%S')}")

        # 如果 h 没有赋值，则使用当前时间的小时数
        if h is None:
            h = now.hour
        
        target_time = now.replace(hour=h, minute=59, second=59, microsecond=784288)
        
        # 计算目标时间和当前时间的差值
        time_diff = (target_time - now).total_seconds()
        
        # 如果时间差在30秒之内，则等待到目标时间
        if 0 <= time_diff <= 30:
            await asyncio.sleep(time_diff)
        
        tt = time.time()  # 记录请求开始时间
        request_time_str = datetime.datetime.fromtimestamp(tt).strftime('%H:%M:%S.%f')[:-3]
        print(f"{phone} 请求时间: {request_time_str}")

        # 第二次请求
        url = "https://wapact.189.cn:9001/gateway/standExchange/detailNew/exchange"
        
        # 发送兑换请求
        async with s.post(url, json={"activityId": aid}, cookies=cookies) as r:
            # 直接检查状态码
            if r.status == 412:
                print(f"{phone} 兑换请求返回 412，结束本次兑换！")
                return
            print(f"{phone} 响应码: {r.status} {await r.text()}")
            if r.status == 200:
                r_json = await r.json()
                if r_json["code"] == 0:
                    if r_json["biz"] != {} and r_json["biz"]["resultCode"] in errcode:
                        print(f'{str(datetime.datetime.now())[11:22]} {phone} {title} {errcode[r_json["biz"]["resultCode"]]}')

                        if r_json["biz"]["resultCode"] in ["0", "412"]:
                            if r_json["biz"]["resultCode"] == "0":
                                msg = phone + ":" + title + "兑换成功"
                                send(uid, msg)
                            if phone not in dhjl[yf][title]:
                                dhjl[yf][title] += "#" + phone
                                with open('电信金豆换话费.log', 'w') as f:
                                    json.dump(dhjl, f, ensure_ascii=False)
                else:
                    print(f'🌟{str(datetime.datetime.now())[11:22]} {phone} {r_json}')
            else:
                print(f"{phone} 兑换请求失败: {await r.text()}")
            print(time.time() - tt)

        # 打印当前时间
        now = datetime.datetime.now()
        print(f"当前时间: {now.strftime('%Y-%m-%d %H:%M:%S')}")

    except Exception as e:
        print(f"发生错误: {e}")

async def dh(phone, s, title, aid, wt, uid):
    global h  # 使用全局变量 h
    while wt > get_network_time().timestamp():
        await asyncio.sleep(1)
    
    printn(f"💡{str(datetime.datetime.now())[11:22]} {phone} {title} 开始兑换")
    cs = 0
    tasks = []
    while cs < 2:
        # 提取金额
        amount = title.split('元')[0]
        tasks.append(exchange(phone, s, title, aid, uid, amount))      
        cs += 1
        await asyncio.sleep(0.1)

    await asyncio.gather(*tasks)

async def ks(phone, ticket, uid):
    global h, wt  # 使用全局变量 h 和 wt
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Linux; Android 13; 22081212C Build/TKQ1.220829.002) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.97 Mobile Safari/537.36",
        "Referer": "https://wapact.189.cn:9001/JinDouMall/JinDouMall_independentDetails.html"
    }
    
    timeout = aiohttp.ClientTimeout(total=20)  # 设置超时时间
    
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=ssl_context), headers=headers, timeout=timeout) as s:
        cookies = await datetime_b.get_rs('https://wapact.189.cn:9001/gateway/stand/detailNew/exchange', session=s)

        s.cookie_jar.update_cookies(cookies)

        # 登录请求
        max_retries = 3  # 最大重试次数
        retries = 0
        while retries < max_retries:
            try:
                login_response = await s.post(
                    'https://wapact.189.cn:9001/unified/user/login',
                    json={"ticket": ticket, "backUrl": "https%3A%2F%2Fwapact.189.cn%3A9001", "platformCode": "P201010301", "loginType": 2}
                )

                # 处理登录响应
                if login_response.status == 200:
                    login = await login_response.json()
                    break  # 如果成功，跳出循环
                elif login_response.status == 412:
                    print(f"{phone} 登录请求失败，HTTP状态码: {login_response.status}, 直接重新调用 ks 函数...")
                    return await ks(phone, ticket, uid)  # 直接从头开始调用 ks 函数
                else:
                    print(f"{phone} 登录请求失败，HTTP状态码: {login_response.status}")
                    print(f"响应内容: {await login_response.text()}")

            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                retries += 1
                print(f"{phone} 登录请求失败，重试 {retries}/{max_retries}... 错误信息: {e}")
                await asyncio.sleep(2 ** retries)  # 指数退避算法等待时间
                
                if retries == max_retries:
                    print(f"{phone} 登录失败，达到最大重试次数. 尝试重新调用 ks 函数...")
                    return await ks(phone, ticket, uid)  # 递归调用 ks 函数

        if 'login' in locals() and login['code'] == 0:
            s.headers["Authorization"] = "Bearer " + login["biz"]["token"]   

            r = await s.get('https://wapact.189.cn:9001/gateway/golden/api/queryInfo')
            r_json = await r.json()
            print(f'{phone} 金豆余额 {r_json["biz"]["amountTotal"]}')
            
            queryBigDataAppGetOrInfo = await s.get('https://wapact.189.cn:9001/gateway/golden/goldGoods/getGoodsList?floorType=0&userType=1&page=1&order=2&tabOrder=')
            queryBigDataAppGetOrInfo_json = await queryBigDataAppGetOrInfo.json()

            # 检查列表是否为空
            if "biz" in queryBigDataAppGetOrInfo_json and "ExchangeGoodslist" in queryBigDataAppGetOrInfo_json["biz"]:
                for i in queryBigDataAppGetOrInfo_json["biz"]["ExchangeGoodslist"]:
                    if '话费' not in i["title"]:
                        continue
                    
                    if '0.5元' in i["title"] or '5元' in i["title"]:
                        jp["9"][i["title"]] = i["id"]
                    elif '1元' in i["title"] or '10元' in i["title"]:
                        jp["13"][i["title"]] = i["id"]
            else:
                print(f"{phone} 获取兑换商品列表失败")
            
            h = datetime.datetime.now().hour
            if 11 > h:
                h = 9            
            else:
                h = 13
            
            if len(sys.argv) == 2:
                h = int(sys.argv[1])
            
            d = jp[str(h)]
            
            wt = t(h) + kswt
            
            tasks = []
            for di in d:
                if di not in dhjl[yf]:
                    dhjl[yf][di] = ""
                if phone in dhjl[yf][di]:
                    print(f"{phone} {di} 已兑换")
                else:
                    print(f"{phone} {di}")
                    if wt - time.time() > 30 * 60:
                        print("等待时间超过30分钟")
                        return
                    
                    tasks.append(dh(phone, s, di, d[di], wt, uid))
            
            await asyncio.gather(*tasks)
        else:
            print(f"{phone} 获取token失败, 错误信息: {login['message']}")

async def main():
    global wt, rs, h  # 使用全局变量 wt, rs, h
    headers = {
        "User-Agent": "Mozilla/5.0 (Linux; Android 13; 22081212C Build/TKQ1.220829.002) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.97 Mobile Safari/537.36",
        "Referer": "https://wapact.189.cn:9001/JinDouMall/JinDouMall_independentDetails.html"
    }
    
    timeout = aiohttp.ClientTimeout(total=20)  # 设置超时时间
    
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=ssl_context), headers=headers, timeout=timeout) as ss:
        r = await ss.get('https://wapact.189.cn:9001/gateway/stand/detailNew/exchange')

        if '$_ts=window' in await r.text():
            rs = 1
            # first_request()
        else:
            rs = 0

        tasks = []
        for i in chinaTelecomAccount.split('&'):
            i = i.split('@')
            phone = i[0]
            password = i[1]
            uid = i[-1]
            ticket = False
            # ticket = get_userTicket(phone)

            if phone in load_token:
                printn(f'{phone} 使用缓存登录')
                ticket = get_ticket(phone, load_token[phone]['userId'], load_token[phone]['token'])

            if ticket == False:
                printn(f'{phone} 使用密码登录')
                ticket = userLoginNormal(phone, password)

            if ticket:
                tasks.append(ks(phone, ticket, uid))
            else:
                printn(f'{phone} 登录失败')
        # 等待到设定时间
        while wt > get_network_time().timestamp():
            await asyncio.sleep(1)

        await asyncio.gather(*tasks)

appToken = ""

chinaTelecomAccount = os.environ.get('jdhf')

if chinaTelecomAccount:
    if len(sys.argv) > 1:
        h = int(sys.argv[1])
    else:
        h = None  # 默认值为 None
    asyncio.run(main())

# 获取当前月份
current_month = datetime.datetime.now().strftime("%Y%m")

# 读取原始日志文件
try:
    with open('电信金豆换话费.log', 'r') as fr:
        dhjl = json.load(fr)
except FileNotFoundError:
    dhjl = {}

# 初始化新的日志结构
dhjl2 = {}

# 只处理当前月份的数据
if current_month in dhjl:
    records = dhjl[current_month]
    for fee, phones in records.items():
        phone_list = phones.strip('#').split('#')
        for phone in phone_list:
            if phone not in dhjl2:
                dhjl2[phone] = {}
            if current_month not in dhjl2[phone]:
                dhjl2[phone][current_month] = []
            dhjl2[phone][current_month].append(fee)

# 写入新的日志文件
with open('电信金豆换话费2.log', 'w') as fw:
    json.dump(dhjl2, fw, ensure_ascii=False, indent=4)