# -*- coding: utf-8 -*-
'''
依赖:bs4，requests，PyExecJs，pycryptodome
变量chinaTelecomAccount 值手机号#服务密码
'''
import requests
import re
import time
import json
import random
import datetime
import base64
import threading
import ssl
import execjs
import os
import sys
import urllib3

from bs4 import BeautifulSoup

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
from http import cookiejar  # Python 2: import cookielib as cookiejar
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.ssl_ import create_urllib3_context

# =================== 并发相关 ===================
from concurrent.futures import ThreadPoolExecutor, as_completed

# =========== 你原脚本中的 SSL/TLS 思路，但进一步强制 SECLEVEL=0 ============
class DESAdapter(HTTPAdapter):
    """
    A TransportAdapter that re-enables 3DES/低安全握手, 并在直连和代理时都使用 SECLEVEL=0.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def init_poolmanager(self, *args, **kwargs):
        context = self._create_weak_ssl_context()
        kwargs['ssl_context'] = context
        return super(DESAdapter, self).init_poolmanager(*args, **kwargs)

    def proxy_manager_for(self, *args, **kwargs):
        context = self._create_weak_ssl_context()
        kwargs['ssl_context'] = context
        return super(DESAdapter, self).proxy_manager_for(*args, **kwargs)

    def _create_weak_ssl_context(self):
        """
        创建一个尽量宽松的 SSLContext, 避免 "DH_KEY_TOO_SMALL" 和 "No cipher can be selected."
        """
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        # 如果 Python/ssl 版本支持 IGNORE_UNSAFE_LEGACY_RENEGOTIATION, 则加上
        if hasattr(ssl, "OP_IGNORE_UNSAFE_LEGACY_RENEGOTIATION"):
            ctx.options |= ssl.OP_IGNORE_UNSAFE_LEGACY_RENEGOTIATION

        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        # 强行使用 SECLEVEL=0, 尽量兼容弱 DH
        ctx.set_ciphers("DEFAULT@SECLEVEL=0")

        return ctx

# 全局禁用警告
requests.packages.urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 全局 session
ss = requests.session()
ss.verify = False
ss.headers = {
    "User-Agent": "Mozilla/5.0 (Linux; Android 13; 22081212C Build/TKQ1.220829.002) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.97 Mobile Safari/537.36",
    "Referer": "https://wapact.189.cn:9001/JinDouMall/JinDouMall_independentDetails.html"
}
ss.mount('https://', DESAdapter())  # 用自定义的 DESAdapter

class BlockAll(cookiejar.CookiePolicy):
    return_ok = set_ok = domain_return_ok = path_return_ok = lambda self, *args, **kwargs: False
    netscape = True
    rfc2965 = hide_cookie2 = False

# ============ 新增日志函数 + 保留printn调用 =============
def log_print(msg):
    now_str = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f"[{now_str}] {msg}")

def printn(m):
    log_print(m)

# ============ 新增代理池相关变量 =============
proxy_status = '0'  # 0=关闭，1=启用
proxy_addr = ''     # 若启用时在此写形如 http://IP:PORT

def get_proxies():
    """
    0=关闭(直连)，1=启用代理池
    当 proxy_status 不是 '0'/'1'，或 proxy_addr 不合法，均视为直连
    """
    if proxy_status not in ['0','1']:
        return None
    if proxy_status == '0':
        return None
    addr = proxy_addr.strip()
    if not addr:
        return None
    if not (addr.startswith('http://') or addr.startswith('https://')):
        return None
    return {
        'http': addr,
        'https': addr
    }

yc = 0.1
wt = 0
kswt = -3
yf = datetime.datetime.now().strftime("%Y%m")

jp = {"9":{},"12":{},"13":{},"23":{}}

try:
    with open('电信金豆换话费.log','r',encoding='utf-8') as fr:
        dhjl = json.load(fr)
except:
    dhjl = {}
if yf not in dhjl:
    dhjl[yf] = {}

wxp = {}
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

# 保留原有加密参数
key = b'1234567`90koiuyhgtfrdews'
iv = 8 * b'\0'

public_key_b64 = '''-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDBkLT15ThVgz6/NOl6s8GNPofdWzWbCkWnkaAm7O2LjkM1H7dMvzkiqdxU02jamGRHLX/ZNMCXHnPcW/sDhiFCBN18qFvy8g6VYb9QtroI09e176s+ZCtiv7hbin2cCTj99iUpnEloZm19lwHyo69u5UMiPMpq0/XKBO8lYhN/gwIDAQAB
-----END PUBLIC KEY-----'''

public_key_data = '''-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC+ugG5A8cZ3FqUKDwM57GM4io6JGcStivT8UdGt67PEOihLZTw3P7371+N47PrmsCpnTRzbTgcupKtUv8ImZalYk65dU8rjC/ridwhw9ffW2LBwvkEnDkkKKRi2liWIItDftJVBiWOh17o6gfbPoNrWORcAdcbpk2L+udld5kZNwIDAQAB
-----END PUBLIC KEY-----'''

def t(h):
    date = datetime.datetime.now()
    date_zero = date.replace(hour=h, minute=59, second=59, microsecond=0)
    return int(time.mktime(date_zero.timetuple()))

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
    return ''.join(chr(ord(c)+2) for c in text)

def ophone(txt):
    key2 = b'34d7cb0bcdf07523'
    cipher = AES.new(key2, AES.MODE_ECB)
    ciphertext = cipher.encrypt(pad(txt.encode('utf-8'), AES.block_size))
    return ciphertext.hex()

def send(uid, content):
    try:
        # 若想走代理，可传 proxies=get_proxies()
        r = requests.post(
            'https://wxpusher.zjiecode.com/api/send/message',
            json={
                "appToken": "AT_3hr0wdZn5QzPNBbpTHFXawoDIsSUmPkN",
                "content": content,
                "contentType": 1,
                "uids": [uid]
            },
            verify=False
        )
        return r.json()
    except:
        return None

def userLoginNormal(phone,password):
    alphabet = 'abcdef0123456789'
    uuid = [
        ''.join(random.sample(alphabet,8)),
        ''.join(random.sample(alphabet,4)),
        '4'+''.join(random.sample(alphabet,3)),
        ''.join(random.sample(alphabet,4)),
        ''.join(random.sample(alphabet,12))
    ]
    timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    loginAuthCipherAsymmertric = 'iPhone 14 15.4.' + uuid[0] + uuid[1] + phone + timestamp + password[:6] + '0$$$0.'

    try:
        r = ss.post(
            'https://appgologin.189.cn:9031/login/client/userLoginNormal',
            json={
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
                        "deviceUid": uuid[0]+uuid[1]+uuid[2],
                        "phoneNum": encode_phone(phone),
                        "isChinatelecom": "0",
                        "systemVersion": "15.4.0",
                        "authentication": password
                    }
                }
            },
            verify=False
        )
        if not r:
            printn(f"{phone} 登录失败(无响应)")
            return False
        j = r.json()
        printn(f"登录响应: {j}")
        if 'responseData' not in j or 'data' not in j['responseData'] or 'loginSuccessResult' not in j['responseData']['data']:
            printn("登录失败: 数据结构不正确")
            return False
        l = j['responseData']['data']['loginSuccessResult']
        if l:
            load_token[phone] = l
            with open(load_token_file,'w',encoding='utf-8') as ff:
                json.dump(load_token, ff)
            ticket = get_ticket(phone,l['userId'],l['token'])
            return ticket
    except Exception as e:
        printn(f"{phone} 登录异常: {e}")
    return False

def get_ticket(phone, userId, token):
    r = ss.post(
        'https://appgologin.189.cn:9031/map/clientXML',
        data=(
            '<Request><HeaderInfos><Code>getSingle</Code><Timestamp>'
            + datetime.datetime.now().strftime("%Y%m%d%H%M%S")
            + '</Timestamp><BroadAccount></BroadAccount><BroadToken></BroadToken>'
            + '<ClientType>#9.6.1#channel50#iPhone 14 Pro Max#</ClientType>'
            + '<ShopId>20002</ShopId><Source>110003</Source><SourcePassword>Sid98s</SourcePassword>'
            + '<Token>'+token+'</Token><UserLoginName>'+phone+'</UserLoginName>'
            +'</HeaderInfos><Content><Attach>test</Attach><FieldData><TargetId>'
            + encrypt(userId)
            +'</TargetId><Url>4a6862274835b451</Url></FieldData></Content></Request>'
        ),
        headers={'user-agent':'CtClient;10.4.1;Android;13;22081212C;NTQzNzgx!#!MTgwNTg1'},
        verify=False
    )
    if not r:
        return False
    tk = re.findall('<Ticket>(.*?)</Ticket>', r.text)
    if not tk:
        return False
    return decrypt(tk[0])

def queryInfo(phone, s):
    global rs
    a = 1
    while a < 10:
        if rs:
            bd = js.call('main').split('=')
            ck[bd[0]] = bd[1]
        r = s.get('https://wapact.189.cn:9001/gateway/golden/api/queryInfo', cookies=ck, verify=False)
        if not r:
            time.sleep(2)
            a += 1
            continue
        try:
            info = r.json()
            printn(f"{phone} 金豆余额 {info['biz']['amountTotal']}")
            amountTotal = info["biz"]["amountTotal"]
        except:
            amountTotal = 0
        if amountTotal < 3000:
            if rs==1:
                bd = js.call('main').split('=')
                ck[bd[0]] = bd[1]
            rr = s.post('http://wapact.189.cn:9000/gateway/stand/detail/exchange', json={"activityId":jdaid}, cookies=ck, verify=False)
            if rr and '$_ts=window' in rr.text:
                first_request()
                rs = 1
            time.sleep(3)
        else:
            return info
        a += 1
    return {}

def exchange(phone, s, title, aid, uid):
    try:
        bd = js.call('main').split('=')
        ck[bd[0]] = bd[1]
        r = s.post('https://wapact.189.cn:9001/gateway/standExchange/detailNew/exchange', json={"activityId":aid}, cookies=ck, verify=False)
        if not r:
            printn(f"{phone} {title} => 无响应")
            return False
        if '$_ts=window' in r.text:
            first_request(r.text)
            return False
        j = r.json()
        if j["code"]==0:
            if j["biz"] and "resultCode" in j["biz"] and j["biz"]["resultCode"] in errcode:
                rc = j["biz"]["resultCode"]
                printn(f"{phone} {title} => {errcode[rc]}")
                if rc in ["0","412"]:
                    if rc=="0":
                        send(uid, f"{phone}:{title}兑换成功")
                    if phone not in dhjl[yf][title]:
                        dhjl[yf][title] += "#"+phone
                        with open('电信金豆换话费.log','w',encoding='utf-8') as ff:
                            json.dump(dhjl, ff, ensure_ascii=False)
                    return True
            else:
                printn(f"{phone} {title} => 未知结构 {j}")
        else:
            printn(f"{phone} {title} => {j['message']}")
    except Exception as e:
        printn(f"{phone} {title} exchange异常: {e}")
    return False

def dh(phone,s,title,aid, wait_ts, uid):
    while time.time() < wait_ts:
        time.sleep(0.1)
    printn(f"{phone} {title} 开始并发抢兑")
    for i in range(30):
        ok = exchange(phone,s,title,aid,uid)
        if ok:
            printn(f"{phone} {title} 第{i+1}次成功 => 停止")
            return
        time.sleep(0.02)
    printn(f"{phone} {title} => 30次均失败")

def lottery(s):
    for cishu in range(3):
        try:
            if rs:
                bd = js.call('main').split('=')
                ck[bd[0]] = bd[1]
            s.post('https://wapact.189.cn:9001/gateway/golden/api/lottery', json={"activityId":"6384b49b1e44396da4f1e4a3"}, cookies=ck, verify=False)
        except:
            pass
        time.sleep(3)

def ks(phone, ticket, uid):
    global wt
    wxp[phone] = uid
    s = requests.session()
    s.verify = False
    s.headers = {
        "User-Agent":"Mozilla/5.0 (Linux; Android 13; 22081212C Build/TKQ1.220829.002) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.97 Mobile Safari/537.36",
        "Referer":"https://wapact.189.cn:9001/JinDouMall/JinDouMall_independentDetails.html"
    }
    s.cookies.set_policy(BlockAll())
    s.mount('https://', DESAdapter())

    if rs:
        bd = js.call('main').split('=')
        ck[bd[0]] = bd[1]

    login = s.post('https://wapact.189.cn:9001/unified/user/login', json={"ticket":ticket,"backUrl":"https%3A%2F%2Fwapact.189.cn%3A9001","platformCode":"P201010301","loginType":2}, cookies=ck, verify=False)
    jj = login.json()
    if jj["code"]==0:
        printn(f"{phone} 获取token成功")
        s.headers["Authorization"] = "Bearer " + jj["biz"]["token"]
        queryInfo(phone,s)

        if rs:
            bd = js.call('main').split('=')
            ck[bd[0]] = bd[1]

        r2 = s.get('https://wapact.189.cn:9001/gateway/golden/api/queryBigDataAppGetOrInfo?floorType=0&userType=1&page&1&order=2&tabOrder=', cookies=ck, verify=False)
        data2 = r2.json()
        for it in data2["biz"]["ExchangeGoodslist"]:
            if '话费' not in it["title"]:
                continue
            if '0.5元' in it["title"] or '5元' in it["title"]:
                jp["9"][it["title"]] = it["id"]
            elif '1元' in it["title"] or '10元' in it["title"]:
                jp["13"][it["title"]] = it["id"]
            else:
                jp["12"][it["title"]] = it["id"]

        h = datetime.datetime.now().hour
        if 11>h>1:
            h=9
        elif 23>h>1:
            h=13
        else:
            h=23
        if len(sys.argv)==2:
            h=int(sys.argv[1])

        d = jp[str(h)]
        global_wt = t(h)+kswt
        if jp["12"]!={}:
            d.update(jp["12"])
            global_wt=0

        for di in d:
            if di not in dhjl[yf]:
                dhjl[yf][di] = ""
            if phone in dhjl[yf][di]:
                printn(f"{phone} {di} 已兑换")
            else:
                printn(f"{phone} 即将抢兑 {di}")
                dh(phone,s,di,d[di],global_wt,uid)
    else:
        printn(f"{phone} 获取token失败 => {jj['message']}")

def first_request(res=''):
    global js, fw
    url = 'https://wapact.189.cn:9001/gateway/stand/detail/exchange'
    if not res:
        response = ss.get(url)
        res = response.text

    soup = BeautifulSoup(res, 'html.parser')
    scripts = soup.find_all('script')
    rsurl = None
    ts_code = ''
    for script in scripts:
        if 'src' in str(script):
            rsurl = re.findall('src="([^"]+)"', str(script))
            if rsurl:
                rsurl = rsurl[0]
        if '$_ts=window' in script.get_text():
            ts_code = script.get_text()

    if rsurl:
        base_part = url.split('/')
        rsurl2 = base_part[0] + '//' + base_part[2] + rsurl
        r2 = ss.get(rsurl2)
        ts_code += r2.text

    content_code = soup.find_all('meta')[1].get('content')
    with open("瑞数通杀.js",'r',encoding='utf-8') as f:
        js_code_ym = f.read()
    js_code = js_code_ym.replace('content_code', content_code).replace("'ts_code'", ts_code)
    jsc = execjs.compile(js_code)
    global js
    js = jsc

    for cookie in ss.cookies:
        ck[cookie.name] = cookie.value
    return content_code, ts_code, ck

def main():
    global wt, rs
    # 判断瑞数
    # 这里如果启用代理池，则可以这么写:
    # r = requests.get('https://wapact.189.cn:9001/gateway/stand/detailNew/exchange', proxies=get_proxies(), verify=False)
    r = ss.get('https://wapact.189.cn:9001/gateway/stand/detailNew/exchange', verify=False)
    if '$_ts=window' in r.text:
        rs=1
        printn("瑞数加密已开启")
        first_request()
    else:
        printn("瑞数加密已关闭")
        rs=0

    if os.environ.get('chinaTelecomAccount'):
        cta = os.environ['chinaTelecomAccount']
    else:
        cta = chinaTelecomAccount

    GLOBAL_CONCURRENCY = 10
    pool = ThreadPoolExecutor(max_workers=GLOBAL_CONCURRENCY)
    futures = []

    for line in cta.split('&'):
        arr = line.split('#')
        phone = arr[0]
        password = arr[1]
        uid = arr[-1]
        ticket = False
        if phone in load_token:
            printn(f"{phone} 使用缓存登录")
            ticket = get_ticket(phone, load_token[phone]['userId'], load_token[phone]['token'])

        if not ticket:
            printn(f"{phone} 使用密码登录")
            ticket = userLoginNormal(phone, password)

        if ticket:
            fut = pool.submit(ks, phone, ticket, uid)
            futures.append(fut)
        else:
            printn(f"{phone} 登录失败")

    for f in as_completed(futures):
        _ = f.result()

    printn("所有账号预处理完成，脚本结束。")

chinaTelecomAccount = ""
cfcs = 7
jdaid = '60dd79533dc03d3c76bdde30'
ck = {}
load_token_file = 'chinaTelecom_cache.json'
try:
    with open(load_token_file,'r',encoding='utf-8') as ff:
        load_token = json.load(ff)
except:
    load_token = {}

if __name__=="__main__":
    main()
