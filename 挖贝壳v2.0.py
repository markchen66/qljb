#更新：贝壳领取确认，直接替换掉原来的脚本就行
#入口：https://shellscoin.com/h5/#/pages/loginregister/register?invite_code=MjM3NTg=&langCode=zh-Hant
#定时：每天一次。
#变量：shells_coin
#格式：email#passport
# qq:482550471，备注来意

print("☞☞☞ 挖贝壳币 ☜☜☜\n")

import requests
import time

def ming(token):

    tokenn = token
    headers = {

        "Host": "shellscoin.com",
        "Connection": "keep-alive",
        "Content-Length": "63",
        "sec-ch-ua-platform": "Windows",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36 Edg/132.0.0.0",
        "sec-ch-ua": '"Chromium";v="134", "Not:A-Brand";v="24", "Microsoft Edge";v="134"',
        "content-type": "application/json",
        "token": token,
        "sec-ch-ua-mobile": "?0",
        "Accept": "*/*",
        "Origin": "https://shellscoin.com",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
        "Referer": "https://shellscoin.com/h5/",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
        "Cookie": "think_var=zh-tw"
    }

    # 提现
    url = f'https://shellscoin.com/api/mining/mining'
    data = '{"token":"' + tokenn + '","lang":"zh-tw"}'

    response = requests.post(url=url, headers=headers, data=data, timeout=5).json()
    print("📧开始挖贝壳！")
    return response['code']


def login(email,passport):
    headers = {
                    "Host": "shellscoin.com",
                    "Connection": "keep-alive",
                    "Content-Length": "72",
                    "sec-ch-ua-platform": "Windows",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36 Edg/132.0.0.0",
                    "sec-ch-ua": '"Chromium";v="134", "Not:A-Brand";v="24", "Microsoft Edge";v="134"',
                    "content-type": "application/json",
                    "token": "",
                    "sec-ch-ua-mobile": "?0",
                    "Accept": "*/*",
                    "Origin": "https://shellscoin.com",
                    "Sec-Fetch-Site": "same-origin",
                    "Sec-Fetch-Mode": "cors",
                    "Sec-Fetch-Dest": "empty",
                    "Referer": "https://shellscoin.com/h5/",
                    "Accept-Encoding": "gzip, deflate, br, zstd",
                    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
                    "Cookie": "think_var=zh-tw"
                }


    #提现
    url = f'https://shellscoin.com/api/user/login'
    data='{"username": "'+ email +'","password": "'+passport+'","lang": "zh-tw"}'

    response = requests.post(url=url, headers=headers, data=data, timeout=5).json()
    print(response)
    if response['msg'] == "Logged in successful":
        print("✅登录成功")
        uu = float(response['data']['userinfo']['money'])/10
        print("🔥账户余额：", uu," usdt")
    return response['data']['userinfo']['token']


def checkout(token):
    headers = {
        "Host": "shellscoin.com",
        "Connection": "keep-alive",
        "Content-Length": "72",
        "sec-ch-ua-platform": "Windows",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36 Edg/132.0.0.0",
        "sec-ch-ua": '"Not A(Brand";v="8", "Chromium";v="132", "Microsoft Edge";v="132"',
        "content-type": "application/json",
        "token": token,
        "sec-ch-ua-mobile": "?0",
        "Accept": "*/*",
        "Origin": "https://shellscoin.com",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
        "Referer": "https://shellscoin.com/h5/",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
        "Cookie": "think_var=zh-tw"
    }

    # 提现
    url = f'https://shellscoin.com/api/mining/checkout'
    data = '{"token": "' + token + '","lang": "zh-tw"}'

    response = requests.post(url=url, headers=headers, data=data, timeout=5).json()
    print("✅贝壳领取成功")

requests.KeepAlive = True

fen = os.environ.get("shells_coin").split("#")

email = fen[0]
passport = fen[1]

token = login(email,passport)
checkout(token)
ming(token)
