#打开抓包软件,进入提现后选择需要提现的金额然后发送验证码过了验证后5分钟内抓https://integralapi.kuwo.cn/api/v1/online/sign/v1/getWithdraw这个域名下整个URL就是值。注:有效期只有5分钟过期重抓否则无效
#定时55 59 8,12,16,19,23 * * *
import requests
import datetime
import random
import time
import re
import os,threading,sys
import concurrent.futures
response = requests.get("https://mkjt.jdmk.xyz/mkjt.txt")
response.encoding = 'utf-8'
txt = response.text
print(txt)


def tx(url):
    url = url
    headers = {
        "User-Agent": "Mozilla/5.0 (Linux; Android 10; MI 8 Build/QKQ1.190828.002; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/83.0.4103.101 Mobile Safari/537.36/ kuwopage",
        "Host": "integralapi.kuwo.cn",
        "Connection": "keep-alive",
        "sec-ch-ua": '"Not A(Brand";v="99", "Android WebView";v="121", "Chromium";v="121"',
        "Accept": "application/json, text/plain, */*",
        "Origin": "https://h5app.kuwo.cn",
        "X-Requested-With": "cn.kuwo.player",
        "Sec-Fetch-Site": "same-site",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
        "Accept-Encoding": "gzip, deflate",
        "Accept-Language": "zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7"
    }
    mmm = 0
    for _ in range(1000):
        response = requests.get(url, headers=headers).json()
        sleept = int(time.time())-int(response['curTime']/1000)
        description = response['data']['text']
        print(f"☁️兑换：{description}")
        if "您的余额不足" in description or '已领取' in description:
            break
        elif "成功" in description:
            break
        elif "用户未登录" in description:
            break
        time.sleep(0.1)

def main():
    name = "酷我༒提现"
    environ = 'kwyytx'
    if os.environ.get(environ):
        ck = os.environ.get(environ)
    else:
        ck = ""
        if ck == "":
            print("请设置变量")
            sys.exit()
    ck_run = ck.split('\n')
    ck_run = [item for item in ck_run if item]
    print(f"{' ' * 10}꧁༺ {name} ༻꧂\n")
    for i, ck_run_n in enumerate(ck_run):
        threads = []
        for _ in range(2):
            thread = threading.Thread(target=tx, args=(ck_run_n,))
            threads.append(thread)
            thread.start()
            time.sleep(0.01)
        for thread in threads:
            thread.join()
    print(f'\n----------- 🎊 执 行  结 束 🎊 -----------')

if __name__ == '__main__':
    main()