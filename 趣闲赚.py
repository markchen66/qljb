import requests, json, re, os, sys, time, random, datetime, threading, execjs
environ = "qxz"#备注#CK
session = requests.session()
response = requests.get("https://mkjt.jdmk.xyz/mkjt.txt")
response.encoding = 'utf-8'
txt = response.text
print(txt)

def run(arg1,arg2):
    header = {
        "Host": "wap.huayingrc.com",
        "accept": "application/json",
        "content-type": "application/x-www-form-urlencoded",
        "User-Agent": "Mozilla/5.0 (Linux; Android 10; MI 8 Build/QKQ1.190828.002; ) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/83.0.4103.101 Mobile Safari/537.36  XiaoMi/MiuiBrowser/10.8.1 LT-APP/46/225",
        "cookie": f"tzb_formhash_cookie={arg1};tzb_user_cryptograph={arg2}"
    }
    try:
        url = 'https://wap.huayingrc.com/user/fen/receive/'
        data = f"double=0&formhash={arg1}&inajax=1"
        response = session.post(url=url, headers=header, data=data).json()
        print(f"☁️{response['msg']}")
    except Exception as e:
        print(e)

def main():
    if os.environ.get(environ):
        ck = os.environ.get(environ)
    else:
        #ck = ""
        if ck == "":
            print("⭕请设置变量")
            sys.exit()
    ck_run = ck.split('\n')
    ck_run = [item for item in ck_run if item]
    print(f"{' ' * 7}꧁༺ 趣闲༒赚 ༻꧂\n\n")
    for i, ck_run_n in enumerate(ck_run):
        try:
            id,arg1,arg2 = ck_run_n.split('#',2)
            print(f'\n----------- 🍺账号【{i + 1}/{len(ck_run)}】执行🍺 -----------')
            print(f"☁️当前账号：{id}")
            run(arg1, arg2)
        except Exception as e:
            print(e)
    print(f"\n\n-------- ☁️ 执 行  结 束 ☁️ --------\n\n")
if __name__ == '__main__':
    main()