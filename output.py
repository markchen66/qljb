#2025-02-16 06:44:29
import requests
import time
import hashlib
import random
import uuid
import json
import os
class yuanshen():
 def __init__(self,cookie):
  self.vayne=cookie.split('#')[0]
  self.teemo=cookie.split('#')[1]
  self.token=cookie.split('#')[2]
  self.headers={"Host":"gwh.xiaocantech.com","sec-ch-ua":'"Chromium";v="122", "Not(A:Brand";v="24", "Android WebView";v="122"',"x-version":"3.4.5","x-vayne":f"{self.vayne}","x-platform":"mini","x-annie":"XC","x-city":"440100","x-nami":"","sec-ch-ua-platform":"Android","x-teemo":f"{self.teemo}","sec-ch-ua-mobile":"?1","user-agent":"Mozilla/5.0 (Linux; Android 13; 23054RA19C Build/TP1A.220624.014; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/122.0.6261.120 Mobile Safari/537.36 XWEB/1220053 MMWEBSDK/20240404 MMWEBID/98 MicroMessenger/8.0.49.2600(0x28003133) WeChat/arm64 Weixin NetType/5G Language/zh_CN ABI/arm64 miniProgram/wx52ae177248081591","x-garen":"","content-type":"application/json","accept":"application/json, text/plain, */*","x-sivir":f"{self.token}","servername":"SilkwormLottery","x-ashe":"fbaf2e77defc91f9fd0170697e2cad36","methodname":"SilkwormLotteryMobile.Lottery","origin":"https://gw.djtaoke.cn","x-requested-with":"com.tencent.mm","sec-fetch-site":"cross-site","sec-fetch-mode":"cors","sec-fetch-dest":"empty","referer":"https://gw.djtaoke.cn/","accept-encoding":"gzip, deflate, br","accept-language":"zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7"}
 def g_header(self):
  ruuid=str(uuid.uuid4()).replace('-','')
  part1=ruuid[:4]
  part2=self.teemo
  part3=ruuid[4:20-len(self.teemo)-4]
  h=part1+part2+part3
  self.headers['x-nami']=h
  self.headers['x-garen']=str(int(time.time()*1000))
  def s(input):
   return hashlib.md5(input.encode()).hexdigest()
  self.headers['x-ashe']=s(s((f"{self.headers['servername']}"+"."+f"{self.headers['methodname']}").lower())+self.headers['x-garen']+h)
 def Lottery(self):
  self.headers['methodname']='SilkwormLotteryMobile.Lottery'
  self.g_header()
  url="https://gwh.xiaocantech.com/rpc"
  data={"silk_id":int(self.teemo),"prize_type":1}
  data=json.dumps(data,separators=(',',':'))
  r=requests.post(url,headers=self.headers,data=data).json()
  if r['status']['code']==0:
   print(f"抽奖成功,获得---[{r['prize']['name']}]")
   return True
  else:
   print(f"抽奖失败---[{r['status']['msg']}]")
   return False
 def task(self,id):
  self.headers['methodname']='SilkwormLotteryMobile.AddLotteryTimes'
  self.g_header()
  url="https://gwh.xiaocantech.com/rpc"
  data={"silk_id":int(self.teemo),"type":int(id)}
  data=json.dumps(data,separators=(',',':'))
  r=requests.post(url,headers=self.headers,data=data).json()
  if r['status']['code']==0:
   print(f"任务id[{id}]完成成功,抽奖次数+1")
   return True
  else:
   print(f"任务id[{id}]完成失败---[{r['status']['msg']}]")
   return False
 def main(self):
  if bug:
   i=0
   self.task(1)
   while True:
    i+=1
    if not self.task(3):
     break
    if i>=20:
     break
    time.sleep(10)
  else:
   self.task(1)
   time.sleep(10)
   self.task(2)
  while True:
   if not self.Lottery():
    break
   time.sleep(random.randint(5,10))
if __name__=='__main__':
 cookie=''
 if not cookie:
  cookie=os.getenv("yuanshen_xcplus")
  if not cookie:
   print("请设置环境变量:yuanshen_xcplus")
   exit()
 cookies=cookie.split("@")
 print(f"一共获取到{len(cookies)}个账号")
 i=1
 for cookie in cookies:
  print(f"\n--------开始第{i}个账号--------")
  main=yuanshen(cookie)
  main.main()
  print(f"--------第{i}个账号执行完毕--------")
  time.sleep(20)
  i+=1
