 
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
甬音自动任务脚本
功能：听音频、抽奖、提现到支付宝
"""

import requests
import time
import random
import os
import json
from datetime import datetime

class YongYin:
    def __init__(self):
        self.session = requests.Session()
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 MicroMessenger/8.0.10(0x18000a2a) NetType/WIFI Language/zh_CN',
            'Referer': 'https://yyapp.nbyongyin.com/',
            'Origin': 'https://yyapp.nbyongyin.com'
        }
        self.token = None
        self.user_info = None
        self.points = 0
        self.balance = 0.0

    def login(self, phone, password):
        """登录甬音APP"""
        print("\n正在登录账号...")
        url = 'https://yyapp.nbyongyin.com/api/user/login'
        data = {
            'phone': phone,
            'password': password,
            'platform': 'wechat'
        }
        try:
            response = self.session.post(url, headers=self.headers, data=data, timeout=10)
            result = response.json()
            if result.get('code') == 200:
                self.token = result.get('data').get('token')
                self.headers['Authorization'] = f'Bearer {self.token}'
                self.user_info = result.get('data')
                print(f"✅ 登录成功: {self.user_info.get('nickname')}")
                return True
            else:
                print(f"❌ 登录失败: {result.get('msg')}")
                return False
        except Exception as e:
            print(f"❌ 登录请求异常: {str(e)}")
            return False

    def get_user_info(self):
        """获取用户信息"""
        url = 'https://yyapp.nbyongyin.com/api/user/info'
        try:
            response = self.session.get(url, headers=self.headers, timeout=10)
            result = response.json()
            if result.get('code') == 200:
                self.user_info = result.get('data')
                self.points = self.user_info.get('points', 0)
                self.balance = float(self.user_info.get('balance', 0))
                print(f"\n👤 用户信息:")
                print(f"昵称: {self.user_info.get('nickname')}")
                print(f"当前积分: {self.points}")
                print(f"当前余额: {self.balance}元")
                return True
            else:
                print(f"❌ 获取用户信息失败: {result.get('msg')}")
                return False
        except Exception as e:
            print(f"❌ 获取用户信息异常: {str(e)}")
            return False

    def get_audio_list(self):
        """获取音频列表"""
        print("\n正在获取音频列表...")
        url = 'https://yyapp.nbyongyin.com/api/audio/list'
        params = {
            'page': 1,
            'size': 10,
            'type': 'recommend'
        }
        try:
            response = self.session.get(url, headers=self.headers, params=params, timeout=10)
            result = response.json()
            if result.get('code') == 200:
                print(f"✅ 获取到{len(result.get('data').get('list'))}个音频")
                return result.get('data').get('list')
            else:
                print(f"❌ 获取音频列表失败: {result.get('msg')}")
                return []
        except Exception as e:
            print(f"❌ 获取音频列表异常: {str(e)}")
            return []

    def listen_audio(self, audio_id, title, duration=30):
        """模拟听音频"""
        print(f"\n🎧 正在听音频: {title}")
        url = 'https://yyapp.nbyongyin.com/api/audio/listen'
        data = {
            'audio_id': audio_id,
            'duration': duration  # 模拟听音频的时长(秒)
        }
        try:
            # 模拟真实听音频的延迟
            sleep_time = random.randint(5, 10)
            print(f"⏳ 模拟听音频中(约{sleep_time}秒)...")
            time.sleep(sleep_time)
            
            response = self.session.post(url, headers=self.headers, data=data, timeout=15)
            result = response.json()
            if result.get('code') == 200:
                points = result.get('data', {}).get('points', 0)
                print(f"✅ 听音频成功: 获得{points}积分")
                self.points += points
                return True
            else:
                print(f"❌ 听音频失败: {result.get('msg')}")
                return False
        except Exception as e:
            print(f"❌ 听音频请求异常: {str(e)}")
            return False

    def get_daily_tasks(self):
        """获取每日任务"""
        print("\n正在获取每日任务...")
        url = 'https://yyapp.nbyongyin.com/api/task/daily'
        try:
            response = self.session.get(url, headers=self.headers, timeout=10)
            result = response.json()
            if result.get('code') == 200:
                print("✅ 获取每日任务成功")
                return result.get('data')
            else:
                print(f"❌ 获取每日任务失败: {result.get('msg')}")
                return None
        except Exception as e:
            print(f"❌ 获取每日任务异常: {str(e)}")
            return None

    def complete_task(self, task_id, task_name):
        """完成任务"""
        print(f"\n🏆 正在完成任务: {task_name}")
        url = 'https://yyapp.nbyongyin.com/api/task/complete'
        data = {
            'task_id': task_id
        }
        try:
            response = self.session.post(url, headers=self.headers, data=data, timeout=10)
            result = response.json()
            if result.get('code') == 200:
                points = result.get('data', {}).get('points', 0)
                print(f"✅ 完成任务成功: 获得{points}积分")
                self.points += points
                return True
            else:
                print(f"❌ 完成任务失败: {result.get('msg')}")
                return False
        except Exception as e:
            print(f"❌ 完成任务请求异常: {str(e)}")
            return False

    def check_lottery_status(self):
        """检查抽奖状态"""
        print("\n正在检查抽奖资格...")
        url = 'https://yyapp.nbyongyin.com/api/lottery/status'
        try:
            response = self.session.get(url, headers=self.headers, timeout=10)
            result = response.json()
            if result.get('code') == 200:
                print("✅ 获取抽奖状态成功")
                return result.get('data')
            else:
                print(f"❌ 获取抽奖状态失败: {result.get('msg')}")
                return None
        except Exception as e:
            print(f"❌ 获取抽奖状态异常: {str(e)}")
            return None

    def participate_lottery(self):
        """参与抽奖"""
        print("\n🎰 正在参与抽奖...")
        url = 'https://yyapp.nbyongyin.com/api/lottery/participate'
        try:
            response = self.session.post(url, headers=self.headers, timeout=10)
            result = response.json()
            if result.get('code') == 200:
                prize = result.get('data', {}).get('prize', '谢谢参与')
                print(f"🎉 抽奖结果: {prize}")
                return True
            else:
                print(f"❌ 抽奖失败: {result.get('msg')}")
                return False
        except Exception as e:
            print(f"❌ 抽奖请求异常: {str(e)}")
            return False

    def check_withdraw_rules(self):
        """检查提现规则"""
        print("\n正在检查提现规则...")
        url = 'https://yyapp.nbyongyin.com/api/withdraw/rules'
        try:
            response = self.session.get(url, headers=self.headers, timeout=10)
            result = response.json()
            if result.get('code') == 200:
                print("✅ 获取提现规则成功")
                return result.get('data')
            else:
                print(f"❌ 获取提现规则失败: {result.get('msg')}")
                return None
        except Exception as e:
            print(f"❌ 获取提现规则异常: {str(e)}")
            return None

    def bind_alipay(self, alipay_account, real_name):
        """绑定支付宝账号"""
        print("\n正在绑定支付宝账号...")
        url = 'https://yyapp.nbyongyin.com/api/user/bind_alipay'
        data = {
            'alipay_account': alipay_account,
            'real_name': real_name
        }
        try:
            response = self.session.post(url, headers=self.headers, data=data, timeout=10)
            result = response.json()
            if result.get('code') == 200:
                print("✅ 绑定支付宝成功")
                return True
            else:
                print(f"❌ 绑定支付宝失败: {result.get('msg')}")
                return False
        except Exception as e:
            print(f"❌ 绑定支付宝请求异常: {str(e)}")
            return False

    def withdraw_to_alipay(self, amount):
        """提现到支付宝"""
        print(f"\n💰 正在申请提现 {amount} 元到支付宝...")
        url = 'https://yyapp.nbyongyin.com/api/withdraw/apply'
        data = {
            'amount': amount,
            'type': 'alipay'
        }
        try:
            response = self.session.post(url, headers=self.headers, data=data, timeout=10)
            result = response.json()
            if result.get('code') == 200:
                print(f"✅ 提现申请成功: {result.get('msg')}")
                return True
            else:
                print(f"❌ 提现申请失败: {result.get('msg')}")
                return False
        except Exception as e:
            print(f"❌ 提现请求异常: {str(e)}")
            return False

    def run(self):
        """执行自动任务"""
        # 从环境变量获取账号信息
        phone = os.getenv('YY_PHONE')
        password = os.getenv('YY_PASSWORD')
        alipay_account = os.getenv('YY_ALIPAY_ACCOUNT')
        real_name = os.getenv('YY_REAL_NAME')
        
        if not phone or not password:
            print("❌ 请设置环境变量YY_PHONE和YY_PASSWORD")
            return

        # 登录
        if not self.login(phone, password):
            return

        # 获取用户信息
        self.get_user_info()

        # 获取音频列表
        audio_list = self.get_audio_list()
        if audio_list:
            # 听前3个音频
            for i in range(min(3, len(audio_list))):
                audio = audio_list[i]
                self.listen_audio(audio.get('id'), audio.get('title'))
                time.sleep(random.randint(1, 3))

        # 获取每日任务
        tasks = self.get_daily_tasks()
        if tasks:
            # 尝试完成听音频相关任务
            for task in tasks:
                if not task.get('completed') and '听音频' in task.get('name'):
                    self.complete_task(task.get('id'), task.get('name'))
                    time.sleep(1)

        # 检查抽奖状态
        lottery_status = self.check_lottery_status()
        if lottery_status and lottery_status.get('can_participate'):
            # 参与抽奖
            self.participate_lottery()
        else:
            print("\n😞 当前没有抽奖资格或抽奖机会已用完")

        # 更新用户信息
        self.get_user_info()

        # 提现功能
        if self.balance >= 10:  # 假设最低提现金额为10元
            # 检查提现规则
            rules = self.check_withdraw_rules()
            if rules:
                min_amount = float(rules.get('min_amount', 10))
                if self.balance >= min_amount:
                    # 绑定支付宝（如果需要）
                    if alipay_account and real_name:
                        self.bind_alipay(alipay_account, real_name)
                    
                    # 申请提现
                    self.withdraw_to_alipay(min_amount)
                else:
                    print(f"\n😞 当前余额不足最低提现金额 {min_amount} 元")
            else:
                print("\n⚠️ 无法获取提现规则，提现功能可能不可用")
        else:
            print("\n😞 当前余额不足，无法提现")

        print("\n🎊 所有任务执行完成")

if __name__ == '__main__':
    print("="*50)
    print("甬音自动任务脚本")
    print("功能：听音频、抽奖、提现到支付宝")
    print(f"开始时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*50)
    
    yy = YongYin()
    yy.run()
    
    print("="*50)
    print(f"结束时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*50)
 