# -*- coding: utf-8 -*-
"""
脚本名称: 欢盈麻烦小程序脚本 (V1.1)
作者: 老猫
功能: 自动登录欢盈麻烦小程序并进行每日签到，然后尝试进行积分抽奖，并将执行结果发送通知。日志输出更精简。
使用方法:
1. 在青龙面板中创建脚本文件，将本代码复制进去。
2. 添加环境变量: 名称为 HYMF_TOKENS，值为你的token。
   多个账号请使用 & 符号连接，例如: token1&token2&token3
3. **根据需要配置通知环境变量**，例如 PUSH_KEY, PUSH_PLUS_TOKEN 等。
4. 定时运行该脚本。
"""

import requests
import os
import json
import time

# Base URL for the API
BASE_URL = "https://huanyingmafan.com/public/home/WxApp"

# Define common headers
HEADERS_TEMPLATE = {
    "authority": "huanyingmafan.com",
    "scheme": "https",
    "xweb_xhr": "1",
    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 MicroMessenger/7.0.20.1781(0x6700143B) NetType/WIFI MiniProgramEnv/Windows WindowsWechat/WMPF WindowsWechat(0x63090c33)XWEB/13487",
    "content-type": "application/json",
    "accept": "*/*",
    "sec-fetch-site": "cross-site",
    "sec-fetch-mode": "cors",
    "sec-fetch-dest": "empty",
    "referer": "https://servicewechat.com/wxe8a9b29d45e0cfe3/22/page-frame.html",
    "accept-encoding": "gzip, deflate, br",
    "accept-language": "zh-CN,zh;q=0.9",
    "priority": "u=1, i",
    # Token will be added per account
}

# Empty payload for all requests
PAYLOAD = {}

# === 日志精简版：移除请求URL日志打印 ===
# request_api 函数将不再打印任何 URL 请求日志。
# =========================================

# === 通知环境变量获取 ===
# 获取青龙面板中配置的通知环境变量
PUSH_KEY = os.environ.get("PUSH_KEY")
BARK_PUSH = os.environ.get("BARK_PUSH") # 未在send_notification中实现，但获取以便扩展
BARK_SOUND = os.environ.get("BARK_SOUND", "")
BARK_GROUP = os.environ.get("BARK_GROUP", "QingLong")
TG_BOT_TOKEN = os.environ.get("TG_BOT_TOKEN") # 未在send_notification中实现
TG_USER_ID = os.environ.get("TG_USER_ID")
TG_PROXY_HOST = os.environ.get("TG_PROXY_HOST")
TG_PROXY_PORT = os.environ.get("TG_PROXY_PORT")
TG_PROXY_AUTH = os.environ.get("TG_PROXY_AUTH")
TG_API_HOST = os.environ.get("TG_API_HOST")
DD_BOT_TOKEN = os.environ.get("DD_BOT_TOKEN") # 未在send_notification中实现
DD_BOT_SECRET = os.environ.get("DD_BOT_SECRET")
QYWX_KEY = os.environ.get("QYWX_KEY") # 未在send_notification中实现
QYWX_AM = os.environ.get("QYWX_AM") # 未在send_notification中实现
IGOT_PUSH_KEY = os.environ.get("IGOT_PUSH_KEY") # 未在send_notification中实现
PUSH_PLUS_TOKEN = os.environ.get("PUSH_PLUS_TOKEN")
PUSH_PLUS_USER = os.environ.get("PUSH_PLUS_USER") # Push Plus 一对多推送群组编码
# ========================


def request_api(endpoint, token, payload=PAYLOAD):
    """Helper function to make API requests."""
    url = f"{BASE_URL}{endpoint}"
    headers = HEADERS_TEMPLATE.copy()
    headers["token"] = token

    # === 已移除请求URL日志打印 ===
    # print(f"正在请求：{url}") # 这行被移除
    # ============================

    try:
        response = requests.post(url, headers=headers, json=payload)
        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"   ❌请求失败：{e}") # 增加缩进
    except json.JSONDecodeError:
        print("   ❌响应体不是有效的JSON") # 增加缩进
        # Optionally print response text for debugging if needed
        # try:
        #     print(f"   Response text: {response.text}") # 增加缩进
        # except:
        #     pass
    return None

def get_user_basic_info(token):
    """Gets and prints basic user info (nickname, phone, total points). Returns user data."""
    result = request_api("/getUserInfo", token)
    user_info = None # Initialize to None
    if result and result.get("errorCode") == 0:
        data = result.get("data", {})
        nick_name = data.get("nick_name", "N/A")
        phone = data.get("phone", "N/A")
        total_points = data.get("total_points", "N/A")
        # === 使用【】格式打印 ===
        print(f"【用户昵称】: {nick_name}")
        print(f"【手机号】: {phone}")
        print(f"【总积分】: {total_points}")
        # ======================
        user_info = data # Store data for potential future use (like total_points)
    else:
        print(f"   ❌查询用户基本信息失败: {result.get('errorInfo', '未知错误') if result else '请求失败'}") # 增加缩进
    return user_info # Return user info data dictionary

def check_sign_status(token):
    """Checks if the user has signed in today. Returns boolean or None."""
    result = request_api("/getUserSignDate", token)
    is_signed = None
    if result and result.get("errorCode") == 0:
        data = result.get("data", {})
        is_signed = data.get("todaySign", False)
        # === 使用【】格式打印 ===
        print(f"【今日签到】: {'已签到' if is_signed else '未签到'}")
        # ======================
    else:
        print(f"   ❌查询今日签到状态失败: {result.get('errorInfo', '未知错误') if result else '请求失败'}") # 增加缩进
    return is_signed # Indicate failure to check

def perform_sign_in(token):
    """Performs the daily sign-in action. Returns True on success, False otherwise."""
    print("   尝试执行签到...") # 增加缩进
    result = request_api("/dealTodaySign", token)
    success = False
    sign_info = "未知结果" # To capture details for notification
    if result and result.get("errorCode") == 0:
        # === 精简成功日志，增加缩进 ===
        sign_info = f"✅签到成功！信息: {result.get('errorInfo', '无')}, 获得积分: {result.get('data', '未知')}"
        print(f"   {sign_info}")
        # ============================
        success = True
    else:
        # === 精简失败日志，增加缩进 ===
        sign_info = f"❌签到失败！信息: {result.get('errorInfo', '未知错误') if result else '请求失败'}"
        print(f"   {sign_info}")
        # Check for specific error like already signed in
        if result and "已签到" in result.get('errorInfo', ''):
             print("   (错误信息显示今天已签到)")
        # ============================
    return success, sign_info # Return success status and info string

# get_sign_info_after_sign 函数根据新的日志要求，可以不再单独调用并打印。
# 用户签到后的积分变化可以通过最后的 get_user_basic_info 查看。
# def get_sign_info_after_sign(token): pass


# === 积分抽奖功能函数 (修改为返回结构化结果) ===
def perform_lottery(token):
    """Performs points lottery and returns results as a dictionary."""
    print("   --- 积分抽奖 ---") # Keep console log header

    lottery_results = {
        'draw_count': 'N/A', # Available draws reported by API
        'attempted_draws': 0, # Number of draws we attempted
        'successful_draws': 0,
        'prizes': [],
        'error_message': None # Store potential stopping error
    }

    # 4.1 查询可用抽奖次数
    luck_draw_num_result = request_api("/getUserLuckDrawNum", token)
    draw_count = 0
    if luck_draw_num_result and luck_draw_num_result.get("errorCode") == 0:
        draw_count = luck_draw_num_result.get("data", 0)
        lottery_results['draw_count'] = draw_count # Store count
        print(f"【可用抽奖次数】: {draw_count} 次") # Keep console log
    else:
        error_msg = f"❌查询可用抽奖次数失败: {luck_draw_num_result.get('errorInfo', '未知错误') if luck_draw_num_result else '请求失败'}"
        print(f"   {error_msg}")
        lottery_results['error_message'] = error_msg
        return lottery_results # Return results dict even on initial failure

    if draw_count <= 0:
        print("   当前没有可用抽奖次数，跳过抽奖。") # Keep console log
        return lottery_results # Return results dict

    print(f"   开始执行 {draw_count} 次抽奖...") # Keep console log

    # 4.3 循环执行抽奖
    lottery_results['attempted_draws'] = draw_count # We attempt up to the reported count
    for i in range(draw_count):
        draw_result = request_api("/checkLuckDraw", token)

        if draw_result and draw_result.get("errorCode") == 0:
            lottery_results['successful_draws'] += 1
            draw_info = draw_result.get('errorInfo', '无')
            draw_data = draw_result.get('data', {})

            prize_name = draw_data.get("wheel_name", draw_info) # 优先data.wheel_name, 其次errorInfo
            prize_type = draw_data.get("type", None) # 获取奖品类型
            prize_value_str = ""
            if prize_type is not None:
                 if prize_type == 3: # 余额类型 (根据getRotaryRecord推断)
                     prize_value_str = f", 获得余额: {draw_data.get('balance', '未知')}"
                 elif prize_type == 1: # 积分类型 (根据getRotaryRecord推断)
                      prize_value_str = f", 获得积分: {draw_data.get('points', '未知')}"
                 # Add more prize type handling if needed

            prize_description = f"{prize_name}{prize_value_str}"
            lottery_results['prizes'].append(prize_description) # Collect prize string for notification

            # === 精简抽奖成功日志，增加缩进 ===
            print(f"   ✅第 {i+1}/{draw_count} 次抽奖成功！{prize_description}") # Keep console log
            # ======================================
        else:
            # === 精简抽奖失败日志，增加缩进 ===
            error_msg = f"❌第 {i+1}/{draw_count} 次抽奖失败！信息: {draw_result.get('errorInfo', '未知错误') if draw_result else '请求失败'}"
            print(f"   {error_msg}")
            # ======================================
            # 如果是积分不足，后续次数也无法抽奖，退出循环
            if draw_result and "积分不足" in draw_result.get('errorInfo', ''):
                 print("   检测到积分不足错误，停止后续抽奖。") # Keep console log
                 lottery_results['error_message'] = "积分不足，停止后续抽奖"
                 # Update attempted_draws to reflect how many were actually tried before stopping
                 lottery_results['attempted_draws'] = i + 1
                 break # Exit loop

        # 等待一段时间再进行下一次抽奖，避免过于频繁
        if i < draw_count - 1 and not lottery_results['error_message']: # 最后一次或因错误停止时不需要等待
            time.sleep(3)

    print(f"   积分抽奖执行完毕。成功抽奖 {lottery_results['successful_draws']} 次。") # Keep console log

    return lottery_results # Return the structured results dictionary

# === 通知发送函数 ===
def send_notification(title, content):
    """Sends notification using configured methods (Server酱, Push Plus)."""
    print("\n--- 发送通知 ---")
    notified = False
    content = content.strip() # Remove leading/trailing whitespace

    # Server酱 (仅支持PUSH_KEY, 新版API)
    if PUSH_KEY:
        url = f"https://sctapi.ftqq.com/{PUSH_KEY}.send"
        data = {
            "title": title,
            # Server酱 Markdown换行需要两个换行符，且自动转换为HTML，因此用<br/>更保险
            # content.replace('\n', '\n\n') # 旧版可能用这个
            "desp": content.replace('\n', '<br/>') # 新版API推荐Markdown或使用<br/>
        }
        try:
            response = requests.post(url, data=data)
            result = response.json()
            if result.get("code") == 0:
                print("   ✅ Server酱推送成功")
                notified = True
            else:
                 print(f"   ❌ Server酱推送失败: {result.get('message', response.text)}")
        except requests.exceptions.RequestException as e:
            print(f"   ❌ Server酱推送异常: {e}")

    # Push Plus
    if PUSH_PLUS_TOKEN:
        url = "http://www.pushplus.plus/send"
        data = {
            "token": PUSH_PLUS_TOKEN,
            "title": title,
            "content": content,
            "topic": PUSH_PLUS_USER, # 如果提供了USER，则推送到组
            "template": "html" # 或者 markdown, text (html通常支持换行)
        }
        try:
            response = requests.post(url, json=data)
            result = response.json()
            if result.get("code") == 200:
                print("   ✅ Push Plus推送成功")
                notified = True
            else:
                print(f"   ❌ Push Plus推送失败: {result.get('msg', response.text)}")
        except requests.exceptions.RequestException as e:
            print(f"   ❌ Push Plus推送异常: {e}")

    # Add other notification methods here if needed (BARK, TG, DD, QYWX, IGOT)
    # Implement similar blocks checking their respective environment variables
    # and making the correct API call.

    if not notified:
        print("   ⚠️ 没有配置任何通知方式或所有推送失败。")
    print("--- 通知发送完毕 ---")


# === 主执行函数 ===
def main():
    """Main function to process tokens and perform actions, then send notification."""
    print("--- 欢盈麻烦自动签到及积分抽奖脚本 ---")

    tokens_str = os.environ.get("HYMF_TOKENS")

    if not tokens_str:
        print("❌错误：请设置环境变量 HYMF_TOKENS 并填入你的 token(s)。")
        print("请抓包获取 token，填写在环境变量中。")
        # 可以选择在此处发送通知报告脚本启动失败
        # send_notification("欢盈麻烦脚本运行失败", "错误：请设置环境变量 HYMF_TOKENS。")
        return

    tokens = tokens_str.split("&")
    print(f"检测到 {len(tokens)} 个账号。")

    account_summaries = [] # List to store summary dictionaries for each account

    for i, token in enumerate(tokens):
        account_summary_dict = {} # Dictionary to store results for the current account
        account_summary_dict['index'] = i + 1
        account_summary_dict['total_accounts'] = len(tokens)
        account_summary_dict['log'] = [] # Collect printed logs for this account temporarily

        # Redirect print for this account to capture log output
        # This is a bit advanced, a simpler way is to just build strings directly
        # Let's stick to building strings directly for simplicity in this example.

        print(f"\n--- 账号 {i+1}/{len(tokens)} ---")

        # Get initial user info
        # get_user_basic_info prints directly and returns data
        user_info = get_user_basic_info(token)
        if user_info:
            account_summary_dict['nickname'] = user_info.get('nick_name', 'N/A')
            account_summary_dict['initial_points'] = user_info.get('total_points', 'N/A')
        else:
            account_summary_dict['nickname'] = '未知用户'
            account_summary_dict['initial_points'] = 'N/A'
            # If initial info fails, maybe skip account? Or continue with N/A

        # Check and perform sign-in
        is_signed = check_sign_status(token)
        account_summary_dict['sign_status'] = '查询失败' if is_signed is None else ('已签到' if is_signed else '未签到')
        account_summary_dict['sign_attempted'] = False
        account_summary_dict['sign_result_info'] = "未尝试签到"

        if is_signed is False: # Only attempt if not already signed and status check didn't fail
             account_summary_dict['sign_attempted'] = True
             sign_in_success, sign_result_info = perform_sign_in(token)
             account_summary_dict['sign_result_info'] = sign_result_info
             if sign_in_success:
                  time.sleep(2)
             # We don't need get_sign_info_after_sign here, final points capture covers it

        # Perform lottery
        lottery_results = perform_lottery(token) # This function already prints console logs
        account_summary_dict['lottery'] = lottery_results


        # Get final user info (to see point changes)
        print("   --- 操作后信息 ---")
        final_user_info = get_user_basic_info(token) # This still prints, which is fine for console log
        if final_user_info:
             account_summary_dict['final_points'] = final_user_info.get('total_points', 'N/A')
        else:
             account_summary_dict['final_points'] = 'N/A'

        account_summaries.append(account_summary_dict)

        # Add a small delay between accounts if needed
        # time.sleep(5) # Optional delay

    # --- End of Loop ---

    # Build the final notification message content
    notification_content = f"【脚本】欢盈麻烦自动签到及积分抽奖\n\n"
    notification_content += f"共处理 {len(tokens)} 个账号。\n"
    notification_content += "--------------------\n"

    for summary in account_summaries:
        notification_content += f"--- 账号 {summary['index']}/{summary['total_accounts']} ---\n"
        notification_content += f"【昵称】: {summary.get('nickname', 'N/A')}\n"
        notification_content += f"【初始积分】: {summary.get('initial_points', 'N/A')}\n"
        notification_content += f"【今日签到】: {summary.get('sign_status', '未知')}\n"

        if summary.get('sign_attempted'):
             notification_content += f"  签到尝试结果: {summary.get('sign_result_info', '未知')}\n"

        lottery_info = summary.get('lottery', {})
        notification_content += f"--- 抽奖结果 ---\n"
        notification_content += f"【可用抽奖次数】: {lottery_info.get('draw_count', 'N/A')} 次\n"
        # notification_content += f"  尝试执行次数: {lottery_info.get('attempted_draws', 'N/A')} 次\n" # 尝试次数通常等于可用次数，除非失败
        notification_content += f"  成功抽奖次数: {lottery_info.get('successful_draws', 'N/A')} 次\n"

        if lottery_info.get('prizes'):
            notification_content += "  获得奖品:\n"
            for prize in lottery_info['prizes']:
                notification_content += f"    - {prize}\n"
        elif lottery_info.get('attempted_draws', 0) > 0:
             notification_content += "  未能获得奖品。\n"

        if lottery_info.get('error_message'):
             notification_content += f"  抽奖停止原因: {lottery_info['error_message']}\n"

        notification_content += f"【最终积分】: {summary.get('final_points', 'N/A')}\n"
        notification_content += "--------------------\n" # Separator between accounts

    notification_content += "脚本运行完毕。"

    # Send the notification
    send_notification("欢盈麻烦脚本运行报告", notification_content)

    print("\n--- 脚本运行完毕 ---") # Keep the console log completion message


if __name__ == "__main__":
    main()