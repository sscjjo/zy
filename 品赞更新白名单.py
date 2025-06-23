# cron 10 2
# new Env('更新IP代理白名单');

import requests
import logging
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
import time

# --- 配置区域 ---
# 品赞代理配置
PINZAN_API_URL = 'https://service.ipzan.com/whiteList-add'  # 官方API地址
PINZAN_NO = ''  # 套餐购买编号
PINZAN_SIGN_KEY = ''  # 签名密钥（控制台查看）
PINZAN_LOGIN_PASSWORD = ''  # 登录密码
PINZAN_PACKAGE_SECRET = ''  # 套餐提取密匙
PINZAN_USER_ID = ''  # 品赞用户ID

# --- 日志配置 ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def get_current_ip():
    """获取本机公网IP地址"""
    try:
        response = requests.get('https://myip.ipip.net/json', timeout=10)
        response.raise_for_status()
        data = response.json()
        ip = data.get('data', {}).get('ip')
        if not ip:
            raise ValueError("未能从API响应中获取IP地址")
        return ip
    except (requests.RequestException, ValueError) as e:
        logging.error(f"获取IP地址失败: {e}")
        return None

def update_pinzan_white_list(ip, api_url, no, sign_key, login_password, package_secret, replace=0):
    """更新品赞代理的IP白名单"""
    if not (api_url and no and sign_key and login_password and package_secret):
        logging.warning("品赞代理的参数未配置完整，跳过更新。")
        return "跳过"
    try:
        ts = int(time.time())
        sign_content = f"{login_password}:{package_secret}:{ts}"
        key = sign_key.encode('utf-8')
        cipher = AES.new(key, AES.MODE_ECB)
        padded = pad(sign_content.encode('utf-8'), AES.block_size, style='pkcs7')
        encrypted = cipher.encrypt(padded)
        sign = binascii.hexlify(encrypted).decode('utf-8')
        params = {
            'no': no,
            'ip': ip,
            'sign': sign,
            'replace': str(replace)
        }
        response = requests.get(api_url, params=params, timeout=10)
        response.raise_for_status()
        return response.text
    except Exception as e:
        return f"请求出错: {e}"

def delete_pinzan_white_list(ip, user_id, api_url="https://service.ipzan.com/whiteList-del", no=None):
    """
    删除品赞代理的IP白名单
    :param ip: 要删除的IP
    :param user_id: 用户ID
    :param api_url: API地址
    :param no: 套餐编号（可选）
    :return: API响应文本
    """
    if not (ip and user_id):
        logging.warning("品赞删除白名单参数未配置完整，跳过删除。")
        return "跳过"
    try:
        params = {
            'ip': ip,
            'userId': user_id
        }
        if no:
            params['no'] = no
        response = requests.get(api_url, params=params, timeout=10)
        response.raise_for_status()
        return response.text
    except Exception as e:
        return f"请求出错: {e}"

def main():
    ip = get_current_ip()
    if not ip:
        logging.error("无法获取当前IP，程序终止。")
        return
    logging.info(f"获取到当前公网IP: {ip}")

    # 只更新白名单
    result_pinzan = update_pinzan_white_list(ip, PINZAN_API_URL, PINZAN_NO, PINZAN_SIGN_KEY, PINZAN_LOGIN_PASSWORD, PINZAN_PACKAGE_SECRET)
    logging.info(f"更新品赞白名单结果: {result_pinzan}")

if __name__ == "__main__":
    main()
