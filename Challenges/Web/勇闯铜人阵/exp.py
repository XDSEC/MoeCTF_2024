import re
from pydash import trim
import requests
from bs4 import BeautifulSoup
url1 = "http://localhost:40763/restart"
url2 = "http://localhost:40763/"

sess = requests.session()
direct_list = ["北方", "东北方", "东方", "东南方", "南方", "西南方", "西方", "西北方"]

def parse_status(html):
    bs = BeautifulSoup(html, "html.parser")
    coin = trim(bs.find('h1', id='status').text)
    # 一枚硬币
    if len(coin) == 1:
        return direct_list[int(coin) - 1]
    # 两枚硬币
    else:
        nums = re.findall(r'\d', coin)
        return direct_list[int(nums[0]) - 1] + '一个，' + direct_list[int(nums[1]) - 1] + '一个'
        
if __name__ == "__main__":
    # restart
    sess.get(url=url1)
    # start
    body = {
        "player": "sxrhhh",
        "direct": "弟子明白",
    }
    r = sess.post(url=url2, data=body)
    # 循环
    for i in range(0, 5):
        payload = parse_status(r.text)
        body = {
            "player": "sxrhhh",
            "direct": payload,
        }
        r = sess.post(url=url2, data=body)
        # 打印结果
        bs = BeautifulSoup(r.text, "html.parser")
        status = trim(bs.find('h1', id='status').text)
        print(status)
