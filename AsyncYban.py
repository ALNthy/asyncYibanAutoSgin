import httpx
import asyncio
import re
from Crypto.Cipher import PKCS1_v1_5, AES
from Crypto.PublicKey import RSA
import base64
import time
from base64 import b64encode
import json
import config
import random

# 密钥
AES_KEY = '2knV5VGRTScU7pOq'
AES_IV = 'UmNWaNtM0PUdtFCs'

# 表单内容
task_once = config.task_once


def encryptPassword(pwd):
    # 密码加密
    PUBLIC_KEY = '''-----BEGIN PUBLIC KEY-----
        MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA6aTDM8BhCS8O0wlx2KzA
        Ajffez4G4A/QSnn1ZDuvLRbKBHm0vVBtBhD03QUnnHXvqigsOOwr4onUeNljegIC
        XC9h5exLFidQVB58MBjItMA81YVlZKBY9zth1neHeRTWlFTCx+WasvbS0HuYpF8+
        KPl7LJPjtI4XAAOLBntQGnPwCX2Ff/LgwqkZbOrHHkN444iLmViCXxNUDUMUR9bP
        A9/I5kwfyZ/mM5m8+IPhSXZ0f2uw1WLov1P4aeKkaaKCf5eL3n7/2vgq7kw2qSmR
        AGBZzW45PsjOEvygXFOy2n7AXL9nHogDiMdbe4aY2VT70sl0ccc4uvVOvVBMinOp
        d2rEpX0/8YE0dRXxukrM7i+r6lWy1lSKbP+0tQxQHNa/Cjg5W3uU+W9YmNUFc1w/
        7QT4SZrnRBEo++Xf9D3YNaOCFZXhy63IpY4eTQCJFQcXdnRbTXEdC3CtWNd7SV/h
        mfJYekb3GEV+10xLOvpe/+tCTeCDpFDJP6UuzLXBBADL2oV3D56hYlOlscjBokNU
        AYYlWgfwA91NjDsWW9mwapm/eLs4FNyH0JcMFTWH9dnl8B7PCUra/Lg/IVv6HkFE
        uCL7hVXGMbw2BZuCIC2VG1ZQ6QD64X8g5zL+HDsusQDbEJV2ZtojalTIjpxMksbR
        ZRsH+P3+NNOZOEwUdjJUAx8CAwEAAQ==
        -----END PUBLIC KEY-----'''
    cipher = PKCS1_v1_5.new(RSA.importKey(PUBLIC_KEY))
    cipher_text = base64.b64encode(cipher.encrypt(bytes(pwd, encoding="utf8")))
    return cipher_text.decode("utf-8")


# 加密
def aes_encrypt(AES_KEY, AES_IV, data):
    """
    aes_key: 密钥
    aes_iv: iv
    提交表单加密
    """
    aes_key = bytes(AES_KEY, 'utf-8')
    aes_iv = bytes(AES_IV, 'utf-8')
    data = bytes(data, 'utf-8')
    data = aes_pkcs7padding(data)
    cipher = AES.new(aes_key, AES.MODE_CBC, aes_iv)
    encrypted = b64encode(cipher.encrypt(data))
    return b64encode(encrypted).decode('ascii')




def aes_pkcs7padding(data):
    bs = AES.block_size
    padding = bs - len(data) % bs
    padding_text = bytes(chr(padding) * padding, 'utf-8')
    return data + padding_text


def fromIntGetTimePeriod():
    """
    获取本月时间段
    :return:
    """
    return [
        time.strftime("%Y-%m-01 00:00:00", time.localtime(int(time.time()))),
        time.strftime("%Y-%m-%d 23:59:59", time.localtime(int(time.time())))
    ]
def csrf():
    # 随机字符串
    seef = "1234567890abcdefghijklmnopqrstuvwxyz"
    seef_list = []
    for i in range(32):
        seef_list.append(random.choice(seef))
    StringS = ''.join(seef_list)
    return StringS

# 主程序

class asYiban():

    def __init__(self, mobile, password):
        self.mobile = mobile
        self.password = password
        self.CSRF = csrf()
        self.HEADERS={"Origin": "'https://m.yiban.cn", 'AppVersion': '5.0.1', "User-Agent": "YiBan/5.0.1"}
        self.COOKIES={"csrf_token": self.CSRF}
    async def aioyiban(self):
        async with httpx.AsyncClient() as requests:
            params = {
                "mobile": self.mobile,
                "password": encryptPassword(self.password),
                "ct": "2",
                "identify": "0",
            }
            # 账号登录
            res = await requests.post("https://mobile.yiban.cn/api/v4/passport/login", headers=self.HEADERS,
                                      cookies=self.COOKIES, data=params)

            login = res.json()

            if login is not None and login["response"] == 100:
                access_token = login["data"]["access_token"]
                self.HEADERS["Authorization"] = "Bearer" + access_token
                self.COOKIES["loginToken"] = access_token

                ac = await requests.get("https://f.yiban.cn/iapp/index?act=iapp7463", cookies=self.COOKIES, headers=self.HEADERS)
                act = ac.headers["Location"]

                verifyRequest = re.findall(r"verify_request=(.*?)&", act)[0]
                self.HEADERS.update({
                    'Origin': 'https://app.uyiban.com',
                    'referer': 'https://app.uyiban.com/',
                    'Host': 'api.uyiban.com',
                    'User-Agent': 'yiban'
                })
                # 登录验证
                auto = await requests.get(
                    "https://api.uyiban.com/base/c/auth/yiban?verifyRequest=" + verifyRequest + "&CSRF=" + self.CSRF,
                    cookies=self.COOKIES, headers=self.HEADERS)
                code = auto.json()["code"]
                if code == 0:
                    params = {
                        "StartTime": fromIntGetTimePeriod()[0],
                        "EndTime": fromIntGetTimePeriod()[1],
                        "CSRF": self.CSRF
                    }
                    # 获取任务列表
                    task_list = await requests.get(
                        "https://api.uyiban.com/officeTask/client/index/uncompletedList",
                        cookies=self.COOKIES, headers=self.HEADERS, params=params)
                    if task_list.json()["code"] == 0:
                        if len(task_list.json()["data"]) != 0:
                            for task_id in task_list.json()["data"]:
                                # 获取任务extend信息
                                Extend = await requests.get(
                                    "https://api.uyiban.com/officeTask/client/index/detail?TaskId=" + task_id[
                                        "TaskId"] + "&CSRF=" + self.CSRF, cookies=self.COOKIES, headers=self.HEADERS)
                                if Extend.json()["code"] == 0:
                                    extend = {
                                        "TaskId": task_id["TaskId"],
                                        "title": "任务信息",
                                        "content": [
                                            {"label": "任务名称", "value": Extend.json()["data"]["Title"]},
                                            {"label": "发布机构", "value": Extend.json()["data"]["PubOrgName"]},
                                            {"label": "发布人", "value": Extend.json()["data"]["PubPersonName"]}
                                        ]
                                    }
                                    params = {
                                        "Data": json.dumps(task_once, ensure_ascii=False),
                                        "Extend": json.dumps(extend, ensure_ascii=False),
                                        "WFId": Extend.json()['data']['WFId']
                                    }
                                    params = json.dumps(params, ensure_ascii=False)
                                    # 提交表单
                                    upform = await requests.post(
                                        "https://api.uyiban.com/workFlow/c/my/apply/?CSRF=%s" % (self.CSRF),
                                        data={'Str': aes_encrypt(AES_KEY, AES_IV, params)}, cookies=self.COOKIES,
                                        headers=self.HEADERS)
                                    if upform.json()["code"] == 0:
                                        print(task_id["TaskId"], f"  {self.mobile}打卡成功")
                                    else:
                                        print(f"{self.mobile}  " + task_id["TaskId"], "打卡失败，原因：", upform.json())
                                else:
                                    print(f"{self.mobile}获取表单Extend失败", Extend.json())
                        else:
                            print(f"账号{self.mobile}没有找到要提交的表单,可能今天已经打过卡了")
                    else:
                        print(f"{self.mobile}获取任务列表错误，{task_list.json()}")
            else:
                print(f"{self.mobile}登入失败，账号或密码错误", login)


if __name__ == '__main__':
    # 示例1
    task = [asYiban(16670101, "xh8736").aioyiban(), asYiban(1652, "th24155").aioyiban(),asYiban(1667014554601, "xh8736").aioyiban()]
    asyncio.run(asyncio.wait(task))
    # 示例2
    asyncio.run(asYiban(166709, "xh4836").aioyiban())
