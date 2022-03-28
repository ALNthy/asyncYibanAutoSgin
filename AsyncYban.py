import random
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


class asYiban():

    def __init__(self, mobile, password):
        self.mobile = mobile
        self.password = password
        self.CSRF = csrf()
        self.HEADERS = {"Origin": "'https://m.yiban.cn", 'AppVersion': '5.0.1', "User-Agent": "YiBan/5.0.1"}
        self.COOKIES = {"csrf_token": self.CSRF}
        self.session = httpx.AsyncClient()
        self.WFId = ""

    async def req(self, m: str = "get", params=None, url=None):
        if m == "get":
            res = await self.session.get(url=url, cookies=self.COOKIES, headers=self.HEADERS, params=params)
        else:
            res = await self.session.post(url=url, cookies=self.COOKIES, headers=self.HEADERS, data=params)
        return res

    async def login(self):
        """
        登录
        """
        params = {
            "mobile": self.mobile,
            "password": encryptPassword(self.password),
            "ct": "2",
            "identify": "0",
        }
        login = await self.req(m="post", params=params, url="https://mobile.yiban.cn/api/v4/passport/login")

        return login.json()

    async def auth(self):
        """
        登录验证
        """
        ac = await self.session.get("https://f.yiban.cn/iapp/index?act=iapp7463", cookies=self.COOKIES)
        act = ac.headers["Location"]
        verifyRequest = re.findall(r"verify_request=(.*?)&", act)[0]
        self.HEADERS.update({
            'Origin': 'https://app.uyiban.com',
            'referer': 'https://app.uyiban.com/',
            'Host': 'api.uyiban.com',
            'User-Agent': 'yiban'
        })
        at = await self.req(url=
                            "https://api.uyiban.com/base/c/auth/yiban?verifyRequest=" + verifyRequest + "&CSRF=" + self.CSRF,
                            m="get")
        return at.json()

    async def getListTime(self) -> json:
        """
        获取特定时间内未完成的任务
        """
        res = await self.req(
            url="https://api.uyiban.com/officeTask/client/index/uncompletedList?StartTime=" + fromIntGetTimePeriod()[
                0] + "&EndTime=" + fromIntGetTimePeriod()[1] + "&CSRF=" + self.CSRF)
        return res.json()

    async def getDetail(self, taskId) -> json:
        """
        获取表单所需的Extend信息
        """
        res = await self.req(
            url="https://api.uyiban.com/officeTask/client/index/detail?TaskId=" + taskId + "&CSRF=" + self.CSRF)
        self.WFId = res.json()['data']['WFId']
        return res.json()

    async def submitApply(self, data, extend) -> json:
        """
        提交表单
        """
        params = {
            "Data": json.dumps(data, ensure_ascii=False),
            "Extend": json.dumps(extend, ensure_ascii=False),
            "WFId": self.WFId
        }
        params = json.dumps(params, ensure_ascii=False)
        res = await self.req(url="https://api.uyiban.com/workFlow/c/my/apply/?CSRF=%s" % (self.CSRF), m="post",
                             params={'Str': aes_encrypt(AES_KEY=AES_KEY, AES_IV=AES_IV, data=params)})
        return res.json()

    async def aiosession(self) -> str:
        """
        主程序
        """
        login = await self.login()
        if (login["response"]) != 100:
            return f"账号{self.mobile}:{login['message']}"
        access_token = login["data"]["access_token"]
        self.HEADERS["Authorization"] = "Bearer" + access_token
        self.COOKIES["loginToken"] = access_token
        auth = await self.auth()
        if auth["code"] != 0:
            return f"账号{self.mobile} 登录验证未通过"
        now_task = await self.getListTime()
        if not len(now_task["data"]):
            return f"账号{self.mobile}没有找到要提交的表单"
        else:
            task_id = now_task["data"]
            i = 0
            p = 0
            for now_task_id in task_id:
                if now_task_id["State"] == 0:
                    detail = await self.getDetail(taskId=now_task_id["TaskId"])
                    extend = {
                        "TaskId": now_task_id["TaskId"],
                        "title": "任务信息",
                        "content": [
                            {"label": "任务名称", "value": detail["data"]["Title"]},
                            {"label": "发布机构", "value": detail["data"]["PubOrgName"]},
                            {"label": "发布人", "value": detail["data"]["PubPersonName"]}
                        ]
                    }
                    sb_result = await self.submitApply(data=task_once, extend=extend)
                    if sb_result["code"] == 0:
                        i = i + 1
                    else:
                        p = p + 1
            return f"账号{self.mobile}找到{len(task_id)}个打卡任务,打卡成功{i}个,失败{p}个,其中有{len(task_id)-i-p}个任务无法操作"

    async def aioyiban(self):
        """
        执行主程序
        关闭AsyncClient()
        """
        async with self.session:
            log = await self.aiosession()
            print(log)
            return log


if __name__ == '__main__':
    # 示例1
    task = [asYiban(16670101, "xh8736").aioyiban(), asYiban(1652, "th24155").aioyiban(),
            asYiban(1667014554601, "xh8736").aioyiban()]
    asyncio.run(asyncio.wait(task))
    # 示例2
    asyncio.run(asYiban(166709, "xh4836").aioyiban())
