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
from httpx import Response
import config

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
    s = "1234567890abcdefghijklmnopqrstuvwxyz"
    StringS = ''.join([random.choice(s) for _ in range(32)])
    return StringS


class AsyncYiban:
    COOKIES = {"csrf_token": csrf()}
    HEADERS = {"Origin": "https://c.uyiban.com", "User-Agent": "Yiban", "AppVersion": "5.0"}
    # 密钥
    AES_KEY = '2knV5VGRTScU7pOq'
    AES_IV = 'UmNWaNtM0PUdtFCs'
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

    def __init__(self, username, password):
        self.yiban_user_token = None
        self.user = {
            'account': username,
            'password': password,
        }
        self.session = httpx.AsyncClient(timeout=10)

    def encryptPassword(self, pwd):
        # 密码加密
        cipher = PKCS1_v1_5.new(RSA.importKey(self.PUBLIC_KEY))
        cipher_text = base64.b64encode(cipher.encrypt(bytes(pwd, encoding="utf8")))
        return cipher_text.decode("utf-8")

    # 加密
    def aes_encrypt(self, data):
        """
        aes_key: 密钥
        aes_iv: iv
        提交表单加密
        """
        aes_key = bytes(self.AES_KEY, 'utf-8')
        aes_iv = bytes(self.AES_IV, 'utf-8')
        data = bytes(data, 'utf-8')
        data = data + bytes(
            chr(AES.block_size - len(data) % AES.block_size) * (AES.block_size - len(data) % AES.block_size), 'utf-8')
        cipher = AES.new(aes_key, AES.MODE_CBC, aes_iv)
        encrypted = b64encode(cipher.encrypt(data))
        return b64encode(encrypted).decode('ascii')

    async def req(self, url: str, method='get', cookies: dict = None, headers: dict = None,
                  allow_redirects=True, data: dict = None, params: dict = None) -> Response:
        if headers is None:
            headers = {}
        if cookies is None:
            cookies = {}
        headers.update(self.HEADERS)
        cookies.update(self.COOKIES)
        if method == 'get':
            return await self.session.get(url=url,
                                          headers=headers,
                                          cookies=cookies,
                                          params=params,
                                          follow_redirects=allow_redirects)
        else:
            return await self.session.post(url=url,
                                           headers=headers,
                                           cookies=cookies,
                                           params=params,
                                           data=data,
                                           follow_redirects=allow_redirects)

    async def login(self):
        res = await self.req(method='post',
                             url='https://www.yiban.cn/login/doLoginAjax',
                             data=self.user)
        if res.json()['code'] == 200:
            self.yiban_user_token = res.cookies['yiban_user_token']
        else:
            raise Exception(f"{self.user['account']} 用户名或密码错误")

    async def auto(self):

        res = await self.req(url='https://f.yiban.cn/iframe/index',
                             params={'act': 'iapp7463'},
                             cookies={'yiban_user_token': self.yiban_user_token},
                             allow_redirects=False
                             )
        verify = re.findall(r"verify_request=(.*?)&", res.headers.get("Location"))[0]
        await self.req(url='https://api.uyiban.com/base/c/auth/yiban',
                           params={'verifyRequest': verify, 'CSRF': self.COOKIES["csrf_token"]}, )
        await self.req(
            url='https://oauth.yiban.cn/code/html',
            params={'client_id': '95626fa3080300ea', 'redirect_uri': 'https://f.yiban.cn/iapp7463'},
        )
        await self.req(
            method='post',
            url='https://oauth.yiban.cn/code/usersure',
            data={'client_id': '95626fa3080300ea', 'redirect_uri': 'https://f.yiban.cn/iapp7463'}
        )
        await self.req(url='https://api.uyiban.com/base/c/auth/yiban',
                           params={'verifyRequest': verify, 'CSRF': self.COOKIES["csrf_token"]}, )

    async def getListTime(self) -> list:
        """
        获取本月时间段的打卡任务
        """
        res = await self.req(
            url="https://api.uyiban.com/officeTask/client/index/uncompletedList?StartTime=" + fromIntGetTimePeriod()[
                0] + "&EndTime=" + fromIntGetTimePeriod()[1] + "&CSRF=" + self.COOKIES["csrf_token"])
        return res.json()['data']

    async def submit(self, taskid):
        detail = await self.req(
            url="https://api.uyiban.com/officeTask/client/index/detail?TaskId=" + taskid + "&CSRF=" + self.COOKIES[
                "csrf_token"])
        form = json.dumps({
            "Data": json.dumps(task_once, ensure_ascii=False),
            "Extend": json.dumps({
                "TaskId": taskid,
                "title": "任务信息",
                "content": [
                    {"label": "任务名称", "value": detail.json()["data"]["Title"]},
                    {"label": "发布机构", "value": detail.json()["data"]["PubOrgName"]},
                    {"label": "发布人", "value": detail.json()["data"]["PubPersonName"]}
                ]
            }, ensure_ascii=False),
            "WFId": detail.json()["data"]["WFId"]
        }, ensure_ascii=False)
        a = await self.req(url="https://api.uyiban.com/workFlow/c/my/apply/?CSRF=%s" % self.COOKIES["csrf_token"],
                           method="post",
                           data={'Str': self.aes_encrypt(data=form)})
        if a.json()["code"] == 0:
            return f'账号：{self.user["account"]} {detail.json()["data"]["Title"]} succeed'
        else:
            return f'账号：{self.user["account"]} {detail.json()["data"]["Title"]} fail  {a.json()}'

    async def main(self):
        async with self.session:
            await self.login()
            await self.auto()
            return [await self.submit(i["TaskId"]) for i in await self.getListTime()]


if __name__ == '__main__':
    print(asyncio.run(AsyncYiban("admin", "admin").main()))
