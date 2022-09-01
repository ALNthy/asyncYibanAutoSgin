# 免责声明
- 本项目仅供学习测试研究，禁止用于商业用途
- 本项目使用后的任何后果须使用本人承担，关于本项目的问题概不负责，包括使用过程中的任何损失和损害
- 如有出现 **发热** 等症状，请立即停用本项目，认真履行好社会责任与义务

pyhton=3.10

安装依赖

>pip install -r requirements.txt

### 使用方法


在config中

添加账号密码
>user = [
    {"Account": "账号",
     "password": "密码"
     }
]

抓包解包获取表单信息

```Python
# 密钥
AES_KEY = '2knV5VGRTScU7pOq'
AES_IV = 'UmNWaNtM0PUdtFCs'

# 解密
def aes_decrypt(aes_key, aes_iv, data):
    """
    aes_key: 密钥
    aes_iv: iv
    提交表单解密
    """
    aes_key = bytes(aes_key, 'utf-8')
    aes_iv = bytes(aes_iv, 'utf-8')
    data = b64decode(b64decode(data))
    cipher = AES.new(aes_key, AES.MODE_CBC, aes_iv)
    decrypted = cipher.decrypt(data)
    return decrypted.decode('utf-8')
```
填写表单，其他学校自行抓包填写
```Python
task_once = {
    "7acae1b0e8bee6d65ea0ff5ef7ac998c": "小于36.0℃ ",
    "c265c750979d6250566b112a90ad5277": "已完成疫苗接种",
    "5db079912c206b9b9a08ff4461a6d5f1": ["否"],
    "a7649f5e0e50c64e924c41f842996787": ["否"],
    "7d26f4de58d45167bd85624a1088b15f": ["否"],
    "615283662f5f8a13aa79058a27ca995e": ["否"],
    "58086a8c1592bb32bc11b34e3a7670bb": ["否"],
    "97475c78c7fae615c0c277eeb17ab6ff": [{"name": "sb.png", "type": "image/png", "size": 642368, "status": "done",
                                          "percent": 100, "   fileName": "workflow/202203/10/sb.png",
                                          "path": "workflow/202203/10/sbyiban.png"}]
}
```
运行 main.py
