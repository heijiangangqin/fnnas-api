### 飞牛api逻辑

根据浏览器抓包，飞牛大部分接口都是websocket协议

上传用的http协议，但是要使用ws获取一个文件名，叫做checkUpload

飞牛网页一共建立三个ws，分别是main, file,timer，实际都是一个服务响应

只是网页版简历了三个连接，用python调用api，使用type=main也可以checkUpload

### ws接口地址

```python
ws://192.168.1.4:5666/websocket?type=main # 这里的main就是类型区分
```

### 请求参数结构

json格式的的请求体

| 参数         | 类型 | 示例                         | 用途               |
| ------------ | ---- | ---------------------------- | ------------------ |
| req          | str  | user.login                   | 指定调用的api      |
| reqid        | str  | 6819dfb56819dfb500000002000d | 请求id，和响应对应 |
| 其他业务参悟 | ...  | ...                          | ...                |

**reqid生成代码**

python生成，自增

```python
def _get_reqid():
    index = 1

    def func(backId='0000000000000000'):
        nonlocal index
        t = format(int(time.time()), 'x').zfill(8)
        e = format(index, 'x').zfill(4)
        index += 1
        return f"{t}{backId}{e}"

    return func

get_reqid = _get_reqid()
```



### 接口加密

连接ws后先发送获取RSA公钥的请求到服务器，用于登录和其他参数加密

```json
{reqid: "6819e1ca00000000000000000001", req: "util.crypto.getRSAPub"}
```

返回示例：
```json
{"pub":"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzWICqab2gcSuRzhguXqH\nKOzS0irokLS9pvT488UIv1581RcfuqUKV/CpvBvbzrLEM1kQtbSAXjOSAYrmOW+V\nN9Nwb8XhJSZHuPdAmqDzm9hu+06QDkIE9TLkNnIZcQKW6gG9Pbo5vID7BWYjzJVU\n7rP+lX5lUrCbpgsXxs5UjEb+4E5St1RaKFCOMiapy40wXgMh4rVyfbfkT752RSsj\nvnNWyYEHuFDJZ7Z2JHJZBhZnIRXOt0k4bTzpqxBbq/2llZ2Z60pm+Ad/h+xpLjvU\nlITh9ddocFpYddYO7MIGQ6dDO4KBObPkqvOJuZ+9sKw1PE6pm4C/ArR1lVHh4L3j\n8wIDAQAB\n-----END PUBLIC KEY-----\n","si":"21474836501","result":"succ","reqid":"6819e1ca00000000000000000001"}
```

### 登录接口

**原始数据**

| 参数       | 类型 | 示例值                       | 备注                                     |
| ---------- | ---- | ---------------------------- | ---------------------------------------- |
| req        | str  | user.login                   |                                          |
| reqid      | str  | 6819e1ce00000000000000000003 | 自增id，自己维护，可以是uuid             |
| user       | str  | admin                        | 需要登录的账号                           |
| password   | str  | password                     | 账号的密码                               |
| deviceType | str  | Browser                      | 这里可以固定，也可以随便填，我认为不重要 |
| deviceName | str  | Windows-Google Chrome        | 同上                                     |
| stay       | bool | True                         | 勾选“保持登录”时为True                   |
| si         | str  | 21474836501                  | util.crypto.getRSAPub返回的si            |
|            |      |                              |                                          |

**加密后**

| 参数 | 类型 | 示例               | 备注                      |
| ---- | ---- | ------------------ | ------------------------- |
| aes  | str  | 5aA/cocgii6UWK.... | 把原始请求数据使用aes加密 |
| iv   | str  | aHr5yKmqaVU8gJ...  | 随机os.urandom(16)        |
| req  | str  | encrypted          | 固定                      |
| rsa  | str  | aTlIFLgZ8HOjhV0... | aes加密key使用rsa加密     |

**失败返回**

```json
{"errno":131072,"result":"fail","reqid":"6819e1ce00000000000000000003"}
```

**成功响应**

```json
{
    "uid": 1000, // uid
    "admin": true, // 是否管理
    "token": "TvPxZlDmGWj+Zhoj3ePKAXhNwEoRg20sOTC0+j/Yof8=", // 会话token
    "secret": "bWH/dMzpTM2c498hzpW5FXic9ap5wPHhFiMqXnFBqs4=", // 后面签名密钥
    "backId": "6819e65000000004", // 替换reqid的8-24位的0， 参考reqid生成代码
    "machineId": "744d46cccc6b4ababf2ffbe273a55cc620fee21f", // 没搞懂
    "result": "succ", // 接口响应状态
    "reqid": "6819e65000000000000000000004" // 和请求id保持一致
}
```

**加密函数**

```python
# AES 加密
def aes_encrypt(data, key, iv):
    cipher = AES.new(key.encode(), AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))
    return base64.b64encode(ciphertext).decode('utf-8')

# RSA 加密
def rsa_encrypt(public_key_str, plaintext):
    key = RSA.import_key(public_key_str)

    # 注释和不注释都能过，就很奇怪
    # MAX_ENCRYPT_BLOCK = 117
    # ciphertext = b''
    # for i in range(0, len(plaintext), MAX_ENCRYPT_BLOCK):
    #     chunk = plaintext[i:i + MAX_ENCRYPT_BLOCK]
    #     cipher = PKCS1_v1_5.new(key)
    #     encrypted_chunk = cipher.encrypt(chunk)
    #     ciphertext += encrypted_chunk

    cipher = PKCS1_v1_5.new(key)
    ciphertext = cipher.encrypt(plaintext.encode())
    ciphertext = base64.b64encode(ciphertext).decode()
    return ciphertext


def login_encrypt(data, public_key_str, key, iv):
    # RSA 加密
    rsa_encrypted = rsa_encrypt(public_key_str, key)

    # AES 加密
    # data = json.dumps(t, separators=(',', ':'))
    aes_encrypted = aes_encrypt(data, key, iv)

    # 返回加密数据
    return {
        'req': 'encrypted',
        'iv': base64.b64encode(iv).decode('utf-8'),  # 正常
        'rsa': rsa_encrypted,
        'aes': aes_encrypted  # 正常
    }
```

### 写不下去了

**去github看代码吧，我实在不会写文档，所有代码使用python写**