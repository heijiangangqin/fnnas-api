import asyncio
from sdk import FnOsClient
from sdk.exceptions import WebSocketConnectionError
from sdk.handlers import HandlerUserInfo
import logging


# Configure the root logger
# logging.basicConfig(
#     level=logging.DEBUG,
#     format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
#     handlers=[logging.StreamHandler()]
# )


async def main():
    # 启动飞牛连接
    client = FnOsClient(ping_interval=60)
    await client.connect('ws://172.22.182.150:5666/websocket?type=main')
    client.add_handler('user.info', HandlerUserInfo)

    try:
        login_res = await client.login('dev', '8GMu~_u+nD1Rj3')
        print(login_res)

        res = await client.user_info()
        print(res)
        res = await client.authToken() # 非必须
        # 上传文件
        local_path = r'C:\Users\Administrator\Pictures\bg.jpg'
        nas_path = f'vol1/1001/tmp_img/bg.jpg' # NAS绝对路径
        res = await client.upload(local_path, nas_path)
        print(res)

        # 看网站60秒就user.active一次，应该保活 目测30s超时
        # 找到原因了，服务器没处理ping
        # 永久运行（直到手动停止）
        await asyncio.Event().wait()

        # 运行60s停止
        # await asyncio.sleep(60)
        # await client.close()
    except KeyboardInterrupt:
        print('中断进程')
        print('关闭client')
        await client.close()


if __name__ == "__main__":
    asyncio.run(main())
