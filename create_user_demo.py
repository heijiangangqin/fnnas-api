import asyncio
import logging
from sdk.fnos_client import FnOsClient

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

async def main():
    client = FnOsClient(url='ws://192.168.2.165:5666/websocket?type=main', ping_interval=60)#飞牛地址
    try:
        logger.info("Connecting to WebSocket...")
        await client.connect()
        logger.info("Connection successful.")

        # 管理员登录
        admin_user = 'admin' #飞牛的账号
        admin_pass = 'admin' #飞牛的密码
        login_res = await client.login(admin_user, admin_pass)
        logger.info(f"管理员登录结果: {login_res}")
        if login_res.get('result') == 'succ':
            # 登录成功后自动创建子用户并加入默认用户组
            create_res = await client.request(
                'user.add',
                user='lxt001',#创建的子用户名
                password='932932932',#创建的子用户密码
                groups=["默认用户组"],#创建的子用户组
                comment="某某使用"#创建的子用户备注
            )
            logger.info(f"创建子用户结果: {create_res}")
        else:
            logger.error(f"管理员登录失败: {login_res}")

        # 保持连接一会儿以便接收响应
        try:
            logger.info("Waiting for 3 seconds to receive responses...")
            await asyncio.wait_for(asyncio.Event().wait(), timeout=3.0)
        except asyncio.TimeoutError:
            logger.info("Timeout reached. Proceeding to close client.")

    except KeyboardInterrupt:
        logger.info('Interrupt signal received. Closing client.')
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}", exc_info=True)
    finally:
        if client:
            logger.info('Closing client connection.')
            await client.close()
        logger.info("Script finished.")


if __name__ == "__main__":
    asyncio.run(main())