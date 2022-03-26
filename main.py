from AsyncYban import asYiban
import config
import asyncio

if __name__ == '__main__':
    task=[]
    for user in config.user:
        task.append(asYiban(user["Account"],user["password"]).aioyiban())
    asyncio.run(asyncio.wait(task))