from AsyncYban import AsyncYiban
import config
import asyncio

if __name__ == '__main__':
    task = [AsyncYiban(user["Account"], user["password"]).main() for user in config.user]
    done, pending = asyncio.run(asyncio.wait(task))
    [print(i) for i in list(done)[0].result()]
