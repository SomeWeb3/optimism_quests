from main import run
import asyncio
from os import environ
from dotenv import load_dotenv

if __name__ == '__main__':
    load_dotenv()
    time_sleep = eval(environ["SLEEP"])
    print(time_sleep)
    asyncio.run(run())
