import asyncio
from gravixhost.main import create_app

if __name__ == "__main__":
    asyncio.run(create_app()())