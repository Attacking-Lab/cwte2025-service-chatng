from enochecker3.chaindb import ChainDB
from enochecker3.enochecker import Enochecker
from enochecker3.types import (
    BaseCheckerTaskMessage,
    ExploitCheckerTaskMessage,
    GetflagCheckerTaskMessage,
    InternalErrorException,
    MumbleException,
    PutflagCheckerTaskMessage,
)
from enochecker3.utils import FlagSearcher, assert_in
from typing import Optional, Callable
from httpx import AsyncClient, Response
from logging import LoggerAdapter

from bots import getRandomizedBot

class EnocheckerPatched(Enochecker):
    def _get_http_client(self, task: BaseCheckerTaskMessage) -> AsyncClient:
        return AsyncClient(
            base_url=f"https://{task.address}:{self.service_port}", verify=False
        )

checker = EnocheckerPatched("ChatNG", 3443)
app = lambda: checker.app

import os
import json
import base64
import traceback

import socket
Socket = socket.socket
import random
import string
import hashlib
CHECKER_ENTROPY_SECRET_SEED = 'Th4N0s_m4De_th1s_FoR-T34m_Eur0p3__ChatNG'
ALNUM = string.ascii_letters + string.digits


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

async def do_get_static(logger: LoggerAdapter, client: AsyncClient) -> None:
    r = await client.get("/")
    assert_status_code(logger, r, code=200)
    if not 'Your NextGen Chat' in r.text:
        logger.error(f"Bad response during {r.request.method} {r.request.url.path}")
        raise MumbleException(f"Invalid index page")
    r = await client.get("/static/style.css")
    assert_status_code(logger, r, code=200)
    r = await client.get("/static/chat.js")
    assert_status_code(logger, r, code=200)

async def do_register(logger: LoggerAdapter, client: AsyncClient, username: str, password: str) -> None:
    data = {
        "username": username,
        "password": password
    }
    r = await client.post("/api/auth/register", json=data)
    assert_status_code(logger, r, code=200)

async def do_login(logger: LoggerAdapter, client: AsyncClient, username: str, password: str) -> str:
    data = {
        "username": username,
        "password": password
    }
    r = await client.post("/api/auth/login", json=data)
    assert_status_code(logger, r, code=200)
    data = r.json()

    if not 'username' in data or not 'token' in data or username != data['username']:
        logger.error(f"Bad response code during {r.request.method} {r.request.url.path}: " + f"\n{data}")
        raise MumbleException(f"Invalid login response")

    return data['token']

async def do_get_info(logger: LoggerAdapter, client: AsyncClient, username: str, token: str) -> None:
    r = await client.get("/api/auth/info", headers={'authorization': token})
    assert_status_code(logger, r, code=200)
    data = r.json()

    if not 'username' in data or not 'friends' in data or not 'bots' in data or (username and username != data['username']):
        logger.error(f"Bad server response during {r.request.method} {r.request.url.path}: " + f"\n{data}")
        raise MumbleException(f"Faild to parse info response")

    return {"friends": data['friends'], "bots": data['bots']}

async def do_get_inbox(logger: LoggerAdapter, client: AsyncClient, username: str, token: str) -> None:
    r = await client.get("/api/chat/inbox", headers={'authorization': token})
    assert_status_code(logger, r, code=200)
    data = r.json()
    return data

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

async def do_register_bot(logger: LoggerAdapter, client: AsyncClient, botName: str, botToken: str, token: str) -> None:
    data = {
        "token": botToken,
        "username": botName
    }
    r = await client.post("/api/auth/register_bot", headers={'authorization': token}, json=data)
    assert_status_code(logger, r, code=200)
    data = r.json()
    if not 'msg' in data or data['msg'] != "Bot created":
        logger.error(f"Bad server response during {r.request.method} {r.request.url.path}: " + f"\n{data}")
        raise MumbleException(f"Failed to parse bot register response")

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

def do_socket_connect(logger: LoggerAdapter, address: str) -> Socket:
    try:
        s = socket.create_connection((address, 31337))
        s.settimeout(5)
        return s
    except Exception as e:
        logger.error(f"Failed to start a socket with the mng service: " + f"\n{e}")
        raise MumbleException(f"Failed to connect to mng")

def do_socket_auth(logger: LoggerAdapter, socket: Socket, botName: str, botToken: str) -> None:
    data = None
    try:
        socket.sendall(b'AUTHEN ' + botName.encode() + b' ' + botToken.encode() + b'\n')
        data = recvuntil(socket, b'\n')
    except Exception as e:
        logger.error(f"Failed to send AUTHEN command to the mng service: " + f"\n{e}")
        raise MumbleException(f"Failed to authenticate to mng")
    if data != b'OK authenticated\n':
        logger.error(f"Authentication using the AUTHEN command to the mng service failed: " + f"\n{data}")
        raise MumbleException(f"Failed to authenticate to mng")

def do_socket_setcode(logger: LoggerAdapter, socket: Socket, code: dict) -> None:
    data = None
    try:
        code = base64.b64encode(json.dumps(code).encode())
        socket.sendall(b'SETCODE ' + code + b'\n')
        data = recvuntil(socket, b'\n')
    except Exception as e:
        logger.error(f"Failed to send SETCODE command to the mng service: " + f"\n{e}")
        raise MumbleException(f"Failed to set bot code through mng")
    if data != b'OK code saved\n':
        logger.error(f"Setting bot code using the SETCODE command through the mng service failed: " + f"\n{data}")
        raise MumbleException(f"Failed to set bot code through mng")

def do_socket_getcode(logger: LoggerAdapter, socket: Socket) -> dict:
    data = None
    try:
        socket.sendall(b'GETCODE' + b'\n')
        data = recvuntil(socket, b'\n')
    except Exception as e:
        logger.error(f"Failed to send SETCODE command to the mng service: " + f"\n{e}")
        raise MumbleException(f"Failed to get bot code through mng")
    try:
        data = base64.b64decode(data).decode('utf-8')
    except Exception as e:
        logger.error(f"Failed decode code recovered from SETCODE command on the mng service: " + f"\n{data}")
        raise MumbleException(f"Failed to get bot code through mng")

    return data



@checker.putflag(0)
async def putflag_store1(task: PutflagCheckerTaskMessage, logger: LoggerAdapter, client: AsyncClient, db: ChainDB) -> str:
    gen = RandomGenerator(seed=f"{CHECKER_ENTROPY_SECRET_SEED}|flag_store1|{task.task_id}")
    username = gen.genStr(gen.genInt(8,12))
    password = gen.genStr(gen.genInt(12,16))
    await do_register(logger, client, username, password)

    token = await do_login(logger, client, username, password)
    message = gen.choice(["TODO", "Note for me", "📝", "✍️"]) + " " + task.flag
    await do_send(logger, client, username, message, token)

    data = {
        "username": username,
        "password": password,
        "token": token,
    }
    await db.set("info_flagstore1", json.dumps(data))
    return username

@checker.getflag(0)
async def getflag_store1(task: GetflagCheckerTaskMessage, logger: LoggerAdapter, client: AsyncClient, db: ChainDB) -> None:
    try:
        data = await db.get("info_flagstore1")
        data = json.loads(data)
    except KeyError:
        raise MumbleException("Database info missing")

    username = data['username']
    password = data['password']
    token = data['token']

    # Randomly re-login
    if (random.getrandbits(1)):
        token = await do_login(logger, client, username, password)
    
    r = await client.get("/api/chat/inbox", headers={'authorization': token})
    assert_status_code(logger, r, code=200)

    msgs = None
    try:
        msgs = r.json()
        msgs = ' '.join([(msg['text'] if 'text' in msg else '-') for msg in msgs])
    except Exception as e:
        raise MumbleException("Invalid inbox response")

    assert_in(task.flag, msgs, "Flag missing")

@checker.putflag(1)
async def putflag_store2(task: PutflagCheckerTaskMessage, logger: LoggerAdapter, client: AsyncClient, db: ChainDB) -> str:
    gen = RandomGenerator(seed=f"{CHECKER_ENTROPY_SECRET_SEED}|flag_store2|{task.task_id}")
    username = gen.genStr(gen.genInt(8,12))
    password = gen.genStr(gen.genInt(12,16))
    botname = gen.choice(["bot","Bot", "b0t", "ai", "AI"]) + gen.genStr(gen.genInt(8,12))
    bottoken = gen.genStr(gen.genInt(32,64))

    await do_register(logger, client, username, password)
    token = await do_login(logger, client, username, password)

    await do_register_bot(logger, client, botname, bottoken, token)

    socket = do_socket_connect(logger, task.address)
    do_socket_auth(logger, socket, botname, bottoken)

    code = getRandomizedBot(gen)
    code[gen.genStr(gen.genInt(12,16))] = task.flag
    do_socket_setcode(logger, socket, code)

    data = {
        "username": username,
        "password": password,
        "token": token,
        "botname": botname,
        "bottoken": bottoken
    }
    await db.set("info_flagstore2", json.dumps(data))
    return username

@checker.getflag(1)
async def getflag_store2(task: GetflagCheckerTaskMessage, logger: LoggerAdapter, client: AsyncClient, db: ChainDB) -> None:
    try:
        data = await db.get("info_flagstore2")
        data = json.loads(data)
    except KeyError:
        raise MumbleException("Database info missing")

    botname = data['botname']
    bottoken = data['bottoken']

    socket = do_socket_connect(logger, task.address)
    do_socket_auth(logger, socket, botname, bottoken)
    code = do_socket_getcode(logger, socket)

    text = None
    try:
        code = json.loads(code)
        text = ' '.join([v for v in code.values() if isinstance(v, str)])
    except Exception as e:
        raise MumbleException("Invalid bot code returned")
    
    assert_in(task.flag, text, "Flag missing")

@checker.putnoise(0)
async def putnoise_store1(logger: LoggerAdapter, client: AsyncClient, db: ChainDB) -> None:
    pass

@checker.getnoise(0)
async def getnoise_store1(logger: LoggerAdapter, client: AsyncClient, db: ChainDB) -> None:
    pass

@checker.putnoise(1)
async def putnoise_store2(logger: LoggerAdapter, client: AsyncClient, db: ChainDB) -> None:
    pass

@checker.getnoise(1)
async def getnoise_store2(logger: LoggerAdapter, client: AsyncClient, db: ChainDB) -> None:
    pass

@checker.havoc(0)
async def havoc_store1(logger: LoggerAdapter, client: AsyncClient) -> None:
    pass

@checker.havoc(1)
async def havoc_store2(logger: LoggerAdapter, client: AsyncClient) -> None:
    pass

@checker.exploit(0)
async def exploit_store1_a(task: ExploitCheckerTaskMessage, logger: LoggerAdapter, searcher: FlagSearcher, client: AsyncClient) -> Optional[str]:
    pass

@checker.exploit(1)
async def exploit_store2_a(task: ExploitCheckerTaskMessage, logger: LoggerAdapter, searcher: FlagSearcher, client: AsyncClient) -> Optional[str]:
    pass

'''
# TODO
@checker.putnoise(0)
async def putnoise(logger: LoggerAdapter, client: AsyncClient, db: ChainDB) -> None:
    username = noise(10, 20)
    privkey = await do_register(logger, client, username)

    wish = noise(20, 50)
    await do_launch(logger, client, wish)

    keyvals = [str(v) for v in privkey.vals()]
    await db.set("info", (username, wish, keyvals))

@checker.getnoise(0)
async def getnoise(logger: LoggerAdapter, client: AsyncClient, db: ChainDB) -> None:
    try:
        username, wish, keyvals = await db.get("info")
    except KeyError:
        raise MumbleException("Database info missing")

    keyvals = [int(v) for v in keyvals]
    privkey = crypto.DSAKey(*keyvals)
    await do_login_bad(logger, client, username, privkey)
    await do_login(logger, client, username, privkey)

    data = await do_profile(logger, client)

    try:
        for k,v in privkey.pubkey().dict().items():
            assert data["profile"][k] == str(v)
    except Exception:
        trace = traceback.format_exc()
        logger.error(f"Invalid public key info in profile\n{trace}")
        raise MumbleException("Invalid public key info in profile")

    try:
        assert data["events"][0]["wish"] == wish
    except:
        raise MumbleException("Wish is missing from events logs")

@checker.havoc(0)
async def havoc(logger: LoggerAdapter, client: AsyncClient) -> None:
    await do_register(logger, client, noise(10, 20))

    for _ in range(random.randint(1, 3)):
        await do_launch(logger, client, noise(20, 50))

@checker.exploit(0)
async def exploit_trivial_sig(task: ExploitCheckerTaskMessage, logger: LoggerAdapter, searcher: FlagSearcher, client: AsyncClient) -> Optional[str]:
    if task.attack_info == "":
        raise InternalErrorException("Missing attack info")
    username = task.attack_info

    data = await do_profile(logger, client, username)
    try:
        q = data["profile"]["q"]
    except KeyError:
        raise MumbleException("Missing pubkey q for profile")

    r = await client.get("/challenge")
    assert_status_code(logger, r, code=200)
    challenge = r.text

    data = {
        "username": username,
        "challenge": challenge,
        "signature": f"1,{q}"
    }
    r = await client.post("/login", data=data)
    assert_status_code(logger, r, code=200)

    r = await client.get("/profile")
    assert_status_code(logger, r, code=200)

    flag = searcher.search_flag(r.text)
    return (flag or b"").decode(errors="replace")

@checker.exploit(1)
async def exploit_nonce_reuse(task: ExploitCheckerTaskMessage, logger: LoggerAdapter, searcher: FlagSearcher, client: AsyncClient) -> Optional[str]:
    if task.attack_info == "":
        raise InternalErrorException("Missing attack info")
    username = task.attack_info
    assert username is not None

    data = await do_profile(logger, client, username)
    try:
        p, q, g, y = [int(data["profile"][k]) for k in ("p", "q", "g", "y")]
    except KeyError as e:
        raise MumbleException(f"Missing pubkey components {e} in profile")

    sigpairs = []
    for _ in range(2):
        r = await client.get("/challenge")
        assert_status_code(logger, r, code=200)
        challenge = int(r.text)

        data = {
            "username": username,
            "challenge": challenge,
            "signature": f"1337,1337"
        }
        r = await client.post("/login", data=data)
        assert_status_code(logger, r, code=400)

        try:
            sig = r.text.split("\n")[-1]
            r,s = (int(v) for v in sig.split(","))
        except (KeyError, ValueError):
            raise MumbleException("Correct sig missing from login error")

        sigpairs.append((crypto.H(challenge), (r, s)))

    z1, (r1, s1) = sigpairs[0]
    z2, (r2, s2) = sigpairs[1]

    if r1 != r2:
        raise MumbleException("Signatures do not have same r, exploit fixed?")

    k = divmod(z1 - z2, s1 - s2, q)
    x = divmod(k * s1 - z1, r1, q)
    privkey = crypto.DSAKey(p, q, g, x, y)

    r = await client.get("/challenge")
    assert_status_code(logger, r, code=200)
    z3 = int(r.text)
    r3, s3 = privkey.sign(z3)
    assert privkey.pubkey().verify(z3, (r3, s3))

    await do_login(logger, client, username, privkey)

    r = await client.get("/profile")
    assert_status_code(logger, r, code=200)

    flag = searcher.search_flag(r.text)
    return (flag or b"").decode(errors="replace")

'''

if __name__ == "__main__":
    checker.run()
