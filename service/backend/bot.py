import os
import re
import sys
import json
import datetime
from itertools import takewhile

BOTS_DIR = os.getenv("BOTS_DIR", "/app/bots")
UPLOADS_DIR = os.getenv("UPLOADS_DIR", "/app/uploads")

def bot_info_store(botname, owner, token):
    path = os.path.join(BOTS_DIR, f"{botname}.info")
    with open(path, 'w') as f:
        f.write('{' + ','.join([
            f'"name":"{botname}"',
            f'"owner":"{owner}"',
            f'"token":"{token}"'
        ]) + '}')

def bot_load(bot, username, state):
    botname = bot['username']
    info_file_path = os.path.join(BOTS_DIR, f"{botname}.info")
    if not os.path.isfile(info_file_path):
        return None
    code_file_path = os.path.join(BOTS_DIR, f"{botname}.code")
    if not os.path.isfile(code_file_path):
        return None
    try:
        info = None
        with open(info_file_path, 'r') as f:
            info = json.load(f)
        code = None
        with open(code_file_path, 'r') as f:
            code = json.load(f)

        return {
            'name' : info['name'],
            'owner' : info['owner'],
            'token' : info['token'],
            'user' : username,
            'state' : state,
            'code' : code
        }
    except Exception as e:
        print(e, file=sys.stderr)
        return None

def bot_reply(session, query):
    state = 'init'

    if not session or (not 'state' in session) or (not 'code' in session) or (not (session['state'] in session['code'])):
        print(session, file=sys.stderr)
        return '[Bot init error]', 'init'

    try:
        state = session['state']
        rules = session['code'][state]

        actions = None
        params = None
        for rule in rules:
            r = re.compile(rule['match'], re.IGNORECASE)
            r = re.match(r, query)
            if r:
                actions = rule['actions']
                params = list(r.groups())
                break

        if not actions:
            return '[No bot action]', state

        replies = ''
        for action in actions:
            reply, state = bot_action(session, action, params, state)
            replies += reply
        return replies, state

    except Exception as e:
        print(e, file=sys.stderr)
        return '[Bot process error]', 'init'

def bot_action(session, action, params, state):
    try:
        name = str(action[0]).lower()
        params = list(action[1:]) + list(params)

        if name == 'print':
            params = list(takewhile(bool, params))
            return (' '.join(params)), state
        elif name == 'echo':
            return (' '.join(params) + '\n'), state
        elif name == 'goto':
            print('command goto = ' + str(params[0]), file=sys.stderr)
            return '', params[0]
        elif name == 'owner_file':
            file_path = os.path.join(UPLOADS_DIR, str(session['owner']), str(params[0]))
            if not os.path.isfile(file_path):
                return 'File not found', state
            try:
                reply = open(path, 'r').read()
                return (reply + '\n'), state
            except Exception as e:
                return 'Failed to load file', state
        elif name == 'user_file':
            file_path = os.path.join(UPLOADS_DIR, str(session['user']), str(params[0]))
            if not os.path.isfile(file_path):
                return 'File not found', state
            try:
                reply = open(path, 'r').read()
                return (reply + '\n'), state
            except Exception as e:
                return 'Failed to load file', state
        elif name == 'time':
            return str(datetime.datetime.now().strftime("%H:%M:%S")), state
        elif name == 'date':
            return str(datetime.datetime.now().strftime("%d-%m-%Y")), state
        elif name == 'base64decode':
            try:
                return base64.b64decode(params[0]).decode('utf-8'), state
            except Exception as e:
                return 'Failed to decode base64 string', state
        elif name == 'base64encode':
            try:
                return base64.b64encode(params[0].encode('utf-8')).decode('utf-8'), state
            except Exception as e:
                return 'Failed to encode base64 string', state
        elif name == 'debug':
            file_path = os.path.join(BOTS_DIR, str(session['name']) + '.code')
            if not os.path.isfile(file_path):
                return 'Failed to debug', state
            try:
                reply = open(path, 'r').read()
                return (base64.b64encode(reply.encode('utf-8')).decode('utf-8') + '\n'), state
            except Exception as e:
                return 'Failed to debug', state
        elif name == 'hex2ascii':
            try:
                return bytes.fromhex(params[0]).decode("ascii"), state
            except Exception as e:
                return 'Failed to convert from hex to ascii', state
        elif name == 'ascii2hex':
            try:
                return str(params[0].encode("ascii").hex()), state
            except Exception as e:
                return 'Failed to convert from ascii to hex', state
        elif name == 'dec2bin':
            try:
                return str(bin(int(params[0]))[2:]), state
            except Exception as e:
                return 'Failed to convert from decimal to binary', state
        elif name == 'bin2dec':
            try:
                return str(int(params[0], 2)), state
            except Exception as e:
                return 'Failed to convert from binary to decimal', state
        elif name == 'dec2hex':
            try:
                return str(hex(int(params[0]))[2:]), state
            except Exception as e:
                return 'Failed to convert from decimal to hex', state
        elif name == 'hex2dec':
            try:
                return str(int(params[0], 16)), state
            except Exception as e:
                return 'Failed to convert from hex to decimal', state
        elif name == 'nop':
            return '', state

    except Exception as e:
        print(e, file=sys.stderr)
        return '[Action call failed]', state
