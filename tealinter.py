#!/usr/bin/env python3

import sys
import re
import base64
import httpx

from algosdk.v2client.algod import AlgodClient

algod_token  = 'a' * 64
algod_server = 'http://127.0.0.1:4001'
algod_server = 'http://192.168.1.142:4001'
algod_client = AlgodClient(algod_token, algod_server)
httpx_headers = {'X-Algo-API-Token': algod_token}

intcblock = []
bytecblock = []
def process(pl, l):
    if l.startswith('intcblock '):
        for i in l[10:].split():
            intcblock.append(i)
        return l
    if l.startswith('bytecblock '):
        for i in l[11:].split():
            bytecblock.append(i)
        return l
    else:
        return l

ops = {
    r'^(#pragma version [0-9]*)$': r'\1\n',
    r'^bytec.[0-9]* // (.*)$': r'byte \1',
    r'^intc.[0-9]* // (.*)$': r'int \1',
    r'^pushbytes .* // (.*)$': r'byte \1',
    r'^pushint (.*)': r'int \1',
    r'^intcblock .*\n': '',
    r'^bytecblock .*\n': '',
    r'^(b[nz]* .*)$': r'\1\n',
    r'^(ret[urnsb]*)$': r'\1\n',
    r'^assert$': r'assert\n',
    r'^err$': r'err\n',
    r'^(app_.*_put)$': r'\1\n',
    r'^byte addr (.*)$': r'addr \1',
}
def lint(teal: str):
    formatted_teal = ''
    previous_line = ''
    for line in teal.splitlines():
        output = line + '\n'
        for op in ops:
            output = re.sub(op, ops[op], output)
        #output = process(previous_line, output) # Turns out I should hold a context and pass that instead.
        formatted_teal += output
        previous_line = output
    return formatted_teal

if __name__ == "__main__":
    if len(sys.argv) == 2:
        try:
            app_id = int(sys.argv[1])
            app = algod_client.application_info(app_id)

            approval_b64 = app['params']['approval-program']
            approval_bin = base64.b64decode(approval_b64)
            r = httpx.post(f"{algod_server}/v2/teal/disassemble", data=approval_bin, headers=httpx_headers)
            approval_teal = r.json()['result']

            clearstate_b64 = app['params']['clear-state-program']
            clearstate_bin = base64.b64decode(clearstate_b64)
            r = httpx.post(f"{algod_server}/v2/teal/disassemble", data=clearstate_bin, headers=httpx_headers)
            clearstate_teal = r.json()['result']
        except Exception as e:
            quit(e)
        print(lint(approval_teal))
        quit()

    if sys.stdin.isatty():
        quit("Pipe only")
    else:
        teal = sys.stdin.read()
        sys.stdout.writelines(lint(teal))

