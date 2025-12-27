import json
import fcntl, pickle
import os, argparse
import time, uuid, random, string

import hashlib

import payloads
from crypt import encrypt, decrypt
from config import config

def authenticate():
    global name
    global keys
    global tickets

    payload = payloads.auth_req(
        c=name,
        s='tgs'
    )

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(('localhost', 8001))
        s.sendall(payload)
        
        response = s.recv(4096)
    
    payload = json.loads(
        decrypt(keys[name], response.decode('utf-8'))
    )

    keys['tgs'] = payload['Kcs']
    tickets['tgs'] = payload['Tcs_e']

def get_ticket(service: str):
    global name
    global keys
    global tickets
    
    Ac = payloads.authenticator(
        c=name,
        c_addr=bytes([0, 0, 0, 0]),
        timestamp=f'{time.time()}',
        Ksc=keys['tgs']
    )

    payload = payloads.tgs_req(
        s=service,
        Tctgs_e=tickets['tgs'],
        Ac=Ac,
        Kctgs=keys['tgs']
    )

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(('localhost', 8002))
        s.sendall(payload)
        
        response = s.recv(4096)
    
    tgs_resp = json.loads(
        decrypt(keys['tgs'], response.decode('utf-8'))
    )

    keys[service] = payload['Kcs']
    tickets[service] = payload['Tcs_e']

def service(msg: str):
    pass

if __name__ == '__main__':
    global name
    global passwd
    global keys
    global tickets

    parser = argparse.ArgumentParser(prog='client')
    parser.add_argument('-u', '--name', type=str)
    parser.add_argument('-p', '--passwd', type=str)
    args = parser.parse_args()

    name = args.name
    if name:
        print(f'name: {name}')
    else:
        name = uuid.uuid4().hex
        print(f'default name: {name}')
    
    passwd = args.passwd
    if passwd:
        print(f'passwd: {passwd}')
    else:
        passwd = ''.join(random.sample(string.ascii_letters+string.digits, 20))
        print(f'default passwd: {passwd}')

    salt = os.urandom(16)

    keys = {}
    tickets = {}
    keys[name] = hashlib.pbkdf2_hmac(
        hash_name='sha256',
        password=passwd.encode('utf-8'),
        salt=salt,
        iterations=config['iterations'],
        dklen=config['bytes']
    )

    try:
        kdbf = open(config['dataset_path'], 'rb+')
        fcntl.flock(kdbf.fileno(), fcntl.LOCK_EX)
        kdb = pickle.load(kdbf)
    except FileNotFoundError:
        kdbf = open(config['dataset_path'], 'wb')
        fcntl.flock(kdbf.fileno(), fcntl.LOCK_EX)
        kdb = {}
    
    if name in kdb:
        print('Client exists in KDB')
        fcntl.flock(kdbf.fileno(), fcntl.LOCK_UN)
        kdbf.close()

        # login attempt
        Kcc = hashlib.pbkdf2_hmac(
            hash_name='sha256',
            password=passwd.encode('utf-8'),
            salt=kdb[name][''],
            iterations=config['iterations'],
            dklen=config['bytes']
        )

        if Kcc == kdb[name][name]:
            keys[name] = Kcc
            # future: expire old keys?
            print('Login successful')
        else:
            raise ValueError('Login failed: incorrect password')
            exit(-1)
    else:
        kdb[name] = {'': salt, name: keys[name]}
        kdbf.seek(0)
        kdbf.truncate()
        pickle.dump(kdb, kdbf)
        fcntl.flock(kdbf.fileno(), fcntl.LOCK_UN)
        kdbf.close()
        print('Client added to KDB')
