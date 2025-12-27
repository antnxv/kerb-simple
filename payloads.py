import json

from crypt import encrypt



def authenticator(c: str, c_addr: str, timestamp: str, Ksc: str) \
        -> str:
    payload = {
        "c": c,
        "c_addr": c_addr,
        "timestamp": timestamp
    }
    return encrypt(Ksc,
        json.dumps(payload)
    )

def ticket(s: str, c: str, c_addr: str, timestamp: str, life: str, Ksc: str, Ks: str) \
        -> str:
    payload = {
        "s": s,
        "c": c,
        "c_addr": c_addr,
        "timestamp": timestamp,
        "life": life,
        "Ksc": Ksc
    }
    return encrypt(Ks,
        json.dumps(payload)
    )


def auth_req(c: str, s: str) \
        -> str:
    payload = {
        "c": c,
        "s": s
    }

    return json.dumps(payload)

def auth_resp(Kc: str, Ks: str, Kcs: str, Tcs: str) \
        -> str:
    payload = {
        "Kcs": Kcs,
        "Tcs_e": encrypt(Ks, Tcs)
    }

    return encrypt(Kc,
        json.dumps(payload)
    )

def tgs_req(s: str, Tctgs_e: str, Ac: str, Kctgs: str) \
        -> str:
    payload = {
        "s": s,
        "Tctgs_e": Tcs_e,
        "Ac_e": encrypt(Kctgs, Ac)
    }

    return json.dumps(payload)

def tgs_resp(Tcs: str, Ks: str, Kcs: str, Kctgs: str) \
        -> str:
    payload = {
        "Tcs_e": encrypt(Ks, Tcs),
        "Kcs": Kcs,
    }

    return encrypt(Kctgs,
        json.dumps(payload)
    )