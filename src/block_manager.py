import time

blocked_ips = {}

BLOCK_TIME = 300

def block_ip(ip):

    blocked_ips[ip] = time.time()

def is_blocked(ip):

    if ip in blocked_ips:

        if time.time() - blocked_ips[ip] < BLOCK_TIME:
            return True

        else:
            del blocked_ips[ip]

    return False