version = "0.1"
from nserver import NameServer, Response, A, NS, TXT
import redis
import json
import re

rdb = redis.Redis(host='127.0.0.1', port='6666', decode_responses=True)


ns = NameServer("dns.hashlookup.circl.lu")

@ns.rule("info.dns.hashlookup.circl.lu", ["TXT"])
def say_info(query):
    #if query.name.endswith(".com.au"):
    #    return TXT(query.name, "G'day mate")
    info = {}
    info['nsrl-version'] = rdb.get('nsrl-version')
    info['nsrl-NSRL-items'] = rdb.get('stat:import')
    info['nsrl-Android-items'] = rdb.get('stat:NSRLAndroid')
    info['nsrl-iOS-items'] = rdb.get('stat:NSRLiOS')
    info['nsrl-NSRLMfg'] = rdb.get('stat:NSRLMfg-import')
    info['nsrl-NSRLOS'] = rdb.get('stat:NSRLOS-import')
    info['nsrl-NSRLProd'] = rdb.get('stat:NSRLProd-import')
    info['hashlookup-version'] = version
    return TXT(query.name, json.dumps(info))

@ns.rule("**", ["TXT"])
def wildcard_hashlookup(query):
    hashq = query.name.split('.', 1)
    print(hashq[0])
    if re.findall(r"^[a-fA-F\d]{32}$", hashq[0]):
        print("MD5")
        sha1 = rdb.get("l:{}".format(hashq[0].upper()))
    elif re.findall(r"^[a-fA-F\d]{40}$", hashq[0]):
        print("SHA-1")
        sha1 = hashq[0].upper()
    else:
        return Response()
    if sha1 is None:
        return Response()
    if not rdb.exists("h:{}".format(sha1.upper())):
        return Response()
    h = {}
    h['SHA-1'] = rdb.hget("h:{}".format(sha1), 'SHA-1')
    h['MD5'] = rdb.hget("h:{}".format(sha1), 'MD5')
    h['FileName'] = rdb.hget("h:{}".format(sha1), 'FileName')
    print(h)
    #if "OpSystemCode" in h:
    #    if rdb.exists("h-OpSystemCode:{}".format(h['OpSystemCode'])):
    #        h['OpSystemCode'] = rdb.hgetall("h-OpSystemCode:{}".format(h['OpSystemCode']))
    #if "ProductCode" in h:
    #    if rdb.exists("h-ProductCode:{}".format(h['ProductCode'])):
    #        h['ProductCode'] = rdb.hgetall("h-ProductCode:{}".format(h['ProductCode']))

    return TXT(query.name, json.dumps(h))


if __name__ == "__main__":
    ns.settings.SERVER_PORT = 53  # It's over 9000!
    ns.settings.SERVER_ADDRESS = "185.194.93.133"
    ns.run()
