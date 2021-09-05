version = "1.0"
from flask import Flask, url_for, send_from_directory, render_template, make_response, request
from flask_restx import Resource, Api, reqparse
import redis
import configparser
import json

config = configparser.ConfigParser()
config.read('../etc/server.conf')
stats = config['global'].getboolean('stats')
stats_pubsub = config['global'].getboolean('stats_pubsub')
stats_public = config['global'].getboolean('stats_public')
score = 1
session = config['session'].getboolean('enable')
session_ttl = config['session'].get('ttl')
app = Flask(__name__)
app.url_map.strict_slashes = False
api = Api(app, version=version, title='hashlookup CIRCL API', description='![](https://www.circl.lu/assets/images/circl-logo.png)\n[CIRCL hash lookup](https://hashlookup.circl.lu/) is a public API to lookup hash values against known database of files. NSRL RDS database is included. More database will be included in the future. The API is accessible via HTTP ReST API and the API is also [described as an OpenAPI](https://hashlookup.circl.lu/swagger.json). A [documentation is available with](https://www.circl.lu/services/hashlookup/) some sample queries. The API can be tested live in the interface below.', doc='/', license='CC-BY', contact='info@circl.lu', ordered=True)

rdb = redis.Redis(host='127.0.0.1', port='6666', decode_responses=True)

def is_hex(s):
    try:
        int(s, 16)
        return True
    except ValueError:
        return False

def check_md5(value=None):
    if value is None or len(value) != 32:
        return False
    if not is_hex(value):
        return False
    k = value.upper()
    return k

def check_sha1(value=None):
    if value is None or len(value) != 40:
        return False
    if not is_hex(value):
        return False
    k = value.upper()
    return k

def client_info():
    if request.environ.get('HTTP_X_FORWARDED_FOR') is None:
        ip = request.environ['REMOTE_ADDR']
    else:
        ip = request.environ['HTTP_X_FORWARDED_FOR']
    user_agent = request.headers.get('User-Agent')
    return ({'ip_addr': ip, 'user_agent': user_agent})

def pub_lookup(channel=None, k=None):
    if channel is None:
        return False
    if k is None:
        return False
    client = client_info()
    client['value'] = k
    rdb.publish(channel, json.dumps(client))
    return True

def get_session():
    if session is False:
        return False
    if request.headers.get('hashlookup_session') is None:
        return False
    session_name = request.headers.get('hashlookup_session')
    if not rdb.exists("session:{}".format(session_name)):
        return False
    print("Using session_name: {}".format(session_name))
    ttl = rdb.ttl("session:{}".format(session_name))
    return ttl

@api.route('/lookup/md5/<string:md5>')
@api.doc(description="Lookup MD5.")
class lookup(Resource):
    def get(self, md5):
        if check_md5(value=md5) is False:
            return {'message': 'MD5 value incorrect, expecting a MD5 value in hex format'}, 400
        k = check_md5(value=md5)
        ttl = False
        if session:
            ttl = get_session()
        if not (rdb.exists("l:{}".format(k)) or rdb.exists("h:{}".format(k))):
            if stats:
                rdb.zincrby("s:nx:md5", score, k)
            if stats_pubsub:
                pub_lookup(channel='nx', k=k)
            if session and ttl is not False:
                session_key = "session:{}:nx".format(request.headers.get('hashlookup_session'))
                rdb.sadd(session_key, k)
                rdb.expire(session_key, ttl)
            return {'message': 'Non existing MD5', 'query': md5}, 404
        if stats:
            rdb.zincrby("s:exist:md5", score, k)
        if stats_pubsub:
            pub_lookup(channel='exist', k=k)
        if session and ttl is not False:
            session_key = "session:{}:exist".format(request.headers.get('hashlookup_session'))
            rdb.sadd(session_key, k)
            rdb.expire(session_key, ttl)
        if rdb.exists("h:{}".format(k)) and not rdb.exists("l:{}".format(k)):
            h = rdb.hgetall("h:{}".format(k))
            sha1 = k
        else:
            sha1 = rdb.get("l:{}".format(k))
            h = rdb.hgetall("h:{}".format(sha1))
        if "OpSystemCode" in h:
            if rdb.exists("h-OpSystemCode:{}".format(h['OpSystemCode'])):
                h['OpSystemCode'] = rdb.hgetall("h-OpSystemCode:{}".format(h['OpSystemCode']))
        if "ProductCode" in h:
            if rdb.exists("h-ProductCode:{}".format(h['ProductCode'])):
                h['ProductCode'] = rdb.hgetall("h-ProductCode:{}".format(h['ProductCode']))
        if rdb.exists("p:{}".format(sha1)):
            parents = []
            card = rdb.scard("p:{}".format(sha1))
            if card <= 15:
                p = rdb.smembers("p:{}".format(sha1))
            else:
                p = rdb.srandmember("p:{}".format(sha1), number=10)
            for parent in p:
                parent_details = rdb.hgetall("h:{}".format(parent))
                parents.append(parent_details)
            h['parents'] = parents
        if rdb.exists("c:{}".format(sha1)):
            children = []
            for child in rdb.smembers("c:{}".format(sha1)):
                children.append(child)
            h['children'] = children
        return h 

@api.route('/lookup/sha1/<string:sha1>')
@api.doc(description="Lookup SHA-1.")
class lookup(Resource):
    def get(self, sha1):
        if check_sha1(value=sha1) is False:
            return {'message': 'SHA1 value incorrect, expecting a SHA1 value in hex format'}, 400
        k = check_sha1(value=sha1)
        ttl = False
        if session:
            ttl = get_session()
        if not rdb.exists("h:{}".format(k)):
            if stats:
                rdb.zincrby("s:nx:sha1", score, k)
            if stats_pubsub:
                pub_lookup(channel='nx', k=k)
            if session and ttl is not False:
                session_key = "session:{}:nx".format(request.headers.get('hashlookup_session'))
                rdb.sadd(session_key, k)
                rdb.expire(session_key, ttl)
            return {'message': 'Non existing SHA-1', 'query': sha1}, 404
        if stats:
            rdb.zincrby("s:exist:sha1", score, k)
        if stats_pubsub:
            pub_lookup(channel='exist', k=k)
        if session and ttl is not False:
            session_key = "session:{}:exist".format(request.headers.get('hashlookup_session'))
            rdb.sadd(session_key, k)
            rdb.expire(session_key, ttl)
        h = rdb.hgetall("h:{}".format(k))
        if "OpSystemCode" in h:
            if rdb.exists("h-OpSystemCode:{}".format(h['OpSystemCode'])):
                h['OpSystemCode'] = rdb.hgetall("h-OpSystemCode:{}".format(h['OpSystemCode']))
        if "ProductCode" in h:
            if rdb.exists("h-ProductCode:{}".format(h['ProductCode'])):
                h['ProductCode'] = rdb.hgetall("h-ProductCode:{}".format(h['ProductCode']))
        if rdb.exists("p:{}".format(k)):
            parents = []
            card = rdb.scard("p:{}".format(k))
            if card <= 15:
                p = rdb.smembers("p:{}".format(k))
            else:
                p = []
                p = rdb.srandmember("p:{}".format(k), number=10)
            for parent in p:
                parent_details = rdb.hgetall("h:{}".format(parent))
                parents.append(parent_details)
                h['parents'] = parents
        if rdb.exists("c:{}".format(k)):
            children = []
            for child in rdb.smembers("c:{}".format(k)):
                children.append(child)
            h['children'] = children
        return h

@api.route('/info')
@api.doc(description="Info about the hashlookup database")
class info(Resource):
    def get(self):
        info = {}
        info['nsrl-version'] = rdb.get('nsrl-version')
        info['nsrl-NSRL-items'] = rdb.get('stat:import')
        info['nsrl-NSRL-Legacy-items'] = rdb.get('stat:NSRLLegacy')
        info['nsrl-Android-items'] = rdb.get('stat:NSRLAndroid')
        info['nsrl-iOS-items'] = rdb.get('stat:NSRLiOS')
        info['nsrl-NSRLMfg'] = str(rdb.scard('s:MfgCode'))
        info['nsrl-NSRLOS'] = str(rdb.scard('s:OpSystemCode'))
        info['nsrl-NSRLProd'] = str(rdb.scard('s:ProductCode'))
        info['hashlookup-version'] = version
        return info

@api.route('/bulk/md5')
@api.doc(description="Bulk search of MD5 hashes in a JSON array with the key \'hashes\'.")
class bulkmd5(Resource):
    def post(self):
        json_data = request.get_json(force=True)
        if not 'hashes' in json_data:
            return {'message': 'JSON format incorrect. An array of hashes in the key \'hashes\' is expected.'}, 404
        ret = []
        for val in json_data['hashes']:
            k = val.upper()
            if check_md5(value=k) is False:
                continue
            if not rdb.exists("l:{}".format(k)):
                if stats_pubsub:
                    pub_lookup(channel='nx', k=k)
                continue
            sha1 = rdb.get("l:{}".format(k))
            ret.append(rdb.hgetall("h:{}".format(sha1)))
            if stats:
                rdb.zincrby("s:exist:sha1", score, k)
            if stats_pubsub:
                pub_lookup(channel='exist', k=k)
        return ret

@api.route('/bulk/sha1')
@api.doc(description="Bulk search of SHA1 hashes in a JSON array with the \'hashes\'.")
class bulksha1(Resource):
    def post(self):
        json_data = request.get_json(force=True)
        if not 'hashes' in json_data:
            return {'message': 'JSON format incorrect. An array of hashes in the key \'hashes\' is expected.'}, 404
        ret = []
        for val in json_data['hashes']:
            k = val.upper()
            if check_sha1(value=k) is False:
                continue
            if not rdb.exists("h:{}".format(k)):
                if stats_pubsub:
                    pub_lookup(channel='nx', k=k)
                continue
            k = val.upper()
            ret.append(rdb.hgetall("h:{}".format(k)))
            if stats:
                rdb.zincrby("s:exist:sha1", score, k)
            if stats_pubsub:
                pub_lookup(channel='exist', k=k)
        return ret

@api.route('/session/create/<string:name>')
@api.doc(description="Create a session key to keep search context. The session is attached to a name. After the session is created, the header `hashlookup_session` can be set to the session name.")
class sessioncreate(Resource):
    def get(self, name):
        if name is None or len(name) > 120:
            return {'message': 'Expecting a name for the session'}, 400
        if session is False:
            return {'message': 'Session feature is not enabled'}, 500
        rdb.set('session:{}'.format(name), str(client_info()))
        rdb.expire('session:{}'.format(name), session_ttl)
        return {'message': 'Session {} created and session will expire in {} seconds'.format(name, session_ttl)}


@api.route('/session/get/<string:name>')
@api.doc(description="Return set of matching and non-matching hashes from a session.")
class sessioncreate(Resource):
    def get(self, name):
        if name is None or len(name) > 120:
            return {'message': 'Expecting a name for the session'}, 400
        if session is False:
            return {'message': 'Session feature is not enabled'}, 500
        if not rdb.exists('session:{}'.format(name)):
            return {'message': 'Non-existing session'}, 404
        nx = rdb.smembers('session:{}:nx'.format(name))
        exist = rdb.smembers('session:{}:exist'.format(name))
        ret = {}
        ret['nx'] = list(nx)
        ret['exist'] = list(exist)
        ret['info'] = rdb.get('session:{}'.format(name))
        return ret

@api.route('/stats/top')
@api.doc(description="Return the top 100 of most queried values.")
class stattop(Resource):
    def get(self):
        if stats_public is False:
            return {'message': 'Public statistics not enabled'}, 400
        ret = {}
        ret['nx'] = rdb.zrevrange("s:nx:sha1", 0, 100, withscores=True)
        for val in ret['nx']:
            if rdb.exists("h:".format(val)):
                ret['nx'].remove(val)
        exist = rdb.zrevrange("s:exist:sha1", 0, 100, withscores=True)
        ret['exist'] = []
        for value in exist:
            name = rdb.hget("h:{}".format(value[0]), "FileName")
            entry = {}
            entry['FileName'] = name
            entry['SHA-1'] = value
            ret['exist'].append(entry)
        return ret

if __name__ == '__main__':
        app.run(host='0.0.0.0')
