version = "1.0"
from flask import Flask, url_for, send_from_directory, render_template, make_response, request
from flask_restx import Resource, Api, reqparse
import redis
import configparser

config = configparser.ConfigParser()
config.read('../etc/server.conf')
stats = config['global'].getboolean('stats')
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

@api.route('/lookup/md5/<string:md5>')
@api.doc(description="Lookup MD5.")
class lookup(Resource):
    def get(self, md5):
        if md5 is None or len(md5) != 32:
            return {'message': 'Expecting a MD5 hex value'}, 400 
        if not is_hex(md5):
            return {'message': 'MD5 is not in hex format'}, 400
        k = md5.upper()
        score = 1
        if not rdb.exists("l:{}".format(k)):
            rdb.zincrby("s:nx:md5", score, k)
            return {'message': 'Non existing MD5', 'query': md5}, 404
        if stats:
            rdb.zincrby("s:exist:md5", score, k)
        sha1 = rdb.get("l:{}".format(k))
        h = rdb.hgetall("h:{}".format(sha1)) 
        if "OpSystemCode" in h:
            if rdb.exists("h-OpSystemCode:{}".format(h['OpSystemCode'])):
                h['OpSystemCode'] = rdb.hgetall("h-OpSystemCode:{}".format(h['OpSystemCode']))
        if "ProductCode" in h:
            if rdb.exists("h-ProductCode:{}".format(h['ProductCode'])):
                h['ProductCode'] = rdb.hgetall("h-ProductCode:{}".format(h['ProductCode']))
        return h 

@api.route('/lookup/sha1/<string:sha1>')
@api.doc(description="Lookup SHA-1.")
class lookup(Resource):
    def get(self, sha1):
        if sha1 is None or len(sha1) != 40:
            return {'message': 'Expecting a SHA-1 hex value'}, 400
        if not is_hex(sha1):
            return {'message': 'SHA-1 is not in hex format'}, 400
        k = sha1.upper()
        score = 1
        if not rdb.exists("h:{}".format(k)):
            rdb.zincrby("s:nx:sha1", score, k)
            return {'message': 'Non existing SHA-1', 'query': sha1}, 404
        if stats:
            rdb.zincrby("s:exist:sha1", score, k)
        h = rdb.hgetall("h:{}".format(k))
        if "OpSystemCode" in h:
            if rdb.exists("h-OpSystemCode:{}".format(h['OpSystemCode'])):
                h['OpSystemCode'] = rdb.hgetall("h-OpSystemCode:{}".format(h['OpSystemCode']))
        if "ProductCode" in h:
            if rdb.exists("h-ProductCode:{}".format(h['ProductCode'])):
                h['ProductCode'] = rdb.hgetall("h-ProductCode:{}".format(h['ProductCode']))
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
            if not rdb.exists("l:{}".format(val.upper())):
                continue
            sha1 = rdb.get("l:{}".format(val.upper()))
            ret.append(rdb.hgetall("h:{}".format(sha1)))
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
            ret.append(rdb.hgetall("h:{}".format(val.upper())))
        return ret


if __name__ == '__main__':
        app.run(host='0.0.0.0')
