import sys
import redis
rdb = redis.Redis(host='127.0.0.1', port='6666', decode_responses=True)

lines = open('../data/xcyclopedia/strontic-xcyclopedia.csv', 'r')
ln = 0
rdb.delete("stat:xcyclopedia-import")
maxvalue = 5000000000
for l in lines:
    if ln == 0:
        headers = l.rstrip().replace("\"","").split(",")
        print (headers)
    else:
        records = l.rstrip().replace("\"","").split(",")
        drecords = {}
        for index, value in enumerate(records):
            try:
                drecords[headers[index]] = value
            except:
                continue

        print(drecords)
        print(drecords['hash_md5'])
        #rdb.set("l:{}".format(drecords['hash_md5']), drecords['hash_sha1'])
        #rdb.hmset("h:{}".format(drecords['hash_sha1']), drecords)
        #rdb.incrby("stat:xcyclopedia-import")
    if ln == maxvalue:
        sys.exit(1)
    ln = ln + 1
