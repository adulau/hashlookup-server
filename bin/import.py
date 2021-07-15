import sys
import redis
rdb = redis.Redis(host='127.0.0.1', port='6666', decode_responses=True)

lines = open('../data/NSRLFile.txt', 'r')
ln = 0
rdb.delete("stat:NSRLAndroid")
rdb.set("stat:NSRLAndroid", 0)
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
        print(drecords['SHA-1'])
        rdb.set("l:{}".format(drecords['MD5']), drecords['SHA-1'])
        rdb.hmset("h:{}".format(drecords['SHA-1']), drecords)
        rdb.incrby("stat:NSRLAndroid")
    if ln == maxvalue:
        sys.exit(1)
    ln = ln + 1
