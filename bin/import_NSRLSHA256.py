import sys
import redis
rdb = redis.Redis(host='127.0.0.1', port='6666', decode_responses=True)

lines = open('../data/rds241-sha256.txt', 'r')
ln = 0
rdb.delete("stat:NSRLsha256-import")
maxvalue = 500000000
headers = ['SHA-1', 'SHA-256', 'filename']
for l in lines:
    records = l.rstrip().split("\t")
    drecords = {}
    for index, value in enumerate(records):
        try:
            drecords[headers[index]] = value
        except:
            continue

    print(drecords)
    print(drecords['SHA-1'])
    #rdb.hmset("h-ProductCode:{}".format(drecords['ProductCode']), drecords)
    rdb.incrby("stat:NSRLsha256-import")
    if ln == maxvalue:
        sys.exit(1)
    ln = ln + 1
