import sys
import redis
rdb = redis.Redis(host='127.0.0.1', port='6666', decode_responses=True)

lines = open('../data/NSRLOS.txt', 'r')
ln = 0
#rdb.delete("stat:NSRLOS-import")
maxvalue = 500000000
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
        print(drecords['OpSystemCode'])
        rdb.sadd('s:OpSystemCode', drecords['OpSystemCode'])
        rdb.hmset("h-OpSystemCode:{}".format(drecords['OpSystemCode']), drecords)
        rdb.incrby("stat:NSRLOS-import")
    if ln == maxvalue:
        sys.exit(1)
    ln = ln + 1
