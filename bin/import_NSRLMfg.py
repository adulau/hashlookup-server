import sys
import redis
rdb = redis.Redis(host='127.0.0.1', port='6666', decode_responses=True)

lines = open('../data/NSRLMfg.txt', 'r')
ln = 0
#rdb.delete("stat:NSRLMfg-import")
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
        print(drecords['MfgCode'])
        rdb.sadd('s:MfgCode', drecords['MfgCode'])
        rdb.hmset("h-MfgCode:{}".format(drecords['MfgCode']), drecords)
        rdb.incrby("stat:NSRLMfg-import")
    if ln == maxvalue:
        sys.exit(1)
    ln = ln + 1
