from pathlib import Path
import pathlab
import zipfile
import wget
import sys
import redis
import json


class import_hash:
    def __init__(self):
        with open('config.json') as config_file:
            data = json.load(config_file)
            self.hash_datasets = data["nsrl_downloads"]
            self.max_value = data["import"]["max_value"]
            self.mod_lines = data["import"]["mod_lines"]
            self.local_path = data["local_path"]
            redis_host = data["redis"]["hostname"]
            redis_port = data["redis"]["port"]

        self.rdb = redis.Redis(host=redis_host, port=redis_port, decode_responses=True)

    def download(self, dataset=False):
        if not dataset:
            self.error("no dataset")

        print("**DOWNLOAD** dataset {0} from {1} to {2} .".format(dataset, self.hash_datasets[dataset]["url"], self.local_path))
        wget.download(self.hash_datasets[dataset]["url"], self.local_path)
        print("\nDownload completed.")

    def __process_nsrl_txt(self, isofile, dataset_file, key1, key2):

        print("\n Work on {0}".format(dataset_file))

        ln = 0
        with isofile.IsoPath("/{0}".format(dataset_file)).open() as f:
            while True:
                l = f.readline()

                if not l:
                    break

                if ln == 0:
                    headers = l.rstrip().replace("\"", "").split(",")
                else:
                    records = l.rstrip().replace("\"", "").split(",")
                    drecords = {}
                    for index, value in enumerate(records):
                        try:
                            drecords[headers[index]] = value
                        except:
                            continue

                    self.rdb.sadd("s:{0}".format(key1), drecords[key1])
                    self.rdb.hmset("h-{0}:{1}".format(key1, drecords[key1]), drecords)
                    self.rdb.incrby("stat:{0}-import".format(key2))
                    if ln % self.mod_lines == 0:
                        print("  Imported {0} records.".format(ln))

                if ln == self.max_value:
                    break

                ln = ln + 1
            print("  Finished, importing {0} records.".format(ln))

    def __process_nsrl_zip(self, isofile, dataset_file, key):
        print("\n Work on {0}".format(dataset_file))

        # First get the ZIP from the ISO and then extract the ZIP
        zip_f = open(self.local_path + dataset_file, "wb")
        with isofile.IsoPath("/{0}".format(dataset_file)).open("rb") as f:
            zip_f.write((f.read()))
        zip_f.close()
        zip_f = zipfile.ZipFile(self.local_path + dataset_file)
        zip_f.extractall(self.local_path)
        
        ln = 0
        lines = open(self.local_path + "NSRLFile.txt", "r")

        for l in lines:
            if ln == 0:
                headers = l.rstrip().replace("\"", "").split(",")
            else:
                records = l.rstrip().replace("\"", "").split(",")
                drecords = {}
                for index, value in enumerate(records):
                    try:
                        drecords[headers[index]] = value
                    except:
                        continue

                self.rdb.set("l:{}".format(drecords['MD5']), drecords['SHA-1'])
                self.rdb.hmset("h:{}".format(drecords['SHA-1']), drecords)
                self.rdb.incrby("stat:{0}".format(key))
                if ln % self.mod_lines == 0:
                    print("  Imported {0} records.".format(ln))

            if ln == self.max_value:
                break
            ln = ln + 1
        print("  Finished, importing {0} records.".format(ln))

    def process(self, dataset=False):
        if not dataset:
            self.error("no dataset")

        local_dataset = self.local_path + self.hash_datasets[dataset]["url"][self.hash_datasets[dataset]["url"].rfind("/")+1:]
        local_dataset.lower()
        print("**PROCESS** dataset {0} from location {1} .".format(dataset, local_dataset))

        if not Path(local_dataset).is_file():
            self.error("Cannot find file {0}".format(local_dataset))

        # Determine dataset file type
        dataset_file_type = local_dataset[local_dataset.rfind(".")+1:]

        if dataset_file_type == "iso":
            isofile = pathlab.IsoAccessor(local_dataset)

            self.__process_nsrl_zip(isofile, "NSRLFILE.ZIP", "NSRLAndroid")
            self.__process_nsrl_txt(isofile, "NSRLMFG.TXT", "MfgCode", "NSRLMfg")
            self.__process_nsrl_txt(isofile, "NSRLOS.TXT", "OpSystemCode", "NSRLOS")
            self.__process_nsrl_txt(isofile, "NSRLPROD.TXT", "ProductCode", "NSRLProd")

    def init(self, dataset=False):
        if not dataset:
            self.error("no dataset")

        print("**INIT** dataset {0} .".format(dataset))

        self.rdb.delete("stat:{0}".format(dataset))
        self.rdb.set("stat:{0}".format(dataset), 0)

    def error(self, error):
        print("!!ERROR!! {0}".format(error))
        sys.exit()


import_hash = import_hash()
#import_hash.download(dataset="nsrl_android")
import_hash.init(dataset="nsrl_android")
import_hash.process(dataset="nsrl_android")
