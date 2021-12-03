from pathlib import Path
import pathlab
import zipfile
import wget
import sys
import redis
import json
import time
import argparse


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
            self.flushrdb = data["redis"]["flushdb_on_init"]

        self.rdb = redis.Redis(host=redis_host, port=redis_port, decode_responses=True)

    def download(self, dataset=False):
        """ Download a dataset
        :param dataset: The dataset to use. This is a key looked for in the config.json file to get the correct download URL
        """
        if not dataset:
            self.error("no dataset")

        print("**DOWNLOAD** dataset {0} from {1} to {2} .".format(dataset, self.hash_datasets[dataset]["url"], self.local_path))
        wget.download(self.hash_datasets[dataset]["url"], self.local_path)
        print("\nDownload completed.")

    def __process_nsrl_support(self, isofile, dataset_file, key):
        """ Process support NSRL data (OS, Product, Vendor/Manufacturer)
        :param isofile: The object to the ISO file. When set to False this indicates the NSRL is provided in a ZIP format
        :param dataset_file: The location of the dataset, is either a path in the ISO or a direct filepath
        :param key: type of support NSRL data
        """
        print("\n Work on {0}".format(dataset_file))

        if isofile:
            with_element = isofile.IsoPath("/{0}".format(dataset_file)).open()
        else:
            with_element = open(dataset_file, encoding='utf-8')

        ln = 0
        with with_element as f:
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

                    self.rdb.sadd("s:{0}".format(key), drecords[key])
                    self.rdb.hmset("h-{0}:{1}".format(key, drecords[key]), drecords)
                    stat_import_key = dataset_file[dataset_file.rfind("/")+1:dataset_file.rfind(".txt")]
                    self.rdb.incrby("stat:{0}-import".format(stat_import_key))
                    if ln % self.mod_lines == 0:
                        print("  Imported {0} records.".format(ln))

                if ln == self.max_value:
                    break

                ln = ln + 1
            print("  Finished, importing {0} records.".format(ln))

    def __process_nsrl_base(self, isofile, dataset_file, rdbkey):
        """ Process base NSRL data (file hashes)
        :param isofile: The object to the ISO file. When set to False this indicates the NSRL is provided in a ZIP format
        :param dataset_file: The location of the dataset, is either a path in the ISO or a direct filepath
        :param rdbkey: redis database key (corresponds with key of dataset in config.json)
        """
        print("\n Work on {0}".format(dataset_file))

        if isofile:
            # We received the NSRL dataset as an ISO file
            # First get the ZIP from the ISO and then extract the ZIP
            zip_f = open(self.local_path + dataset_file, "wb")
            with isofile.IsoPath("/{0}".format(dataset_file)).open("rb") as f:
                zip_f.write((f.read()))
            zip_f.close()
            zip_f = zipfile.ZipFile(self.local_path + dataset_file)
            zip_f.extractall(self.local_path)

            local_dataset_file = self.local_path + "NSRLFile.txt"
        else:
            # No need to do additional actions
            # We probably received the NSRL as a ZIP file
            local_dataset_file = dataset_file

        ln = 0
        lines = open(local_dataset_file, "r")

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

                # Add some meta data
                drecords['source'] = "NSRL"
                drecords['db'] = rdbkey
                drecords['insert-timestamp'] = time.time()

                # Base records
                self.rdb.set("l:{}".format(drecords['MD5']), drecords['SHA-1'])
                self.rdb.hmset("h:{}".format(drecords['SHA-1']), drecords)
                self.rdb.incrby("stat:{0}".format(rdbkey))
                if ln % self.mod_lines == 0:
                    print("  Imported {0} records.".format(ln))

            if ln == self.max_value:
                break
            ln = ln + 1
        print("  Finished, importing {0} records.".format(ln))

    def process(self, dataset=False):
        """Process a dataset
        :param dataset: The dataset to process
        """
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
            # We read directly from the ISO file
            isofile = pathlab.IsoAccessor(local_dataset)

            self.__process_nsrl_base(isofile, "NSRLFILE.ZIP", dataset)
            self.__process_nsrl_support(isofile, "NSRLMFG.TXT", "MfgCode")
            self.__process_nsrl_support(isofile, "NSRLOS.TXT", "OpSystemCode")
            self.__process_nsrl_support(isofile, "NSRLPROD.TXT", "ProductCode")
        elif dataset_file_type == "zip":
            # Extract the ZIP
            zip_f = zipfile.ZipFile(local_dataset)
            zip_f.extractall(self.local_path)
            # NSRL ZIPs store the datafiles in a subdirectory
            namelist_first = zip_f.namelist()[0]
            zip_extract_path = ""
            if namelist_first[-1] == "/":
                zip_extract_path = self.local_path + namelist_first
            # Indicate we don't have an ISO object
            isofile = False

            self.__process_nsrl_base(isofile, zip_extract_path + "NSRLFile.txt", dataset)
            self.__process_nsrl_support(isofile, zip_extract_path + "NSRLMfg.txt", "MfgCode")
            self.__process_nsrl_support(isofile, zip_extract_path + "NSRLOS.txt", "OpSystemCode")
            self.__process_nsrl_support(isofile, zip_extract_path + "NSRLProd.txt", "ProductCode")

    def init(self, dataset=False):
        """ Remove / Initialize a dataset
        :param dataset: Affected dataset
        """
        if not dataset:
            self.error("no dataset")

        print("**INIT** dataset {0} .".format(dataset))

        if self.flushrdb:
            pass 
        else:
            self.rdb.delete("stat:{0}".format(dataset))
            self.rdb.set("stat:{0}".format(dataset), 0)

    def datasetlist(self):
        """ List the available datasets
        """
        for nsrl in self.hash_datasets:
            print("{0}\n {1}\n from: {2}\n".format(nsrl, self.hash_datasets[nsrl]["description"], self.hash_datasets[nsrl]["url"]))

    def valid_dataset(self, dataset):
        """ Verify if the datset exist
        :param dataset: Affected dataset
        """
        if dataset in self.hash_datasets:
            return True
        else:
            return False

    def error(self, error):
        """ Return an error message and exit
        :param error: Error message
        """
        print("!!ERROR!! {0}".format(error))
        sys.exit()


parser = argparse.ArgumentParser()
group = parser.add_mutually_exclusive_group()
group.add_argument("-l", "--list", action="store_true", help="List datasets available for download and import.")
group.add_argument("-i", "--import-dataset", help="Import a dataset.")
group.add_argument("-e", "--init-dataset", help="Remove / initialize a dataset.")
parser.add_argument("-d", "--skip-download", action="store_true", help="Skip downloading the dataset.")
parser.add_argument("-c", "--skip-init", action="store_true", help="Skip initialization of the database.")
args = parser.parse_args()

import_hash = import_hash()

if args.list:
    import_hash.datasetlist()
elif args.import_dataset:
    dataset = args.import_dataset
    if import_hash.valid_dataset(dataset):
        if not args.skip_download:
            import_hash.download(dataset=dataset)
        if not args.skip_init:
            import_hash.init(dataset=dataset)
        import_hash.process(dataset=dataset)
    else:
        print("Dataset not found.")
elif args.init_dataset:
    dataset = args.init_dataset
    if import_hash.valid_dataset(dataset):
        import_hash.init(dataset=dataset)
    else:
        print("Dataset not found.")
