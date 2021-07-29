# hashlookup-server

PoC to better streamline the import of NSRL data.

## Usage

```
$ python3 import-hashlookup-server.py -h
usage: import-hashlookup-server.py [-h] [-l | -i IMPORT_DATASET | -e INIT_DATASET] [-d] [-c]

optional arguments:
  -h, --help            show this help message and exit
  -l, --list            List datasets available for download and import.
  -i IMPORT_DATASET, --import-dataset IMPORT_DATASET
                        Import a dataset.
  -e INIT_DATASET, --init-dataset INIT_DATASET
                        Remove / initialize a dataset.
  -d, --skip-download   Skip downloading the dataset.
  -c, --skip-init       Skip initialization of the database.
```

```
$ python3 import-hashlookup-server.py -i nsrl_minimal
```

## Todo


- ~~Test with the other data sets (currently only Android was tested) : Fetch from ZIP and not ISO file~~
- Move older input scripts to "old" directory 
- Complete with sha256 and xcycl
- Error handling (sufficient drive space, Redis active, check if there is already a db before init)
- Multiple data sets at once?
- Import from MISP (depends on filter)