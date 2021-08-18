# hashlookup-server

hashlookup-server is a minimal and fast open source server (ReST/API) to lookup quickly hash value from large dataset.

The code was quickly written during some boring meetings. The code is still alpha and installation documentation is missing. I released it for the adventurous people
who love to dig into new experimental projects.

# Features

- ReST API to lookup MD5 and SHA-1 hashes or bulk search from large dataset
- A simple DNS server to provide hash lookup via DNS queries
- Import scripts for the [NSRL database](https://www.nist.gov/itl/ssd/software-quality-group/national-software-reference-library-nsrl)
- Support creation of DFIR session to keep track of systems analysed

# Requirements

The server requires a recent version of Python (Python 3.6 or better) and a [kvrocks](https://github.com/KvrocksLabs/kvrocks) database.

If you don't want to run your own local server, you can use and test [hashlookup.circl.lu](https://hashlookup.circl.lu/).

## Public Online version - CIRCL hashlookup (hashlookup.circl.lu)

[CIRCL hash lookup](https://hashlookup.circl.lu/) is a public API to lookup hash values against known database of files. NSRL RDS database is included. More database will be included in the future. The API is accessible via HTTP ReST API and the API is also [described as an OpenAPI](https://hashlookup.circl.lu/swagger.json).

# Is it a database of malicious or non-malicious hash of files?

CIRCL hashlookup service only gives details about known files appearing in specific database(s). This gives you context and information about file hashes which can be discovered during investigation or digital forensic analysis.

# Installation

- Make sure kvrocks is installed
- Download the [NSRL files](https://www.nist.gov/itl/ssd/software-quality-group/national-software-reference-library-nsrl/nsrl-download/current-rds)
- In **bin/run.sh** point to where kvrocks is installed
- - For example "/home/ubuntu/kvrocks/src/kvrocks -c /home/ubuntu/hashlookup-server/etc/kvrocks.conf"
- In **kvrocks.conf** change
- - **dir** to where you want to store the database
- - update **pidfile** **backup-dir** and **log-dir**
- in **import.py** : point to where you stored the NSRL downloaded files
- statistics are kept in stat:NSRLAndroid
- do a test run, in import.py change maxvalue to 2, run import.py and then query the results
- - redis-cli -p 6666
- - HGETALL "h:000000F694CA9BF73836D67DEB5E2724338B422D"


# API Usage

## Get information about the hash lookup database (via ReST)

~~~
curl -X 'GET' \
  'https://hashlookup.circl.lu/info' \
  -H 'accept: application/json'
~~~

~~~json
{
  "nsrl-version": "RDS Verion 2.73.1 - July 2021",
  "nsrl-NSRL-items": "165968856",
  "nsrl-NSRL-Legacy-items": "113737918",
  "nsrl-Android-items": "33419323",
  "nsrl-iOS-items": "46447082",
  "nsrl-NSRLMfg": "92353",
  "nsrl-NSRLOS": "1331",
  "nsrl-NSRLProd": "19050",
  "hashlookup-version": "1.0"
}
~~~


## Perform an MD5 hash lookup

~~~
curl -X 'GET' \
  'https://hashlookup.circl.lu/lookup/md5/8ED4B4ED952526D89899E723F3488DE4' \
  -H 'accept: application/json'
~~~

~~~json
{
  "CRC32": "7A5407CA",
  "FileName": "wow64_microsoft-windows-i..timezones.resources_31bf3856ad364e35_10.0.16299.579_de-de_f24979c73226184d.manifest",
  "FileSize": "2520",
  "MD5": "8ED4B4ED952526D89899E723F3488DE4",
  "OpSystemCode": {
    "MfgCode": "1006",
    "OpSystemCode": "362",
    "OpSystemName": "TBD",
    "OpSystemVersion": "none"
  },
  "ProductCode": {
    "ApplicationType": "Security",
    "Language": "Multilanguage",
    "MfgCode": "608",
    "OpSystemCode": "868",
    "ProductCode": "190742",
    "ProductName": "Cumulative Update for Windows Server 2016 for x64 (KB4338817)",
    "ProductVersion": "1709"
  },
  "SHA-1": "00000079FD7AAC9B2F9C988C50750E1F50B27EB5",
  "SpecialCode": ""
}
~~~

## Perform an SHA-1 hash lookup

~~~
curl -X 'GET'   'https://hashlookup.circl.lu/lookup/sha1/FFFFFDAC1B1B4C513896C805C2C698D9688BE69F'   -H 'accept: application/json' | jq .
~~~

~~~json
{
  "CRC32": "CBD64CD9",
  "FileName": ".rela.dyn",
  "FileSize": "240",
  "MD5": "131312A96CAD4ACAA7E2631A34A0D47C",
  "OpSystemCode": {
    "MfgCode": "1006",
    "OpSystemCode": "362",
    "OpSystemName": "TBD",
    "OpSystemVersion": "none"
  },
  "ProductCode": {
    "ApplicationType": "Operating System",
    "Language": "English",
    "MfgCode": "1722",
    "OpSystemCode": "599",
    "ProductCode": "163709",
    "ProductName": "BlackArch Linux",
    "ProductVersion": "2017.03.01"
  },
  "SHA-1": "FFFFFDAC1B1B4C513896C805C2C698D9688BE69F",
  "SpecialCode": ""
}
~~~


## Bulk search of MD5 hashes

~~~
curl -X 'POST'   'https://hashlookup.circl.lu/bulk/md5' -H "Content-Type: application/json"  -d "{\"hashes\": [\"6E2F8616A01725DCB37BED0A2495AEB2\", \"8ED4B4ED952526D89899E723F3488DE4\", \"344428FA4BA313712E4CA9B16D089AC4\"]}" | jq .
~~~

~~~json
[
  {
    "CRC32": "E774FD92",
    "FileName": "network",
    "FileSize": "7279",
    "MD5": "6E2F8616A01725DCB37BED0A2495AEB2",
    "OpSystemCode": "362",
    "ProductCode": "8321",
    "SHA-1": "00000903319A8CE18A03DFA22C07C6CA43602061",
    "SpecialCode": ""
  },
  {
    "CRC32": "7A5407CA",
    "FileName": "wow64_microsoft-windows-i..timezones.resources_31bf3856ad364e35_10.0.16299.579_de-de_f24979c73226184d.manifest",
    "FileSize": "2520",
    "MD5": "8ED4B4ED952526D89899E723F3488DE4",
    "OpSystemCode": "362",
    "ProductCode": "190742",
    "SHA-1": "00000079FD7AAC9B2F9C988C50750E1F50B27EB5",
    "SpecialCode": ""
  },
  {
    "CRC32": "7516A25F",
    "FileName": ".text._ZNSt14overflow_errorC1ERKSs",
    "FileSize": "33",
    "MD5": "344428FA4BA313712E4CA9B16D089AC4",
    "OpSystemCode": "362",
    "ProductCode": "219181",
    "SHA-1": "0000001FFEF4BE312BAB534ECA7AEAA3E4684D85",
    "SpecialCode": ""
  }
]
~~~

# Bulk search of SHA-1 hashes

~~~
curl -X 'POST'   'https://hashlookup.circl.lu/bulk/sha1' -H "Content-Type: application/json"  -d "{\"hashes\": [\"FFFFFDAC1B1B4C513896C805C2C698D9688BE69F\", \"FFFFFF4DB8282D002893A9BAF00E9E9D4BA45E65\", \"FFFFFE4C92E3F7282C7502F1734B243FA52326FB\"]}" | jq .
~~~

~~~json
[
  {
    "CRC32": "CBD64CD9",
    "FileName": ".rela.dyn",
    "FileSize": "240",
    "MD5": "131312A96CAD4ACAA7E2631A34A0D47C",
    "OpSystemCode": "362",
    "ProductCode": "163709",
    "SHA-1": "FFFFFDAC1B1B4C513896C805C2C698D9688BE69F",
    "SpecialCode": ""
  },
  {
    "CRC32": "8654F11A",
    "FileName": "s_copypix.c",
    "FileSize": "19541",
    "MD5": "559D049F44942683093A91BA19D0AF54",
    "OpSystemCode": "362",
    "ProductCode": "215139",
    "SHA-1": "FFFFFF4DB8282D002893A9BAF00E9E9D4BA45E65",
    "SpecialCode": ""
  },
  {
    "CRC32": "8E51A269",
    "FileName": "358.git2-msvstfs.dll",
    "FileSize": "65",
    "MD5": "9E4C165089CBA3653484C3F23F1CBC67",
    "OpSystemCode": "362",
    "ProductCode": "201317",
    "SHA-1": "FFFFFE4C92E3F7282C7502F1734B243FA52326FB",
    "SpecialCode": ""
  }
]
~~~

## API and HTTP return codes

|HTTP return code | Description and Interpretation|
|---|---|
|200| 200 means the searched hash is present in at least one of the database|
|404| 404 means the searched hash is not present in the any of the database|
|400| 400 means the input used for the hash is in an incorrect format|

# API and Session

A session feature can be enabled on the server side (not enabled on the public instance of CIRCL) to easily track submitted hashes.

The session created has a TTL, and after the expiration, the associated queries of the session will be removed. This feature can be used
to separate different forensic analysis and gather all the results in one go later.

## Create a session

A session can be created via the `/session/create/` endpoint with the name of the session. If the session is recreated, the TTL is reset to the default value.

~~~
curl -X 'GET'   'http://127.0.0.1:5000/session/create/test'   -H 'accept: application/json'
~~~

~~~json
{
  "message": "Session test created and session will expire in 86400 seconds"
}
~~~

## Use a session

To assign the results to a specific session, the `hashlookup_session` header requires to be set with the name of the created session. This can be used on all the `lookup` api endpoints.

~~~
curl -X 'GET'   'http://127.0.0.1:5000/lookup/md5/8ED4B4ED952526D89899E723F3488DE4'  -H 'hashlookup_session: test' -H 'accept: application/json' | jq .
~~~

## Fetch a session

~~~
curl -s -X 'GET'   'http://127.0.0.1:5000/session/get/test' -H 'accept: application/json' | jq .
~~~

~~~json
{
  "nx": [
    "8ED4B4ED952526D89899E723F3488DE2",
    "8ED4B4ED952526D89899E723F3488DE3"
  ],
  "exist": [
    "8ED4B4ED952526D89899E723F3488DE4"
  ],
  "info": "{'ip_addr': '127.0.0.1', 'user_agent': 'curl/7.78.0'}"
}
~~~

# Querying the hashlookup database via DNS

The domain to query is `<query>.dns.hashlookup.circl.lu`. The query can be `info` or an MD5 or SHA-1 value.

## Info of the hashlookup database

```
dig +short -t TXT info.dns.hashlookup.circl.lu | jq -r . | jq .
```

~~~json
{
  "nsrl-version": "RDS Verion 2.73.1 - July 2021",
  "nsrl-NSRL-items": "165968856",
  "nsrl-Android-items": "33419323",
  "nsrl-iOS-items": "46447082",
  "nsrl-NSRLMfg": "543004",
  "nsrl-NSRLOS": "6414",
  "nsrl-NSRLProd": "333546",
  "hashlookup-version": "0.1"
}
~~~

## Query of a hash

```
dig +short -t TXT 931606baaa7a2b4ef61198406f8fc3f4.dns.hashlookup.circl.lu | jq -r . | jq .
```

~~~json
{
  "CRC32": "13C49389",
  "FileName": "ls",
  "FileSize": "133792",
  "MD5": "931606BAAA7A2B4EF61198406F8FC3F4",
  "OpSystemCode": "362",
  "ProductCode": "217853",
  "SHA-1": "D3A21675A8F19518D8B8F3CEF0F6A21DE1DA6CC7",
  "SpecialCode": ""
}
~~~



# Sample digital forensic use-cases

## How to quickly check a set of files in a local directory?

```
sha1sum * | cut -f1 -d" " | parallel 'curl  -s https://hashlookup.circl.lu/lookup/sha1/{}' | jq .
```

Negative output (hash not existing in the database) can be excluded with the `-f` option of `curl`.

```
sha1sum * | cut -f1 -d" " | parallel 'curl -f -s https://hashlookup.circl.lu/lookup/sha1/{}' | jq .
```

## Libraries and Software available which use CIRCL hashlookup

- [PyHashlookup](https://github.com/CIRCL/PyHashlookup) is a client API in Python to query CIRCL hashlookup.
- [The Hive Project - Cortex Analyzers](https://github.com/TheHive-Project/Cortex-Analyzers/pull/1015) pull-request to be integrated in The Hive Cortex Analyzers.

# License

This software is licensed under GNU Affero General Public License version 3.

- Copyright (C) 2021 CIRCL - Computer Incident Response Center Luxembourg
- Copyright (C) 2021 Alexandre Dulaunoy
