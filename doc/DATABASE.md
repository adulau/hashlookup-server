# Database structure of hashlookup

## Publish-Subscribe channels

- `nx` JSON message of non-existing hashes searched
- `exist` JSON message of existing hashes searched

## Statistics

- `s:nx:md5` sorted set of MD5 non-existing hashes
- `s:nx:sha1` sorted set of SHA1 non-existing hashes
- `s:exist:md5` sorted set of SHA1 existing hashes
- `s:exixt:sha1` sorted set of SHA1 existing hashes
- `stat:<NSRLname>` string with the number of items imported
