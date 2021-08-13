# Database structure of hashlookup

# Statistics

- `s:nx:md5` sorted set of MD5 non-existing hashes looked up
- `s:nx:sha1` sorted set of SHA1 non-existing hashes looked up
- `s:exist:md5` sorted set of SHA1 existing hashes looked up
- `s:exixt:sha1` sorted set of SHA1 existing hashes looked up
