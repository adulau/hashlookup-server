# Database structure of hashlookup

## hash storage

- `l:<md5>` key/value -> {sha1, sha1}
- `h:<sha1>` hash -> keys from NSRL or other data sources
- `p:<sha1>` set -> {sha1, sha1} for the parents of a hash (such as original packages)
- `c:<sha1>` set -> {sha1, sha1} for the children of a hash (such as files contained in a package)

### Standard keys

- `MD5`
- `SHA-1`
- `SHA-256`
- `TLSH`
- `SSDEEP`
- `FileName`
- `FileSize`
- `PackageArch`
- `PackageDescription`
- `PackageMaintainer`
- `PackageName`
- `PackageRelease`
- `PackageVersion`
- `KnownMalicious`

## Publish-Subscribe channels

- `nx` JSON message of non-existing hashes searched
- `exist` JSON message of existing hashes searched

## Statistics

- `s:nx:md5` sorted set of MD5 non-existing hashes
- `s:nx:sha1` sorted set of SHA1 non-existing hashes
- `s:exist:md5` sorted set of SHA1 existing hashes
- `s:exist:sha1` sorted set of SHA1 existing hashes
- `stat:<NSRLname>` string with the number of items imported
