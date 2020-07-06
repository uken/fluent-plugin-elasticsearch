## Index

* [Usage](#usage)
* [Configuration](#configuration)
  + [hash_id_key](#hash_id_key)
  + [include_tag_in_seed](#include_tag_in_seed)
  + [include_time_in_seed](#include_time_in_seed)
  + [use_record_as_seed](#use_record_as_seed)
  + [use_entire_record](#use_entire_record)
  + [record_keys](#record_keys)
  + [separator](#separator)
  + [hash_type](#hash_type)
* [Advanced Usage](#advanced-usage)

## Usage

In your Fluentd configuration, use `@type elasticsearch_genid`. Additional configuration is optional, default values would look like this:

```
<source>
  @type elasticsearch_genid
  hash_id_key _hash
  include_tag_in_seed false
  include_time_in_seed false
  use_record_as_seed false
  use_entire_record false
  record_keys []
  separator _
  hash_type md5
</match>
```

## Configuration

### hash_id_key

```
hash_id_key _id
```

You can specify generated hash storing key.

### include_tag_in_seed

```
include_tag_in_seed true
```

You can specify to use tag for hash generation seed.

### include_time_in_seed

```
include_time_in_seed true
```

You can specify to use time for hash generation seed.

### use_record_as_seed

```
use_record_as_seed true
```

You can specify to use record in events for hash generation seed. This parameter should be used with [record_keys](#record_keys) parameter in practice.

### record_keys

```
record_keys request_id,pipeline_id
```

You can specify keys which are record in events for hash generation seed. This parameter should be used with [use_record_as_seed](#use_record_as_seed) parameter in practice.

### use_entire_record

```
use_entire_record true
```

You can specify to use entire record in events for hash generation seed.


### separator

```
separator |
```

You can specify separator charactor to creating seed for hash generation.

### hash_type

```
hash_type sha1
```

You can specify hash algorithm.

## Advanced Usage

Elasticsearch GenID plugin can handle record contents differing with the following parameters:

```aconf
<filter the.awesome.your.routing.tag>
  @type elasticsearch_genid
  use_entire_record true
  hash_type sha1
  hash_id_key _hash
  separator _
  inc_time_as_key true
  inc_tag_as_key true
</filter>
```

The above configuration can handle tag, time, and record differing and generate different base64 encoded hash per record.
