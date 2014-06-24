## Changelog

### 0.4.0

- allow sharding with custom format (shard, shard_format, shard_prefix, shard_dateformat)
- allow insertion of custom timstamp key with a custom format (time_key, time_format)
- move utc_index out of logstash handler
- treat logstash_format as a shorthand for existing configuration keys

### 0.3.1

- do not generate @timestamp if already part of message (#35)

### 0.3.0

- add `parent_key` option (#28)
- have travis-ci build on multiple rubies (#30)
- add `utc_index` and `hosts` options, switch to using `elasticsearch` gem (#26, #29)

### 0.2.0

- fix encoding issues with JSON conversion and again when sending to elasticsearch (#19, #21)
- add logstash_dateformat option (#20)

### 0.1.4

- add logstash_prefix option

### 0.1.3

- raising an exception on non-success response from elasticsearch

### 0.1.2

- add id_key option

### 0.1.1

- fix timezone in logstash key

### 0.1.0

 - Initial gem release.
