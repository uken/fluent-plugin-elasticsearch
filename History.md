## Changelog [[tags]](https://github.com/uken/fluent-plugin-elasticsearch/tags)

### Future

### 1.7.0
- add support for `template_name` and `template_file` (#194)

### 1.6.0
- add support for dot separated `target_index_key` and `target_type_key` (#175)
- add `remove_keys_on_update` and `remove_keys_on_update_key` (#189)
- fix support for fluentd v0.14 (#191)
- remove support for elasticsearch v2 for now (#177)

### 1.5.0
- add `routing_key` (#158)
- add `time_key_exclude_timestamp` to exclude `@timestamp` (#161)
- convert index names to lowercase (#163)
- add `remove_keys` (#164)
- add `flatten_hashes` (#168)
- add `target_type_key` (#169)

### 1.4.0
- add `target_index_key` to specify target index (#153)
- add `time_key_format` for faster time format parsing (#154)

### 1.3.0
- add `write_operation`

### 1.2.1
- fix `resurrect_after` in out_elasticsearch_dynamic

### 1.2.0
- out_elasticsearch_dynamic get memory improvement and fix for race condition (#133)
- Add `resurrect_after` option (#136)

### 1.1.0
- Support SSL client verification and custom CA file (#123)
- Release experimental `type elasticsearch_dynamic` (#127)

### 1.0.0
- password config param is now marked as secret and won't be displayed in logs.

### 0.9.0
- Add `ssl_verify` option (#108)

### 0.8.0
- Replace Patron with Excon HTTP client (#93)

### 0.7.0
- Add new option `time_key` (#85)

### 0.6.1
- 0.10.43 is minimum version required of fluentd (#79)

### 0.6.0
- added `reload_on_failure` and `reload_connections` flags (#78)

### 0.5.1
- fix legacy hosts option, port should be optional (#75)

### 0.5.0
- add full connection URI support (#65)
- use `@timestamp` for index (#41)
- add support for elasticsearch gem version 1 (#71)
- fix connection reset & retry when connection is lost (#67)

### 0.4.0
- add `request_timeout` config (#59)
- fix lockup when non-hash values are sent (#52)

### 0.3.1
- force using patron (#46)
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
