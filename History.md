## Changelog

### Future

### 0.9.0
- Add new `allow_overrides` option

### 0.8.0
- Replace Patron with Excon HTTP client

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
