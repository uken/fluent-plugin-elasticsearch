## Changelog [[tags]](https://github.com/uken/fluent-plugin-elasticsearch/tags)

### [Unreleased]

### 1.18.0
- Avoid NoMethodError on unknown Elasticsearch error responses (#487)

### 1.17.2
- add simple sniffer for simple proxy/lb cases (#459)

### 1.17.1
- backport strictness-scheme (#447)

### 1.17.0
- Fix #434 bulk count (#437)

### 1.16.2
- add trace logging to send_bulk (#435)

### 1.16.1
- allow configure of retry_tag so messages can be routed through a different pipeline (#419)
- fix #417. emit_error_event using an exception (#418)

### 1.16.0
- evaluate bulk request failures and reroute failed messages (#405)

### 1.15.2
- handle case where stats not processed in order; add testing (#410)

### 1.15.1
- successful operation if all duplicates (#406)

### 1.15.0
- revert dlq to use router.emit_error_event instead (#402)
- Don't log full response on error (#399)

### 1.14.0
- introduce dead letter queue to handle issues unpacking file buffer chunks (#398)

### 1.13.4
- backport auth: Fix missing auth tokens after reloading connections (#397)

### 1.13.3
- backport removing outdated generating hash id support module (#374)

### 1.13.2
- backport preventing error when using template in elasticsearch_dynamic for elementally use case (#364)

### 1.13.1
- backport adding config parameter to enable elasticsearch-ruby's transporter logging (#343)

### 1.13.0
- Backport allowing to overwrite existing index template (#336)

### 1.12.0
- GA release 1.12.0.

### 1.12.0.rc.1
- Backport separating generate hash id module and bundled new plugin for generating unique hash id (#331)

### 1.11.1
- Raise ConfigError when specifying different @hash_config.hash_id_key and id_key configration (#326)
- backport small typo fix in README.md (#328)

### 1.11.0
- backport adding bulk errors handling (#324)

### 1.10.3
- releasing generating hash id mechanism to avoid records duplication backport (#323)

### 1.10.3.rc.1
- backport Add generating hash id mechanism to avoid records duplication (#323)

### 1.10.2
- backport adding `include_timestamp` option (#311)

### 1.10.1
- backport escaping basic authentication user information placeholders (#309)
- backport handling dynamic config misconfiguration (#308)

### 1.10.0
- backport adding `logstash_prefix_separator` parameter fix
- backport making configuraable SSL/TLS version (#300)
- bump up minimum required Fluentd version to v0.12.10 due to use enum parameter type

### 1.9.7
- fix license identifier in gemspec (#295)

### 1.9.6
- add pipeline parameter (#266)

### 1.9.5
- sub-second time precision [(#249)](https://github.com/uken/fluent-plugin-elasticsearch/pull/249)

### 1.9.4
- Include 'Content-Type' header in `transport_options`

### 1.9.3
- Use latest elasticsearch-ruby (#240)
- Log ES response errors (#230)

### 1.9.2
- Fix elasticsearch_dynamic for v0.14 (#224)

### 1.9.1
- Cast `reload_*` configs in out_elasticsearch_dynamic to bool (#220)

### 1.9.0
- add `time_parse_error_tag` (#211)
- add `reconnect_on_error` (#214)

### 1.9.0.rc.1
- Optimize output plugins (#203)

### 1.8.0
- fix typo in defaults for ssl_verify on elasticsearch_dynamic (#202)
- add support for `templates` (#196)
- rename `send` method to `send_bulk` (#206)

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
