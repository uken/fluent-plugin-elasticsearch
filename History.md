## Changelog [[tags]](https://github.com/uken/fluent-plugin-elasticsearch/tags)

### [Unreleased]

### 4.0.10
- filter_elasticsearch_genid: Use entire record as hash seed (#777)
- Suppress type in meta with suppress_type_name parameter (#774)
- filter\_elasticsearch\_genid: Add hash generation mechanism from events (#773)
- Clean up error text (#772)
- Use GitHub Actions badges instead of Travis' (#760)
- Add issue auto closer workflow (#759)
- Document required permissions (#757)

### 4.0.9
- Add possibility to configure multiple ILM policies (#753)
- Document required permissions (#757)

### 4.0.8
- Handle compressable connection usable state (#743)
- Use newer tls protocol versions (#739)
- Add GitHub Actions file (#740)

### 4.0.7
- Added http_backend_excon_nonblock config in out_elasticsearch (#733)

### 4.0.6
- Add fallback mechanism for handling to detect es version (#730)
- Remove needless section (#728)
- Handle exception if index already exists (#727)
- Tweak test cases (#726)

### 4.0.5
-  add logstash_dateformat as placeholder (#718)
- Tweak travis.yml for suppressing validator warnings and add CI for Linux Arm64 architecture and macOS 10.14 (#724)
- Elasticsearch ruby v7.5 (#723)
- Add Oj serializer testcases for all job (#722)
- Update documentation for ILM (#721)

### 4.0.4
- Provide clearing caches timer (#719)

### 4.0.3
-  Use http.scheme settings for persisent scheme setup (#713)

### 4.0.2
- Support TLSv1.3 (#710)

### 4.0.1
- Placeholders for template name and customize template (#708)
- Add overwriting ilm policy config parameter (#707)
- Fix a failing ILM config testcase (#706)

### 4.0.0
- Restructuring ILM related features (#701)
- Extract placeholders in pipeline parameter (#695)
- fix typo in `README.md` (#698)
- Reduce log noise when not using rollover_index (#692)

### 3.8.0
- Add FAQ for specifying index.codec (#679)
- Add FAQ for connect_write timeout reached error (#687)
- Unblocking buffer overflow with block action (#688)

### 3.7.1
- Make conpatible for Fluentd v1.8 (#677)
- Handle flatten_hashes in elasticsearch_dynamic (#675)
- Handle empty index_date_pattern parameter (#674)

### 3.7.0
- Tweak for cosmetic change (#671)
- Fix access to Elasticsearch::Transport::VERSION with explicit top level class path (#670)
- Implement Elasticsearch Input plugin (#669)

### 3.6.1
- retry upsert on recoverable error. (#667)
- Allow `_index` in chunk_keys (#665)
- Support compression feature (#664)

### 3.6.0
- Set order in newly created templates (#660)
- Merge Support index lifecycle management into master (#659)
- Support template installation with host placeholder (#654)
- Support index lifecycle management (#651)

### 3.5.6
- Support elasticsearch8 removal of mapping types (#656)
- Upgrade webmock to 3 (#652)
- Suppress `ruby -c` warnings (#649)
- Add tips for sniffer class (#644)
- Make `client_key_pass` secret (#637)
- Validate `user` and `password` early (#636)

### 3.5.5
- Fix arguments order of `assert_equal` (#635)
- Add description for `port` option (#634)
- Fix description position and add examples for `hosts` option (#633)
- Use upper-case to compare before and after conversion (#630)
- Validate `max_retry_get_es_version` (#629)
- Remove unused getting plugin instance (#628)
- Fix error message for `max_retry_putting_template` (#627)
- Fix DST-breaking unit test (#623)
- Handle ClusterBlockException (#621)
- Add contribution guideline document (#618)

### 3.5.4
- Add FAQ for Fluentd seems to hang if it unable to connect Elasticsearch (#617)
- Check bulk_message size before appending (#616)
- Add FAQ for Elasticsearch index mapping glitch (#614)
- Display retry counts and interval (#613)

### 3.5.3
- Handle nil items response (#611)

### 3.5.2
- Fix `@meta_config_map` creation timing (#592)

### 3.5.1
- Configurable split request size threshold (#586)

### 3.5.0
- Adopt Elasticsearch ruby client v7 loggable class (#583)

### 3.4.3
- Add fail_on_putting_template_retry_exceed config (#579)

### 3.4.2
- Comparing DEFAULT_TYPE_NAME_ES_7x to target_type instead of type_name (#573)

### 3.4.1
- Handle non-String value on parse_time (#570)

### 3.4.0
- Check exclusive feature on #configure (#569)
- Modify FAQ for highly load k8s EFK stack (#566)
- Add FAQ for high load k8s EFK stack (#564)

### 3.3.3
- Add unit test for exception message (#563)
- Add ignore_exceptions config (#562)

### 3.3.2
- Fix support for host, hosts placeholders (#560)
- typo fixes in README.md (#559)

### 3.3.1
- add new option to suppress doc wrapping (#557)
- Include 2 (#555)

### 3.3.0
- Support builtin placeholders for host and hosts parameter (#554)

### 3.2.4
- Pass chunk for built in placeholders (#553)

### 3.2.3
- Expose exception backtrace for typhoeus gem loading error (#550)

### 3.2.2
- Don't validate ES cliuent version under dry-run mode (#547)

### 3.2.1
- Don't attempt to connect to Elasticsearch in dry run mode (#543)
- Add FAQ for typhoeus gem installation (#544)

### 3.2.0
- Split huge record requests (#539)

### 3.1.1
- Add document for custom_headers (#538)
- out_elasticsearch: Add custom_headers parameter (#529)
- Bundle irb on Ruby 2.6 or later (#537)

### 3.1.0
- Retry obtaining Elasticsearch version (#532)
- Fix broken id links (#530)

### 3.0.2
-  appveyor: Remove Ruby 2.1 CI targets on AppVeyor (#524)
- Follow removal of _routing field change on recent Elasticsearch (#523)
- Travis: Tweak to use Ruby versions (#522)

### 3.0.1
- Remove needless Elasticsearch version detection (#520)

### 3.0.0
- Use fluentd core retry mechanism (#519)
- Depends on builtin retrying mechanism (#518)
- Loosen ConnectionRetryFailure condition when flush_thread_count > 1 and depends on Fluentd core retrying mechanism (#516)

### 2.12.5
- Ensure sniffer class constants definition before calling #client (#515)

### 2.12.4
- #506 Rollover index will be in effect in case of template overwrite also. (#513)

### 2.12.3
- Added log_es_400_reason configuration item (#511)
- Allow a user to specify the rollover index date pattern (#510)

### 2.12.2
- Verify connection at startup (#504)
- Add faq for glob pattern tag routing (#502)

### 2.12.1
- Make configurable unrecoverable types (#501)
- Add FAQ for TLS enabled nginx proxy TLS version incompatibility trouble (#496)
- Add FAQs (#492)
- Remove issuestats.com badges (#489)

### 2.12.0
- Decoupling the custom template and rollover index creation #485 (#486)

### 2.11.11
- Handle error not to acquire version information (#479)

### 2.11.10
- Verbose error reason output (#469)

### 2.11.9
- Use ConnectionRetryFailure in plugin specific retrying for consistency (#468)
- Remove outdated generating hash_id_key code (#466)
- Tweak behavior for UnrecoverableError and #detect_es_major_version (#465)

### 2.11.8
- Serialize requests with Oj (#464)

### 2.11.7
- Add mechanism to detect ES and its client version mismatch (#463)

### 2.11.6
- 355 customize template (#431)

### 2.11.5
- Uplift Merge pull request #459 from richm/v0.12-simple-sniffer (#461)

### 2.11.4
- Persistent backend (#456)

### 2.11.3
- Implement the `include_index_in_url` option for out_elasticsearch (#451)
- Add an option `include_index_in_url` to allow URL-based conrtrols (#450)

### 2.11.2
- Strictness scheme (#445)

### 2.11.0
- Uplift Merge pull request #437 from jcantrill/fix_bulk_count (#438)

### 2.10.5
- Uplift Merge pull request #435 from jcantrill/add_trace_logging (#436)

### 2.10.4
- Use Fluent::UnrecoverableError as unrecoverable error class ancestors (#433)
- Add parameter validation for retrying template installation (#429)

### 2.10.3
- Add retry mechanism for template installation (#428)

### 2.10.2
- Use logstash_prefix_separator on elasticsearch_dynamic (#427)

### 2.10.1
- Uplift Merge pull request #419 from jcantrill/retry_prefix (#421)
- Uplift Merge pull request #418 from jcantrill/emit_exception (#420)

### 2.10.0
- Uplift Merge pull request #405 from jcantrill/sanitize_bulk (#414)

### 2.9.2
- Uplift Merge pull request #410 from richm/v0.12-consistent-errors-and-tests (#411)
- Add correct link for include_timestamp (#408)

### 2.9.1
- Uplift Merge pull request #406 from richm/v0.12-successes-duplicates-no-retry (#407)

### 2.9.0
- DLQ revisited v1 uplifted #398, #402 (#404)

### 2.8.6
- auth: Fix missing auth tokens after reloading connections (#394)

### 2.8.5
- Add deprecated option into content_type parameter (#391)

### 2.8.4
- Use nanosecond precision in elasticsearch_dynamic (#387)

### 2.8.3
- Specify SSL/TLS version in out_elasticsearch_dynamic (#385)

### 2.8.2
- Revert content type header default value (#383)

### 2.8.1
- Restore default value of type name #(377)

### 2.8.0
- Remove outdated generating hash id support module (#373)
- Check Elasticsearch major version (#371)

### 2.7.0
- Configureable content type (#367)

### 2.6.1
- Prevent error when using template in elasticsearch_dynamic for elementally use case (#363)

### 2.6.0
- Handle high precision time format when using custom time_key (#360)

### 2.5.0
- Using nested record in `id_key`, `parent_key`, and `routing_key` (#351)
- Fix inverted case of a proper noun "Elasticsearch" (#349)

### 2.4.1
- Add config parameter to enable elasticsearch-ruby's transporter logging (#342)

### 2.4.0
- Add built-in placeholders support against type_name parameter (#338)

### 2.3.0
- Allow overwriting existing index template (#239)

### 2.2.0
- GA release 2.2.0.

### 2.2.0.rc.1
- Separate generate hash id module and bundled new plugin for generating unique hash id (#331)

### 2.1.1
- Raise ConfigError when specifying different @hash_config.hash_id_key and id_key configration (#327)
- Small typo fix in README.md (#325)

### 2.1.0
- Retry on certain errors from Elasticsearch (#322)

### 2.0.1
- Releasing generating hash id mechanism to avoid records duplication feature.

### 2.0.1.rc.1
- Add generating hash id mechanism to avoid records duplication (#318)

### 2.0.0
- Release for Fluentd v0.14 stable.

### 2.0.0.rc.7
- Add `include_timestamp` option (#310)

### 2.0.0.rc.6
- Improve documentation (#304)
- Handle dynamic_config misconfigurations (#305)
- Escape basic authentication user information placeholders (#306)

### 2.0.0.rc.5
- make configurable with `ssl_version` parameter (#299)
- add `logstash_prefix_separator` config parameter (#297)

### 2.0.0.rc.4
- fix license identifier in gemspec (#294)

### 2.0.0.rc.3
- add built-in placeholders support (#288, #293)
- permit multi workers feature (#291)

### 2.0.0.rc.2
- add pipeline parameter (#290)

### 2.0.0.rc.1
- Use v0.14 API to support nanosecond precision (#223)

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
