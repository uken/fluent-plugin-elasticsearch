# Fluent::Plugin::Elasticsearch, a plugin for [Fluentd](http://fluentd.org)

[![Gem Version](https://badge.fury.io/rb/fluent-plugin-elasticsearch.png)](http://badge.fury.io/rb/fluent-plugin-elasticsearch)
[![Build Status](https://travis-ci.org/uken/fluent-plugin-elasticsearch.png?branch=master)](https://travis-ci.org/uken/fluent-plugin-elasticsearch)
[![Coverage Status](https://coveralls.io/repos/uken/fluent-plugin-elasticsearch/badge.png)](https://coveralls.io/r/uken/fluent-plugin-elasticsearch)
[![Code Climate](https://codeclimate.com/github/uken/fluent-plugin-elasticsearch.png)](https://codeclimate.com/github/uken/fluent-plugin-elasticsearch)
[![Issue Stats](http://issuestats.com/github/uken/fluent-plugin-elasticsearch/badge/pr)](http://issuestats.com/github/uken/fluent-plugin-elasticsearch)
[![Issue Stats](http://issuestats.com/github/uken/fluent-plugin-elasticsearch/badge/issue)](http://issuestats.com/github/uken/fluent-plugin-elasticsearch)

Send your logs to ElasticSearch (and search them with Kibana maybe?)

Note: For Amazon Elasticsearch Service please consider using [fluent-plugin-aws-elasticsearch-service](https://github.com/atomita/fluent-plugin-aws-elasticsearch-service)

* [Installation](#installation)
* [Usage](#usage)
  + [Index templates](#index-templates)
* [Configuration](#configuration)
  + [hosts](#hosts)
  + [user, password, path, scheme, ssl_verify](#user-password-path-scheme-ssl_verify)
  + [logstash_format](#logstash_format)
  + [logstash_prefix](#logstash_prefix)
  + [logstash_dateformat](#logstash_dateformat)
  + [time_key_format](#time_key_format)
  + [time_key](#time_key)
  + [time_key_exclude_timestamp](#time_key_exclude_timestamp)
  + [utc_index](#utc_index)
  + [target_index_key](#target_index_key)
  + [target_type_key](#target_type_key)
  + [template_name](#template_name)
  + [template_file](#template_file)
  + [request_timeout](#request_timeout)
  + [reload_connections](#reload_connections)
  + [reload_on_failure](#reload_on_failure)
  + [resurrect_after](#resurrect_after)
  + [include_tag_key, tag_key](#include_tag_key-tag_key)
  + [id_key](#id_key)
  + [parent_key](#parent_key)
  + [routing_key](#routing_key)
  + [remove_keys](#remove_keys)
  + [remove_keys_on_update](#remove_keys_on_update)
  + [remove_keys_on_update_key](#remove_keys_on_update_key)
  + [write_operation](#write_operation)
  + [Client/host certificate options](#clienthost-certificate-options)
  + [Proxy Support](#proxy-support)
  + [Buffered output options](#buffered-output-options)
  + [Hash flattening](#hash-flattening)
  + [Not seeing a config you need?](#not-seeing-a-config-you-need)
  + [Dynamic configuration](#dynamic-configuration)
* [Contact](#contact)
* [Contributing](#contributing)
* [Running tests](#running-tests)

## Installation

```sh
$ gem install fluent-plugin-elasticsearch
```

## Usage

In your Fluentd configuration, use `@type elasticsearch`. Additional configuration is optional, default values would look like this:

```
<match my.logs>
  @type elasticsearch
  host localhost
  port 9200
  index_name fluentd
  type_name fluentd
</match>
```

### Index templates

This plugin creates ElasticSearch indices by merely writing to them. Consider using [Index Templates](https://www.elastic.co/guide/en/elasticsearch/reference/current/indices-templates.html) to gain control of what get indexed and how. See [this example](https://github.com/uken/fluent-plugin-elasticsearch/issues/33#issuecomment-38693282) for a good starting point.

## Configuration

### hosts

```
hosts host1:port1,host2:port2,host3:port3
# or
hosts https://customhost.com:443/path,https://username:password@host-failover.com:443
```

You can specify multiple ElasticSearch hosts with separator ",".

If you specify multiple hosts, this plugin will load balance updates to ElasticSearch. This is an [elasticsearch-ruby](https://github.com/elasticsearch/elasticsearch-ruby) feature, the default strategy is round-robin.

### user, password, path, scheme, ssl_verify

If you specify this option, host and port options are ignored.

```
user demo
password secret
path /elastic_search/
scheme https
```

You can specify user and password for HTTP basic auth. If used in conjunction with a hosts list, then these options will be used by default i.e. if you do not provide any of these options within the hosts listed.

Specify `ssl_verify false` to skip ssl verification (defaults to true)

### logstash_format

```
logstash_format true # defaults to false
```

This is meant to make writing data into ElasticSearch indices compatible to what [Logstash](https://www.elastic.co/products/logstash) calls them. By doing this, one could take advantage of [Kibana](https://www.elastic.co/products/kibana). See logstash_prefix and logstash_dateformat to customize this index name pattern. The index name will be `#{logstash_prefix}-#{formated_date}`

### logstash_prefix

```
logstash_prefix mylogs # defaults to "logstash"
```

### logstash_dateformat

The strftime format to generate index target index name when `logstash_format` is set to true. By default, the records are inserted into index `logstash-YYYY.MM.DD`. This option, alongwith `logstash_prefix` lets us insert into specified index like `mylogs-YYYYMM` for a monthly index.

```
logstash_dateformat %Y.%m. # defaults to "%Y.%m.%d"
```

### time_key_format

The format of the time stamp field (`@timestamp` or what you specify with [time_key](#time_key)). This parameter only has an effect when [logstash_format](#logstash_format) is true as it only affects the name of the index we write to. Please see [Time#strftime](http://ruby-doc.org/core-1.9.3/Time.html#method-i-strftime) for information about the value of this format.

Setting this to a known format can vastly improve your log ingestion speed if all most of your logs are in the same format. If there is an error parsing this format the timestamp will default to the ingestion time. If you are on Ruby 2.0 or later you can get a further performance improvment by installing the "strptime" gem: `fluent-gem install strptime`.

For example to parse ISO8601 times with sub-second precision:

```
time_key_format %Y-%m-%dT%H:%M:%S.%N%z
```

### time_key

By default, when inserting records in [Logstash](https://www.elastic.co/products/logstash) format, `@timestamp` is dynamically created with the time at log ingestion. If you'd like to use a custom time, include an `@timestamp` with your record.

```
{"@timestamp":"2014-04-07T000:00:00-00:00"}
```

You can specify an option `time_key` (like the option described in [tail Input Plugin](http://docs.fluentd.org/articles/in_tail)) to replace `@timestamp` key.

Suppose you have settings

```
logstash_format true
time_key vtm
```

Your input is:
```
{
  "title": "developer",
  "vtm": "2014-12-19T08:01:03Z"
}
```

The output will be
```
{
  "title": "developer",
  "@timestamp": "2014-12-19T08:01:03Z",
  "vtm": "2014-12-19T08:01:03Z"
}
```

See `time_key_exclude_timestamp` to avoid adding `@timestamp`.

### time_key_exclude_timestamp

```
time_key_exclude_timestamp false
```

By default, setting `time_key` will copy the value to an additional field `@timestamp`. When setting `time_key_exclude_timestamp true`, no additional field will be added.

### utc_index

```
utc_index true
```

By default, the records inserted into index `logstash-YYMMDD` with UTC (Coordinated Universal Time). This option allows to use local time if you describe utc_index to false.

### target_index_key

Tell this plugin to find the index name to write to in the record under this key in preference to other mechanisms. Key can be specified as path to nested record using dot ('.') as a separator.

If it is present in the record (and the value is non falsey) the value will be used as the index name to write to and then removed from the record before output; if it is not found then it will use logstash_format or index_name settings as configured.

Suppose you have the following settings

```
target_index_key @target_index
index_name fallback
```

If your input is:
```
{
  "title": "developer",
  "@timestamp": "2014-12-19T08:01:03Z",
  "@target_index": "logstash-2014.12.19"
}
```

The output would be

```
{
  "title": "developer",
  "@timestamp": "2014-12-19T08:01:03Z",
}
```

and this record will be written to the specified index (`logstash-2014.12.19`) rather than `fallback`.

### target_type_key

Similar to `target_index_key` config, find the type name to write to in the record under this key (or nested record). If key not found in record - fallback to `type_name` (default "fluentd").

### template_name

The name of the template to define. If a template by the name given is already present, it will be left unchanged.

This parameter along with template_file allow the plugin to behave similarly to Logstash (it installs a template at creation time) so that raw records are available. See [https://github.com/uken/fluent-plugin-elasticsearch/issues/33](https://github.com/uken/fluent-plugin-elasticsearch/issues/33).

[template_file](#template_file) must also be specified.

### template_file

The path to the file containing the template to install.

[template_name](#template_name) must also be specified.

### request_timeout

You can specify HTTP request timeout.

This is useful when ElasticSearch cannot return response for bulk request within the default of 5 seconds.

```
request_timeout 15s # defaults to 5s
```

### reload_connections

You can tune how the elasticsearch-transport host reloading feature works. By default it will reload the host list from the server every 10,000th request to spread the load. This can be an issue if your ElasticSearch cluster is behind a Reverse Proxy, as Fluentd process may not have direct network access to the ElasticSearch nodes.

```
reload_connections false # defaults to true
```

### reload_on_failure

Indicates that the elasticsearch-transport will try to reload the nodes addresses if there is a failure while making the
request, this can be useful to quickly remove a dead node from the list of addresses.

```
reload_on_failure true # defaults to false
```

### resurrect_after

You can set in the elasticsearch-transport how often dead connections from the elasticsearch-transport's pool will be resurrected.

```
resurrect_after 5 # defaults to 60s
```

### include_tag_key, tag_key

```
include_tag_key true # defaults to false
tag_key tag # defaults to tag
```

This will add the Fluentd tag in the JSON record. For instance, if you have a config like this:

```
<match my.logs>
  @type elasticsearch
  include_tag_key true
  tag_key _key
</match>
```

The record inserted into ElasticSearch would be

```
{"_key":"my.logs", "name":"Johnny Doeie"}
```

### id_key

```
id_key request_id # use "request_id" field as a record id in ES
```

By default, all records inserted into ElasticSearch get a random _id. This option allows to use a field in the record as an identifier.

This following record `{"name":"Johnny","request_id":"87d89af7daffad6"}` will trigger the following ElasticSearch command

```
{ "index" : { "_index" : "logstash-2013.01.01, "_type" : "fluentd", "_id" : "87d89af7daffad6" } }
{ "name": "Johnny", "request_id": "87d89af7daffad6" }
```

### parent_key

```
parent_key a_parent # use "a_parent" field value to set _parent in elasticsearch command
```

If your input is
```
{ "name": "Johnny", "a_parent": "my_parent" }
```

ElasticSearch command would be

```
{ "index" : { "_index" : "****", "_type" : "****", "_id" : "****", "_parent" : "my_parent" } }
{ "name": "Johnny", "a_parent": "my_parent" }
```

if `parent_key` is not configed or the `parent_key` is absent in input record, nothing will happen.

### routing_key

Similar to `parent_key` config, will add `_routing` into elasticsearch command if `routing_key` is set and the field does exist in input event.

### remove_keys

```
parent_key a_parent
routing_key a_routing
remove_keys a_parent, a_routing # a_parent and a_routing fields won't be sent to elasticsearch
```

### remove_keys_on_update

Remove keys on update will not update the configured keys in elasticsearch when a record is being updated.  
This setting only has any effect if the write operation is update or upsert.

If the write setting is upsert then these keys are only removed if the record is being
updated, if the record does not exist (by id) then all of the keys are indexed.

```
remove_keys_on_update foo,bar
```

### remove_keys_on_update_key

This setting allows `remove_keys_on_update` to be configured with a key in each record, in much the same way as `target_index_key` works.
The configured key is removed before indexing in elasticsearch. If both `remove_keys_on_update` and `remove_keys_on_update_key` is
present in the record then the keys in record are used, if the `remove_keys_on_update_key` is not present then the value of
`remove_keys_on_update` is used as a fallback.

```
remove_keys_on_update_key keys_to_skip
```

### write_operation

The write_operation can be any of:

| Operation | Description          |
| ------------- | ----------- |
| index (default)      | new data is added while existing data (based on its id) is replaced (reindexed).|
| create      | adds new data - if the data already exists (based on its id), the op is skipped.|
| update      | updates existing data (based on its id). If no data is found, the op is skipped.|
| upsert      | known as merge or insert if the data does not exist, updates if the data exists (based on its id).|

**Please note, id is required in create, update, and upsert scenario. Without id, the message will be dropped.**

### Client/host certificate options

Need to verify ElasticSearch's certificate?  You can use the following parameter to specify a CA instead of using an environment variable.
```
ca_file /path/to/your/ca/cert
```

Does your ElasticSearch cluster want to verify client connections?  You can specify the following parameters to use your client certificate, key, and key password for your connection.
```
client_cert /path/to/your/client/cert
client_key /path/to/your/private/key
client_key_pass password
```

### Proxy Support

Starting with version 0.8.0, this gem uses excon, which supports proxy with environment variables - https://github.com/excon/excon#proxy-support

### Buffered output options

`fluentd-plugin-elasticsearch` extends [Fluentd's builtin Buffered Output plugin](http://docs.fluentd.org/articles/buffer-plugin-overview). It adds the following options:

```
buffer_type memory
flush_interval 60
retry_limit 17
retry_wait 1.0
num_threads 1
```

The value for option `buffer_chunk_limit` should not exceed value `http.max_content_length` in your Elasticsearch setup (by default it is 100mb).

### Hash flattening

Elasticsearch will complain if you send object and concrete values to the same field. For example, you might have logs that look this, from different places:

{"people" => 100}
{"people" => {"some" => "thing"}}

The second log line will be rejected by the Elasticsearch parser because objects and concrete values can't live in the same field. To combat this, you can enable hash flattening.

```
flatten_hashes true
flatten_hashes_separator _
```

This will produce elasticsearch output that looks like this:
{"people_some" => "thing"}

Note that the flattener does not deal with arrays at this time.

### Not seeing a config you need?

We try to keep the scope of this plugin small and not add too many configuration options. If you think an option would be useful to others, feel free to open an issue or contribute a Pull Request.

Alternatively, consider using [fluent-plugin-forest](https://github.com/tagomoris/fluent-plugin-forest). For example, to configure multiple tags to be sent to different ElasticSearch indices:

```
<match my.logs.*>
  @type forest
  subtype elasticsearch
  remove_prefix my.logs
  <template>
    logstash_prefix ${tag}
    # ...
  </template>
</match>
```

And yet another option is described in Dynamic Configuration section.

### Dynamic configuration

If you want configurations to depend on information in messages, you can use `elasticsearch_dynamic`. This is an experimental variation of the ElasticSearch plugin allows configuration values to be specified in ways such as the below:

```
<match my.logs.*>
  @type elasticsearch_dynamic
  hosts ${record['host1']}:9200,${record['host2']}:9200
  index_name my_index.${Time.at(time).getutc.strftime(@logstash_dateformat)}
  logstash_prefix ${tag_parts[3]}
  port ${9200+rand(4)}
  index_name ${tag_parts[2]}-${Time.at(time).getutc.strftime(@logstash_dateformat)}
</match>
```

**Please note, this uses Ruby's `eval` for every message, so there are performance and security implications.**

## Contact

If you have a question, [open an Issue](https://github.com/uken/fluent-plugin-elasticsearch/issues).

## Contributing

There are usually a few feature requests, tagged [Easy](https://github.com/uken/fluent-plugin-elasticsearch/issues?q=is%3Aissue+is%3Aopen+label%3Alevel%3AEasy), [Normal](https://github.com/uken/fluent-plugin-elasticsearch/issues?q=is%3Aissue+is%3Aopen+label%3Alevel%3ANormal) and [Hard](https://github.com/uken/fluent-plugin-elasticsearch/issues?q=is%3Aissue+is%3Aopen+label%3Alevel%3AHard). Feel free to work on any one of them.

Pull Requests are welcomed.

[![Pull Request Graph](https://graphs.waffle.io/uken/fluent-plugin-elasticsearch/throughput.svg)](https://waffle.io/uken/fluent-plugin-elasticsearch/metrics)

## Running tests

Install dev dependencies:

```sh
$ gem install bundler
$ bundle install
$ bundle exec rake test
```
