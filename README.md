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
  + [time_key](#time_key)
  + [utc_index](#utc_index)
  + [request_timeout](#request_timeout)
  + [reload_connections](#reload_connections)
  + [reload_on_failure](#reload_on_failure)
  + [resurrect_after](#resurrect_after)
  + [include_tag_key, tag_key](#include_tag_key-tag_key)
  + [id_key](#id_key)
  + [partial](#partial)
  + [Client/host certificate options](#clienthost-certificate-options)
  + [Buffered output options](#buffered-output-options)
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

In your Fluentd configuration, use `type elasticsearch`. Additional configuration is optional, default values would look like this:

```
<match my.logs>
  type elasticsearch
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

This is meant to make writing data into ElasticSearch compatible to what [Logstash](https://www.elastic.co/products/logstash) writes. By doing this, one could take advantage of [Kibana](https://www.elastic.co/products/kibana).

### logstash_prefix

```
logstash_prefix mylogs # defaults to "logstash"
```

### logstash_dateformat

By default, the records inserted into index `logstash-YYMMDD`. This option allows to insert into specified index like `mylogs-YYYYMM` for a monthly index.

```
logstash_dateformat %Y.%m. # defaults to "%Y.%m.%d"
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
  "@timstamp": "2014-12-19T08:01:03Z",
  "vtm": "2014-12-19T08:01:03Z"
}
```

### utc_index

```
utc_index true
```

By default, the records inserted into index `logstash-YYMMDD` with UTC (Coordinated Universal Time). This option allows to use local time if you describe utc_index to false.

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
  type elasticsearch
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

### partial

You can specify if you want to index a document entirely or update partial fields only.

```
partial true # defaults to false
```

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

### Buffered output options

`fluentd-plugin-elasticsearch` extends [Fluentd's builtin Buffered Output plugin](http://docs.fluentd.org/articles/buffer-plugin-overview). It adds the following options:

```
buffer_type memory
flush_interval 60
retry_limit 17
retry_wait 1.0
num_threads 1
```

The value for option `buffer_chunk_limit` should not exceed value `http.max_content_length` in your Elasticsearch setup (by default it is 104857600 bytes).

### Not seeing a config you need?

We try to keep the scope of this plugin small and not add too many configuration options. If you think an option would be useful to others, feel free to open an issue or contribute a Pull Request.

Alternatively, consider using [fluent-plugin-forest](https://github.com/tagomoris/fluent-plugin-forest). For example, to configure multiple tags to be sent to different ElasticSearch indices:

```
<match my.logs.*>
  type forest
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
  type elasticsearch_dynamic
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

Pull Requests are welcomed.

## Running tests

Install dev dependencies:

```sh
$ gem install bundler
$ bundle install
$ bundle exec rake test
```
