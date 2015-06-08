# Fluent::Plugin::Elasticsearch, a plugin for [Fluentd](http://fluentd.org)

[![Gem Version](https://badge.fury.io/rb/fluent-plugin-elasticsearch.png)](http://badge.fury.io/rb/fluent-plugin-elasticsearch)
[![Dependency Status](https://gemnasium.com/uken/guard-sidekiq.png)](https://gemnasium.com/uken/fluent-plugin-elasticsearch)
[![Build Status](https://travis-ci.org/uken/fluent-plugin-elasticsearch.png?branch=master)](https://travis-ci.org/uken/fluent-plugin-elasticsearch)
[![Coverage Status](https://coveralls.io/repos/uken/fluent-plugin-elasticsearch/badge.png)](https://coveralls.io/r/uken/fluent-plugin-elasticsearch)
[![Code Climate](https://codeclimate.com/github/uken/fluent-plugin-elasticsearch.png)](https://codeclimate.com/github/uken/fluent-plugin-elasticsearch)

I wrote this so you can search logs routed through Fluentd.

## Installation

    $ gem install fluent-plugin-elasticsearch

* prerequisite : You need to install [libcurl (libcurl-devel)](http://curl.haxx.se/libcurl/) to work with.

## Usage

In your fluentd configration, use `type elasticsearch`. Additional configuration is optional, default values would look like this:

```
host localhost
port 9200
index_name fluentd
type_name fluentd
```

**Index templates**

This plugin creates ElasticSearch indices by merely writing to them. Consider using [Index Templates](http://www.elasticsearch.org/guide/en/elasticsearch/reference/current/indices-templates.html) to gain control of what get indexed and how. See [this example](https://github.com/uken/fluent-plugin-elasticsearch/issues/33#issuecomment-38693282) for a good starting point.

**More options:**

**hosts**

```
hosts host1:port1,host2:port2,host3:port3
```

or

```
hosts https://customhost.com:443/path,https://username:password@host-failover.com:443
```

You can specify multiple elasticsearch hosts with separator ",".

If you specify multiple hosts, this plugin will load balance updates to elasticsearch. This is an [elasticsearch-ruby](https://github.com/elasticsearch/elasticsearch-ruby) feature, the default strategy is round-robin.

**user, password, path, scheme, ssl_verify**

If you specify this option, host and port options are ignored.

```
user demo
password secret
path /elastic_search/
scheme https
```

You can specify user and password for HTTP basic auth. If used in conjunction with a hosts list, then these options will be used by default i.e. if you do not provide any of these options within the hosts listed.

Specify `ssl_verify false` to skip ssl verification (defaults to true)

**logstash_format**

```
logstash_format true # defaults to false
```

This is meant to make writing data into elasticsearch compatible to what logstash writes. By doing this, one could take advantade of [kibana](http://kibana.org/).

**logstash_prefix**

```
logstash_prefix mylogs # defaults to "logstash"
```

**logstash_dateformat**

By default, the records inserted into index `logstash-YYMMDD`. This option allows to insert into specified index like `mylogs-YYYYMM` for a monthly index.

```
logstash_dateformat %Y.%m. # defaults to "%Y.%m.%d"
```

**time_key**

By default, when inserting records in logstash format, @timestamp is dynamically created with the time at log ingestion. If you'd like to use a custom time. Include an @timestamp with your record.

```
{"@timestamp":"2014-04-07T000:00:00-00:00"}
```

You can specify an option `time_key` (like the option described in [tail Input Plugin](http://docs.fluentd.org/articles/in_tail)) if you don't like `@timestamp`.

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

**utc_index**

```
utc_index true
```

By default, the records inserted into index `logstash-YYMMDD` with utc (Coordinated Universal Time). This option allows to use local time if you describe utc_index to false.

**request_timeout**

```
request_timeout 15s # defaults to 5s
```

You can specify HTTP request timeout.

This is useful when Elasticsearch cannot return response for bulk request within the default of 5 seconds.

**reload_connections**

```
reload_connections false # defaults to true
```

**reload_on_failure**

You can tune how the elasticsearch-transport host reloading feature works. By default it will reload the host list from the server every 10,000th request to spread the load. This can be an issue if your ElasticSearch cluster is behind a Reverse Proxy, as fluentd process may not have direct network access to the ElasticSearch nodes.

```
reload_on_failure true # defaults to false
```

Indicates that the elasticsearch-transport will try to reload the nodes addresses if there is a failure while making the
request, this can be useful to quickly remove a dead node from the list of addresses.

**include_tag_key, tag_key**

```
include_tag_key true # defaults to false
tag_key tag # defaults to tag
```

This will add the fluentd tag in the json record. For instance, if you have a config like this:

```
<match my.logs>
  type elasticsearch
  include_tag_key true
  tag_key _key
</match>
```

The record inserted into elasticsearch would be

```
{"_key":"my.logs", "name":"Johnny Doeie"}
```

**id_key**

```
id_key request_id # use "request_id" field as a record id in ES
```

By default, all records inserted into elasticsearch get a random _id. This option allows to use a field in the record as an identifier.

This following record `{"name":"Johnny","request_id":"87d89af7daffad6"}` will trigger the following ElasticSearch command

```
{ "index" : { "_index" : "logstash-2013.01.01, "_type" : "fluentd", "_id" : "87d89af7daffad6" } }
{ "name": "Johnny", "request_id": "87d89af7daffad6" }
```

**Buffered output options**

fluentd-plugin-elasticsearch is a buffered output that uses elasticseach's bulk API. So additional buffer configuration would be (with default values):

```
buffer_type memory
flush_interval 60
retry_limit 17
retry_wait 1.0
num_threads 1
```

**Not seeing a config you need?**

We try to keep the scope of this plugin small. If you need more configuration options, please consider using [fluent-plugin-forest](https://github.com/tagomoris/fluent-plugin-forest). For example, to configure multiple tags to be sent to different ElasticSearch indices:

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

## Contributing

1. Fork it
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request

If you have a question, [open an Issue](https://github.com/uken/fluent-plugin-elasticsearch/issues).
