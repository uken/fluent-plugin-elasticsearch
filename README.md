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

```
hosts host1:port1,host2:port2,host3:port3
```

or

```
hosts https://customhost.com:443/path,https://username:password@host-failover.com:443
```

You can specify multiple elasticsearch hosts with separator ",".

If you specify multiple hosts, this plugin will load balance updates to elasticsearch. This is an [elasticsearch-ruby](https://github.com/elasticsearch/elasticsearch-ruby) feature, the default strategy is round-robin.

If you specify this option, host and port options are ignored.

```
user demo
password secret
path /elastic_search/
scheme https
```

You can specify user and password for HTTP basic auth. If used in conjunction with a hosts list, then these options will be used by default i.e. if you do not provide any of these options within the hosts listed.


```
logstash_format true # defaults to false
```

This is meant to make writing data into elasticsearch compatible to what logstash writes. By doing this, one could take advantade of [kibana](http://kibana.org/).

```
logstash_prefix mylogs # defaults to "logstash"
```

By default, the records inserted into index `logstash-YYMMDD`. This option allows to insert into specified index like `mylogs-YYMMDD`.

```
logstash_dateformat %Y.%m. # defaults to "%Y.%m.%d"
```

By default, the records inserted into index `logstash-YYMMDD`. This option allows to insert into specified index like `logstash-YYYYMM` for a monthly index.

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

```
utc_index true
```

By default, the records inserted into index `logstash-YYMMDD` with utc (Coordinated Universal Time). This option allows to use local time if you describe utc_index to false.

```
request_timeout 15s # defaults to 5s
```

You can specify HTTP request timeout.

This is useful when Elasticsearch cannot return response for bulk request within the default of 5 seconds.

```
reload_connections false # defaults to true
```

You can tune how the elasticsearch-transport host reloading feature works. By default it will reload the host list from the server
every 10,000th request to spread the load. This can be an issue if your ElasticSearch cluster is behind a Reverse Proxy,
as fluentd process may not have direct network access to the ElasticSearch nodes.

```
reload_on_failure true # defaults to false
```

Indicates that the elasticsearch-transport will try to reload the nodes addresses if there is a failure while making the
request, this can be useful to quickly remove a dead node from the list of addresses.

---

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

---

```
id_key request_id # use "request_id" field as a record id in ES
```

By default, all records inserted into elasticsearch get a random _id. This option allows to use a field in the record as an identifier.

This following record `{"name":"Johnny","request_id":"87d89af7daffad6"}` will trigger the following ElasticSearch command

```
{ "index" : { "_index" : "logstash-2013.01.01, "_type" : "fluentd", "_id" : "87d89af7daffad6" } }
{ "name": "Johnny", "request_id": "87d89af7daffad6" }
```

---

fluentd-plugin-elasticsearch is a buffered output that uses elasticseach's bulk API. So additional buffer configuration would be (with default values):

```
buffer_type memory
flush_interval 60
retry_limit 17
retry_wait 1.0
num_threads 1
```

---

Please consider using [fluent-plugin-forest](https://github.com/tagomoris/fluent-plugin-forest) to send multiple logs to multiple ElasticSearch indices:

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

---

Sometimes, though, you may not have configuration access to the collector that's pushing data to your elastic search cluster.  This can limit your options for setting your own `_id`, `_index`, `_type`, and `_parent` values which may be calculated on your own software or in your own fluentd collectors.  Setting `allow_overrides` to `true` in this plugin will allow other fluentd collectors to set these values themselves before sending them to this collector.  This plugin will modify these values if they already exist.

For example, you could have one machine that injects an `_index` value of `api-2015.05.21`.  You could have another machine that injects an `_index` value of `www-2015.05.21`.  Both forward their data, for example, to the fluentd collector `es-collector` with the following config:

```
host localhost
port 9200
index_name fluentd
type_name fluentd
user demo
password secret
logstash_format true
logstash_prefix mylogs
allow_overrides true
```

For these two particular machines, they'll have their data put in the `api-2015.05.21` and `www-2015.05.21` indexes respectively.  For all other machines forwarding to this `es-collector`, they'd have their data put in the `mylogs-2015.05.21`.  This allows there to be a collector that deals with pushing to elastic search when it comes ot host names, ports, passwords, and etc, yet allows the option for determining the index, id, parent, and type on a different machine.

---

## Contributing

1. Fork it
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request

If you have a question, [open an Issue](https://github.com/uken/fluent-plugin-elasticsearch/issues).
