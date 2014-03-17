# Fluent::Plugin::Elasticsearch, a plugin for [Fluentd](http://fluentd.org)

[![Gem Version](https://badge.fury.io/rb/fluent-plugin-elasticsearch.png)](http://badge.fury.io/rb/fluent-plugin-elasticsearch)
[![Dependency Status](https://gemnasium.com/uken/guard-sidekiq.png)](https://gemnasium.com/uken/fluent-plugin-elasticsearch)
[![Build Status](https://travis-ci.org/uken/fluent-plugin-elasticsearch.png?branch=master)](https://travis-ci.org/uken/fluent-plugin-elasticsearch)
[![Coverage Status](https://coveralls.io/repos/uken/fluent-plugin-elasticsearch/badge.png)](https://coveralls.io/r/uken/fluent-plugin-elasticsearch)
[![Code Climate](https://codeclimate.com/github/uken/fluent-plugin-elasticsearch.png)](https://codeclimate.com/github/uken/fluent-plugin-elasticsearch)

I wrote this so you can search logs routed through Fluentd.

## Installation

    $ gem install fluent-plugin-elasticsearch

* prerequisite : You need to install [libcurl](http://curl.haxx.se/libcurl/) to work with.

## Usage

In your fluentd configration, use `type elasticsearch`. Additional configuration is optional, default values would look like this:

```
host localhost
port 9200
index_name fluentd
type_name fluentd
```

**More options:**

```
hosts host1:port1,host2:port2,host3:port3
```

You can specify multiple elasticsearch hosts with separator ",".

If you specify multiple hosts, plugin writes to elasticsearch with load balanced. (it's elasticsearch-ruby's feature, default is round-robin.)

If you specify this option, host and port options are ignored.

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

```
utc_index true
```

By default, the records inserted into index `logstash-YYMMDD` with utc (Coordinated Universal Time). This option allows to use local time if you describe utc_index to false.

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

## Contributing

1. Fork it
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request

If you have a question, [open an Issue](https://github.com/uken/fluent-plugin-elasticsearch/issues).
