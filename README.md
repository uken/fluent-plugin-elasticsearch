# Fluent::Plugin::Elasticsearch

I wrote this so you can search logs routed through Fluentd.

## Installation

    $ gem install fluent-plugin-elasticsearch

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
logstash_format true # defaults to false
```

This is meant to make writing data into elasticsearch compatible to what logstash writes. By doing this, one could take advantage of [kibana](http://kibana.org/).

---

```
map {'my.tag' => 'index1', 'my.other.tag' => 'index2'}
```

Will change the index the record is written to, based on the tag - works for a single index name as well as a logstash format.  This is useful when you have inputs from different sources that to want to keep separated.  Will default to the index name provided or "logstash" if the tag isn't found.

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



## Contributing

1. Fork it
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request
