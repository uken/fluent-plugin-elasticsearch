## Index

* [Installation](#installation)
* [Usage](#usage)
* [Configuration](#configuration)
  + [host](#host)
  + [port](#port)
  + [hosts](#hosts)
  + [user, password, path, scheme, ssl_verify](#user-password-path-scheme-ssl_verify)
  + [parse_timestamp](#parse_timestamp)
  + [timestampkey_format](#timestampkey_format)
  + [timestamp_key](#timestamp_key)
  + [timestamp_parse_error_tag](#timestamp_parse_error_tag)
  + [http_backend](#http_backend)
  + [request_timeout](#request_timeout)
  + [reload_connections](#reload_connections)
  + [reload_on_failure](#reload_on_failure)
  + [resurrect_after](#resurrect_after)
  + [with_transporter_log](#with_transporter_log)
  + [Client/host certificate options](#clienthost-certificate-options)
  + [sniffer_class_name](#sniffer-class-name)
  + [custom_headers](#custom_headers)
  + [docinfo_fields](#docinfo_fields)
  + [docinfo_target](#docinfo_target)
  + [docinfo](#docinfo)
* [Advanced Usage](#advanced-usage)

## Usage

In your Fluentd configuration, use `@type elasticsearch` and specify `tag your.awesome.tag`. Additional configuration is optional, default values would look like this:

```
<source>
  @type elasticsearch
  host localhost
  port 9200
  index_name fluentd
  type_name fluentd
  tag my.logs
</source>
```

## Configuration

### host

```
host user-custom-host.domain # default localhost
```

You can specify Elasticsearch host by this parameter.


### port

```
port 9201 # defaults to 9200
```

You can specify Elasticsearch port by this parameter.

### hosts

```
hosts host1:port1,host2:port2,host3:port3
```

You can specify multiple Elasticsearch hosts with separator ",".

If you specify multiple hosts, this plugin will load balance updates to Elasticsearch. This is an [elasticsearch-ruby](https://github.com/elasticsearch/elasticsearch-ruby) feature, the default strategy is round-robin.

If you specify `hosts` option, `host` and `port` options are ignored.

```
host user-custom-host.domain # ignored
port 9200                    # ignored
hosts host1:port1,host2:port2,host3:port3
```

If you specify `hosts` option without port, `port` option is used.

```
port 9200
hosts host1:port1,host2:port2,host3 # port3 is 9200
```

**Note:** If you will use scheme https, do not include "https://" in your hosts ie. host "https://domain", this will cause ES cluster to be unreachable and you will receive an error "Can not reach Elasticsearch cluster"

**Note:** Up until v2.8.5, it was allowed to embed the username/password in the URL. However, this syntax is deprecated as of v2.8.6 because it was found to cause serious connection problems (See #394). Please migrate your settings to use the `user` and `password` field (described below) instead.

### user, password, path, scheme, ssl_verify

```
user demo
password secret
path /elastic_search/
scheme https
```

You can specify user and password for HTTP Basic authentication.

And this plugin will escape required URL encoded characters within `%{}` placeholders.

```
user %{demo+}
password %{@secret}
```

Specify `ssl_verify false` to skip ssl verification (defaults to true)

### parse_timestamp

```
parse_timestamp true # defaults to false
```

Parse a `@timestamp` field and add parsed time to the event.

### timestamp_key_format

The format of the time stamp field (`@timestamp` or what you specify in Elasticsearch). This parameter only has an effect when [parse_timestamp](#parse_timestamp) is true as it only affects the name of the index we write to. Please see [Time#strftime](http://ruby-doc.org/core-1.9.3/Time.html#method-i-strftime) for information about the value of this format.

Setting this to a known format can vastly improve your log ingestion speed if all most of your logs are in the same format. If there is an error parsing this format the timestamp will default to the ingestion time. If you are on Ruby 2.0 or later you can get a further performance improvement by installing the "strptime" gem: `fluent-gem install strptime`.

For example to parse ISO8601 times with sub-second precision:

```
timestamp_key_format %Y-%m-%dT%H:%M:%S.%N%z
```

### timestamp_parse_error_tag

With `parse_timestamp true`, elasticsearch input plugin parses timestamp field for consuming event time. If the consumed record has invalid timestamp value, this plugin emits an error event to `@ERROR` label with `timestamp_parse_error_tag` configured tag.

Default value is `elasticsearch_plugin.input.time.error`.

### http_backend

With `http_backend typhoeus`, elasticsearch plugin uses typhoeus faraday http backend.
Typhoeus can handle HTTP keepalive.

Default value is `excon` which is default http_backend of elasticsearch plugin.

```
http_backend typhoeus
```


### request_timeout

You can specify HTTP request timeout.

This is useful when Elasticsearch cannot return response for bulk request within the default of 5 seconds.

```
request_timeout 15s # defaults to 5s
```

### reload_connections

You can tune how the elasticsearch-transport host reloading feature works. By default it will reload the host list from the server every 10,000th request to spread the load. This can be an issue if your Elasticsearch cluster is behind a Reverse Proxy, as Fluentd process may not have direct network access to the Elasticsearch nodes.

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
resurrect_after 5s # defaults to 60s
```

### with_transporter_log

This is debugging purpose option to enable to obtain transporter layer log.
Default value is `false` for backward compatibility.

We recommend to set this true if you start to debug this plugin.

```
with_transporter_log true
```

### Client/host certificate options

Need to verify Elasticsearch's certificate?  You can use the following parameter to specify a CA instead of using an environment variable.
```
ca_file /path/to/your/ca/cert
```

Does your Elasticsearch cluster want to verify client connections?  You can specify the following parameters to use your client certificate, key, and key password for your connection.
```
client_cert /path/to/your/client/cert
client_key /path/to/your/private/key
client_key_pass password
```

If you want to configure SSL/TLS version, you can specify ssl\_version parameter.
```
ssl_version TLSv1_2 # or [SSLv23, TLSv1, TLSv1_1]
```

:warning: If SSL/TLS enabled, it might have to be required to set ssl\_version.

### Sniffer Class Name

The default Sniffer used by the `Elasticsearch::Transport` class works well when Fluentd has a direct connection
to all of the Elasticsearch servers and can make effective use of the `_nodes` API.  This doesn't work well
when Fluentd must connect through a load balancer or proxy.  The parameter `sniffer_class_name` gives you the
ability to provide your own Sniffer class to implement whatever connection reload logic you require.  In addition,
there is a new `Fluent::Plugin::ElasticsearchSimpleSniffer` class which reuses the hosts given in the configuration, which
is typically the hostname of the load balancer or proxy.  For example, a configuration like this would cause
connections to `logging-es` to reload every 100 operations:

```
host logging-es
port 9200
reload_connections true
sniffer_class_name Fluent::Plugin::ElasticsearchSimpleSniffer
reload_after 100
```

### custom_headers

This parameter adds additional headers to request. The default value is `{}`.

```
custom_headers {"token":"secret"}
```

### docinfo_fields

This parameter specifies docinfo record keys. The default values are `['_index', '_type', '_id']`.

```
docinfo_fields ['_index', '_id']
```

### docinfo_target

This parameter specifies docinfo storing key. The default value is `@metadata`.

```
docinfo_target metadata
```

### docinfo

This parameter specifies whether docinfo information including or not. The default value is `false`.

```
docinfo false
```

## Advanced Usage

Elasticsearch Input plugin and Elasticsearch output plugin can combine to transfer records into another cluster.

```aconf
<source>
  @type elasticsearch
  host original-cluster.local
  port 9200
  tag raw.elasticsearch
  index_name logstash-*
  docinfo true
  # repeat false
  # num_slices 2
  # with_transporter_log true
</source>
<match raw.elasticsearch>
  @type elasticsearch
  host transferred-cluster.local
  port 9200
  index_name ${$.@metadata._index}
  type_name ${$.@metadata._type} # This parameter will be deprecated due to Removal of mapping types since ES7.
  id_key ${$.@metadata._id} # This parameter is needed for prevent duplicated records.
  <buffer tag, $.@metadata._index, $.@metadata._type, $.@metadata._id>
    @type memory # should use file buffer for preventing chunk lost
  </buffer>
</match>
```
