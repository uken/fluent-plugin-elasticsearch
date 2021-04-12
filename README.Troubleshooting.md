## Index

* [Troubleshooting](#troubleshooting)
  + [Cannot send events to elasticsearch](#cannot-send-events-to-elasticsearch)
  + [Cannot see detailed failure log](#cannot-see-detailed-failure-log)
  + [Cannot connect TLS enabled reverse Proxy](#cannot-connect-tls-enabled-reverse-proxy)
  + [Declined logs are resubmitted forever, why?](#declined-logs-are-resubmitted-forever-why)
  + [Suggested to install typhoeus gem, why?](#suggested-to-install-typhoeus-gem-why)
  + [Stopped to send events on k8s, why?](#stopped-to-send-events-on-k8s-why)
  + [Random 400 - Rejected by Elasticsearch is occured, why?](#random-400---rejected-by-elasticsearch-is-occured-why)
  + [Fluentd seems to hang if it unable to connect Elasticsearch, why?](#fluentd-seems-to-hang-if-it-unable-to-connect-elasticsearch-why)
  + [Enable Index Lifecycle Management](#enable-index-lifecycle-management)
    + [Configuring for dynamic index or template](#configuring-for-dynamic-index-or-template)
  + [How to specify index codec](#how-to-specify-index-codec)
  + [Cannot push logs to Elasticsearch with connect_write timeout reached, why?](#cannot-push-logs-to-elasticsearch-with-connect_write-timeout-reached-why)


## Troubleshooting

### Cannot send events to Elasticsearch

A common cause of failure is that you are trying to connect to an Elasticsearch instance with an incompatible version.

For example, td-agent currently bundles the 6.x series of the [elasticsearch-ruby](https://github.com/elastic/elasticsearch-ruby) library. This means that your Elasticsearch server also needs to be 6.x. You can check the actual version of the client library installed on your system by executing the following command.

```
# For td-agent users
$ /usr/sbin/td-agent-gem list elasticsearch
# For standalone Fluentd users
$ fluent-gem list elasticsearch
```
Or, fluent-plugin-elasticsearch v2.11.7 or later, users can inspect version incompatibility with the `validate_client_version` option:

```
validate_client_version true
```

If you get the following error message, please consider to install compatible elasticsearch client gems:

```
Detected ES 5 but you use ES client 6.1.0.
Please consider to use 5.x series ES client.
```

For further details of the version compatibility issue, please read [the official manual](https://github.com/elastic/elasticsearch-ruby#compatibility).

### Cannot see detailed failure log

A common cause of failure is that you are trying to connect to an Elasticsearch instance with an incompatible ssl protocol version.

For example, `out_elasticsearch` set up ssl_version to TLSv1 due to historical reason.
Modern Elasticsearch ecosystem requests to communicate with TLS v1.2 or later.
But, in this case, `out_elasticsearch` conceals transporter part failure log by default.
If you want to acquire transporter log, please consider to set the following configuration:

```
with_transporter_log true
@log_level debug
```

Then, the following log is shown in Fluentd log:

```
2018-10-24 10:00:00 +0900 [error]: #0 [Faraday::ConnectionFailed] SSL_connect returned=1 errno=0 state=SSLv2/v3 read server hello A: unknown protocol (OpenSSL::SSL::SSLError) {:host=>"elasticsearch-host", :port=>80, :scheme=>"https", :user=>"elastic", :password=>"changeme", :protocol=>"https"}
```

This indicates that inappropriate TLS protocol version is used.
If you want to use TLS v1.2, please use `ssl_version` parameter like as:

```
ssl_version TLSv1_2
```

or, in v4.0.2 or later with Ruby 2.5 or later combination, the following congiuration is also valid:

```
ssl_max_version TLSv1_2
ssl_min_version TLSv1_2
```

### Cannot connect TLS enabled reverse Proxy

A common cause of failure is that you are trying to connect to an Elasticsearch instance behind nginx reverse proxy which uses an incompatible ssl protocol version.

For example, `out_elasticsearch` set up ssl_version to TLSv1 due to historical reason.
Nowadays, nginx reverse proxy uses TLS v1.2 or later for security reason.
But, in this case, `out_elasticsearch` conceals transporter part failure log by default.

If you set up nginx reverse proxy with TLS v1.2:

```
server {
    listen <your IP address>:9400;
    server_name <ES-Host>;
    ssl on;
    ssl_certificate /etc/ssl/certs/server-bundle.pem;
    ssl_certificate_key /etc/ssl/private/server-key.pem;
    ssl_client_certificate /etc/ssl/certs/ca.pem;
    ssl_verify_client   on;
    ssl_verify_depth    2;

    # Reference : https://cipherli.st/
    ssl_protocols TLSv1.2;
    ssl_prefer_server_ciphers on;
    ssl_ciphers "EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH";
    ssl_ecdh_curve secp384r1; # Requires nginx >= 1.1.0
    ssl_session_cache shared:SSL:10m;
    ssl_session_tickets off; # Requires nginx >= 1.5.9
    ssl_stapling on; # Requires nginx >= 1.3.7
    ssl_stapling_verify on; # Requires nginx => 1.3.7
    resolver 127.0.0.1 valid=300s;
    resolver_timeout 5s;
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload";
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;

    client_max_body_size 64M;
    keepalive_timeout 5;

    location / {
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_pass http://localhost:9200;
    }
}
```

Then, nginx reverse proxy starts with TLSv1.2.

Fluentd suddenly dies with the following log:
```
Oct 31 9:44:45 <ES-Host> fluentd[6442]: log writing failed. execution expired
Oct 31 9:44:45 <ES-Host> fluentd[6442]: /opt/fluentd/embedded/lib/ruby/gems/2.4.0/gems/excon-0.62.0/lib/excon/ssl_socket.rb:10:in `initialize': stack level too deep (SystemStackError)
Oct 31 9:44:45 <ES-Host> fluentd[6442]:         from /opt/fluentd/embedded/lib/ruby/gems/2.4.0/gems/excon-0.62.0/lib/excon/connection.rb:429:in `new'
Oct 31 9:44:45 <ES-Host> fluentd[6442]:         from /opt/fluentd/embedded/lib/ruby/gems/2.4.0/gems/excon-0.62.0/lib/excon/connection.rb:429:in `socket'
Oct 31 9:44:45 <ES-Host> fluentd[6442]:         from /opt/fluentd/embedded/lib/ruby/gems/2.4.0/gems/excon-0.62.0/lib/excon/connection.rb:111:in `request_call'
Oct 31 9:44:45 <ES-Host> fluentd[6442]:         from /opt/fluentd/embedded/lib/ruby/gems/2.4.0/gems/excon-0.62.0/lib/excon/middlewares/mock.rb:48:in `request_call'
Oct 31 9:44:45 <ES-Host> fluentd[6442]:         from /opt/fluentd/embedded/lib/ruby/gems/2.4.0/gems/excon-0.62.0/lib/excon/middlewares/instrumentor.rb:26:in `request_call'
Oct 31 9:44:45 <ES-Host> fluentd[6442]:         from /opt/fluentd/embedded/lib/ruby/gems/2.4.0/gems/excon-0.62.0/lib/excon/middlewares/base.rb:16:in `request_call'
Oct 31 9:44:45 <ES-Host> fluentd[6442]:         from /opt/fluentd/embedded/lib/ruby/gems/2.4.0/gems/excon-0.62.0/lib/excon/middlewares/base.rb:16:in `request_call'
Oct 31 9:44:45 <ES-Host> fluentd[6442]:         from /opt/fluentd/embedded/lib/ruby/gems/2.4.0/gems/excon-0.62.0/lib/excon/middlewares/base.rb:16:in `request_call'
Oct 31 9:44:45 <ES-Host> fluentd[6442]:          ... 9266 levels...
Oct 31 9:44:45 <ES-Host> fluentd[6442]:         from /opt/td-agent/embedded/lib/ruby/site_ruby/2.4.0/rubygems/core_ext/kernel_require.rb:55:in `require'
Oct 31 9:44:45 <ES-Host> fluentd[6442]:         from /opt/fluentd/embedded/lib/ruby/gems/2.4.0/gems/fluentd-1.2.5/bin/fluentd:8:in `<top (required)>'
Oct 31 9:44:45 <ES-Host> fluentd[6442]:         from /opt/fluentd/embedded/bin/fluentd:22:in `load'
Oct 31 9:44:45 <ES-Host> fluentd[6442]:         from /opt/fluentd/embedded/bin/fluentd:22:in `<main>'
Oct 31 9:44:45 <ES-Host> systemd[1]: fluentd.service: Control process exited, code=exited status=1
```

If you want to acquire transporter log, please consider to set the following configuration:

```
with_transporter_log true
@log_level debug
```

Then, the following log is shown in Fluentd log:

```
2018-10-31 10:00:57 +0900 [warn]: #7 [Faraday::ConnectionFailed] Attempt 2 connecting to {:host=>"<ES-Host>", :port=>9400, :scheme=>"https", :protocol=>"https"}
2018-10-31 10:00:57 +0900 [error]: #7 [Faraday::ConnectionFailed] Connection reset by peer - SSL_connect (Errno::ECONNRESET) {:host=>"<ES-Host>", :port=>9400, :scheme=>"https", :protocol=>"https"}
```

The above logs indicates that using incompatible SSL/TLS version between fluent-plugin-elasticsearch and nginx, which is reverse proxy, is root cause of this issue.

If you want to use TLS v1.2, please use `ssl_version` parameter like as:

```
ssl_version TLSv1_2
```

or, in v4.0.2 or later with Ruby 2.5 or later combination, the following congiuration is also valid:

```
ssl_max_version TLSv1_2
ssl_min_version TLSv1_2
```

### Declined logs are resubmitted forever, why?

Sometimes users write Fluentd configuration like this:

```aconf
<match **>
  @type elasticsearch
  host localhost
  port 9200
  type_name fluentd
  logstash_format true
  time_key @timestamp
  include_timestamp true
  reconnect_on_error true
  reload_on_failure true
  reload_connections false
  request_timeout 120s
</match>
```

The above configuration does not use [`@label` feature](https://docs.fluentd.org/v1.0/articles/config-file#(5)-group-filter-and-output:-the-%E2%80%9Clabel%E2%80%9D-directive) and use glob(**) pattern.
It is usually problematic configuration.

In error scenario, error events will be emitted with `@ERROR` label, and `fluent.*` tag.
The black hole glob pattern resubmits a problematic event into pushing Elasticsearch pipeline.

This situation causes flood of declined log:

```log
2018-11-13 11:16:27 +0000 [warn]: #0 dump an error event: error_class=Fluent::Plugin::ElasticsearchErrorHandler::ElasticsearchError error="400 - Rejected by Elasticsearch" location=nil tag="app.fluentcat" time=2018-11-13 11:16:17.492985640 +0000 record={"message"=>"\xFF\xAD"}
2018-11-13 11:16:38 +0000 [warn]: #0 dump an error event: error_class=Fluent::Plugin::ElasticsearchErrorHandler::ElasticsearchError error="400 - Rejected by Elasticsearch" location=nil tag="fluent.warn" time=2018-11-13 11:16:27.978851140 +0000 record={"error"=>"#<Fluent::Plugin::ElasticsearchErrorHandler::ElasticsearchError: 400 - Rejected by Elasticsearch>", "location"=>nil, "tag"=>"app.fluentcat", "time"=>2018-11-13 11:16:17.492985640 +0000, "record"=>{"message"=>"\xFF\xAD"}, "message"=>"dump an error event: error_class=Fluent::Plugin::ElasticsearchErrorHandler::ElasticsearchError error=\"400 - Rejected by Elasticsearch\" location=nil tag=\"app.fluentcat\" time=2018-11-13 11:16:17.492985640 +0000 record={\"message\"=>\"\\xFF\\xAD\"}"}
```

Then, user should use more concrete tag route or use `@label`.
The following sections show two examples how to solve flood of declined log.
One is using concrete tag routing, the other is using label routing.

#### Using concrete tag routing

The following configuration uses concrete tag route:

```aconf
<match out.elasticsearch.**>
  @type elasticsearch
  host localhost
  port 9200
  type_name fluentd
  logstash_format true
  time_key @timestamp
  include_timestamp true
  reconnect_on_error true
  reload_on_failure true
  reload_connections false
  request_timeout 120s
</match>
```

#### Using label feature

The following configuration uses label:

```aconf
<source>
  @type forward
  @label @ES
</source>
<label @ES>
  <match out.elasticsearch.**>
    @type elasticsearch
    host localhost
    port 9200
    type_name fluentd
    logstash_format true
    time_key @timestamp
    include_timestamp true
    reconnect_on_error true
    reload_on_failure true
    reload_connections false
    request_timeout 120s
  </match>
</label>
<label @ERROR>
  <match **>
    @type stdout
  </match>
</label>
```

### Suggested to install typhoeus gem, why?

fluent-plugin-elasticsearch doesn't depend on typhoeus gem by default.
If you want to use typhoeus backend, you must install typhoeus gem by your own.

If you use vanilla Fluentd, you can install it by:

```
gem install typhoeus
```

But, you use td-agent instead of vanilla Fluentd, you have to use `td-agent-gem`:

```
td-agent-gem install typhoeus
```

In more detail, please refer to [the official plugin management document](https://docs.fluentd.org/v1.0/articles/plugin-management).

### Stopped to send events on k8s, why?

fluent-plugin-elasticsearch reloads connection after 10000 requests. (Not correspond to events counts because ES plugin uses bulk API.)

This functionality which is originated from elasticsearch-ruby gem is enabled by default.

Sometimes this reloading functionality bothers users to send events with ES plugin.

On k8s platform, users sometimes shall specify the following settings:

```aconf
reload_connections false
reconnect_on_error true
reload_on_failure true
```

If you use [fluentd-kubernetes-daemonset](https://github.com/fluent/fluentd-kubernetes-daemonset), you can specify them with environment variables:

* `FLUENT_ELASTICSEARCH_RELOAD_CONNECTIONS` as `false`
* `FLUENT_ELASTICSEARCH_RECONNECT_ON_ERROR` as `true`
* `FLUENT_ELASTICSEARCH_RELOAD_ON_FAILURE` as `true`

This issue had been reported at [#525](https://github.com/uken/fluent-plugin-elasticsearch/issues/525).

### Random 400 - Rejected by Elasticsearch is occured, why?

Index templates installed Elasticsearch sometimes generates 400 - Rejected by Elasticsearch errors.
For example, kubernetes audit log has structure:

```json
"responseObject":{
   "kind":"SubjectAccessReview",
   "apiVersion":"authorization.k8s.io/v1beta1",
   "metadata":{
      "creationTimestamp":null
   },
   "spec":{
      "nonResourceAttributes":{
         "path":"/",
         "verb":"get"
      },
      "user":"system:anonymous",
      "group":[
         "system:unauthenticated"
      ]
   },
   "status":{
      "allowed":true,
      "reason":"RBAC: allowed by ClusterRoleBinding \"cluster-system-anonymous\" of ClusterRole \"cluster-admin\" to User \"system:anonymous\""
   }
},
```

The last element `status` sometimes becomes `"status":"Success"`.
This element type glich causes status 400 error.

There are some solutions for fixing this:

#### Solution 1

For a key which causes element type glich case.

Using dymanic mapping with the following template:

```json
{
  "template": "YOURINDEXNAME-*",
  "mappings": {
    "fluentd": {
      "dynamic_templates": [
        {
          "default_no_index": {
            "path_match": "^.*$",
            "path_unmatch": "^(@timestamp|auditID|level|stage|requestURI|sourceIPs|metadata|objectRef|user|verb)(\\..+)?$",
            "match_pattern": "regex",
            "mapping": {
              "index": false,
              "enabled": false
            }
          }
        }
      ]
    }
  }
}
```

Note that `YOURINDEXNAME` should be replaced with your using index prefix.

#### Solution 2

For unstable `responseObject` and `requestObject` key existence case.

```aconf
<filter YOURROUTETAG>
  @id kube_api_audit_normalize
  @type record_transformer
  auto_typecast false
  enable_ruby true
  <record>
    host "#{ENV['K8S_NODE_NAME']}"
    responseObject ${record["responseObject"].nil? ? "none": record["responseObject"].to_json}
    requestObject ${record["requestObject"].nil? ? "none": record["requestObject"].to_json}
    origin kubernetes-api-audit
  </record>
</filter>
```

Normalize `responseObject` and `requestObject` key with record_transformer and other similiar plugins is needed.

### Fluentd seems to hang if it unable to connect Elasticsearch, why?

On `#configure` phase, ES plugin should wait until ES instance communication is succeeded.
And ES plugin blocks to launch Fluentd by default.
Because Fluentd requests to set up configuration correctly on `#configure` phase.

After `#configure` phase, it runs very fast and send events heavily in some heavily using case.

In this scenario, we need to set up configuration correctly until `#configure` phase.
So, we provide default parameter is too conservative to use advanced users.

To remove too pessimistic behavior, you can use the following configuration:

```aconf
<match **>
  @type elasticsearch
  # Some advanced users know their using ES version.
  # We can disable startup ES version checking.
  verify_es_version_at_startup false
  # If you know that your using ES major version is 7, you can set as 7 here.
  default_elasticsearch_version 7
  # If using very stable ES cluster, you can reduce retry operation counts. (minmum is 1)
  max_retry_get_es_version 1
  # If using very stable ES cluster, you can reduce retry operation counts. (minmum is 1)
  max_retry_putting_template 1
  # ... and some ES plugin configuration
</match>
```

### Enable Index Lifecycle Management

Index lifecycle management is template based index management feature.

Main ILM feature parameters are:

* `index_name` (when logstash_format as false)
* `logstash_prefix` (when logstash_format as true)
* `enable_ilm`
* `ilm_policy_id`
* `ilm_policy`

* Advanced usage parameters
  * `application_name`
  * `index_separator`

They are not all mandatory parameters but they are used for ILM feature in effect.

ILM target index alias is created with `index_name` or an index which is calculated from `logstash_prefix`.

From Elasticsearch plugin v4.0.0, ILM target index will be calculated from `index_name` (normal mode) or `logstash_prefix` (using with `logstash_format`as true).

**NOTE:** Before Elasticsearch plugin v4.1.0, using `deflector_alias` parameter when ILM is enabled is permitted and handled, but, in the later releases such that 4.1.1 or later, it cannot use with when ILM is enabled.

And also, ILM feature users should specify their Elasticsearch template for ILM enabled indices.
Because ILM settings are injected into their Elasticsearch templates.

`application_name` and `index_separator` also affect alias index names.

But this parameter is prepared for advanced usage.

It usually should be used with default value which is `default`.

Then, ILM parameters are used in alias index like as:

##### Simple `index_name` case:

`<index_name><index_separator><application_name>-000001`.

##### `logstash_format` as `true` case:

`<logstash_prefix><logstash_prefix_separator><application_name><logstash_prefix_separator><logstash_dateformat>-000001`.

#### Example ILM settings

```aconf
index_name fluentd-${tag}
application_name ${tag}
index_date_pattern "now/d"
enable_ilm true
# Policy configurations
ilm_policy_id fluentd-policy
# ilm_policy {} # Use default policy
template_name your-fluentd-template
template_file /path/to/fluentd-template.json
# customize_template {"<<index_prefix>>": "fluentd"}
```

Note: This plugin only creates rollover-enabled indices, which are aliases pointing to them and index templates, and creates an ILM policy if enabled.

#### Create ILM indices in each day

If you want to create new index in each day, you should use `logstash_format` style configuration:

```aconf
logstash_prefix fluentd
application_name default
index_date_pattern "now/d"
enable_ilm true
# Policy configurations
ilm_policy_id fluentd-policy
# ilm_policy {} # Use default policy
template_name your-fluentd-template
template_file /path/to/fluentd-template.json
```

Note that if you create a new set of indexes every day, the elasticsearch ILM policy system will treat each day separately and will always
maintain a separate active write index for each day.

If you have a rollover based on max_age, it will continue to roll the indexes for prior dates even if no new documents are indexed.  If you want
to delete indexes after a period of time, the ILM policy will never delete the current write index regardless of its age, so you would need a separate
system, such as curator, to actually delete the old indexes.

For this reason, if you put the date into the index names with ILM you should only rollover based on size or number of documents and may need to use
curator to actually delete old indexes.

#### Fixed ILM indices

Also, users can use fixed ILM indices configuration.
If `index_date_pattern` is set as `""`(empty string), Elasticsearch plugin won't attach date pattern in ILM indices:

```aconf
index_name fluentd
application_name default
index_date_pattern ""
enable_ilm true
# Policy configurations
ilm_policy_id fluentd-policy
# ilm_policy {} # Use default policy
template_name your-fluentd-template
template_file /path/to/fluentd-template.json
```

#### Configuring for dynamic index or template

Some users want to setup ILM for dynamic index/template.
`index_petterns` and `template.settings.index.lifecycle.name` in Elasticsearch template will be overwritten by Elasticsearch plugin:

```json
{
  "index_patterns": ["mock"],
  "template": {
    "settings": {
      "index": {
        "lifecycle": {
          "name": "mock",
          "rollover_alias": "mock"
        },
        "number_of_shards": "<<shard>>",
        "number_of_replicas": "<<replica>>"
      }
    }
  }
}
```

This template will be handled with:

```aconf
<source>
  @type http
  port 5004
  bind 0.0.0.0
  body_size_limit 32m
  keepalive_timeout 10s
  <parse>
    @type json
  </parse>
</source>

<match kubernetes.var.log.containers.**etl-webserver**.log>
    @type elasticsearch
    @id out_es_etl_webserver
    @log_level info
    include_tag_key true
    host $HOST
    port $PORT
    path "#{ENV['FLUENT_ELASTICSEARCH_PATH']}"
    request_timeout "#{ENV['FLUENT_ELASTICSEARCH_REQUEST_TIMEOUT'] || '30s'}"
    scheme "#{ENV['FLUENT_ELASTICSEARCH_SCHEME'] || 'http'}"
    ssl_verify "#{ENV['FLUENT_ELASTICSEARCH_SSL_VERIFY'] || 'true'}"
    ssl_version "#{ENV['FLUENT_ELASTICSEARCH_SSL_VERSION'] || 'TLSv1'}"
    reload_connections "#{ENV['FLUENT_ELASTICSEARCH_RELOAD_CONNECTIONS'] || 'false'}"
    reconnect_on_error "#{ENV['FLUENT_ELASTICSEARCH_RECONNECT_ON_ERROR'] || 'true'}"
    reload_on_failure "#{ENV['FLUENT_ELASTICSEARCH_RELOAD_ON_FAILURE'] || 'true'}"
    log_es_400_reason "#{ENV['FLUENT_ELASTICSEARCH_LOG_ES_400_REASON'] || 'false'}"
    logstash_prefix "#{ENV['FLUENT_ELASTICSEARCH_LOGSTASH_PREFIX'] || 'etl-webserver'}"
    logstash_format "#{ENV['FLUENT_ELASTICSEARCH_LOGSTASH_FORMAT'] || 'false'}"
    index_name "#{ENV['FLUENT_ELASTICSEARCH_LOGSTASH_INDEX_NAME'] || 'etl-webserver'}"
    type_name "#{ENV['FLUENT_ELASTICSEARCH_LOGSTASH_TYPE_NAME'] || 'fluentd'}"
    time_key "#{ENV['FLUENT_ELASTICSEARCH_TIME_KEY'] || '@timestamp'}"
    include_timestamp "#{ENV['FLUENT_ELASTICSEARCH_INCLUDE_TIMESTAMP'] || 'true'}"

    # ILM Settings - WITH ROLLOVER support
    # https://github.com/uken/fluent-plugin-elasticsearch#enable-index-lifecycle-management
    application_name "etl-webserver"
    index_date_pattern ""
    # Policy configurations
    enable_ilm true
    ilm_policy_id etl-webserver
    ilm_policy_overwrite true
    ilm_policy {"policy": {"phases": {"hot": {"min_age": "0ms","actions": {"rollover": {"max_age": "5m","max_size": "3gb"},"set_priority": {"priority": 100}}},"delete": {"min_age": "30d","actions": {"delete": {"delete_searchable_snapshot": true}}}}}}
    use_legacy_template false
    template_name etl-webserver
    template_file /configs/index-template.json
    template_overwrite true
    customize_template {"<<shard>>": "3","<<replica>>": "0"}

    <buffer>
        flush_thread_count "#{ENV['FLUENT_ELASTICSEARCH_BUFFER_FLUSH_THREAD_COUNT'] || '8'}"
        flush_interval "#{ENV['FLUENT_ELASTICSEARCH_BUFFER_FLUSH_INTERVAL'] || '5s'}"
        chunk_limit_size "#{ENV['FLUENT_ELASTICSEARCH_BUFFER_CHUNK_LIMIT_SIZE'] || '8MB'}"
        total_limit_size "#{ENV['FLUENT_ELASTICSEARCH_TOTAL_LIMIT_SIZE'] || '450MB'}"
        queue_limit_length "#{ENV['FLUENT_ELASTICSEARCH_BUFFER_QUEUE_LIMIT_LENGTH'] || '32'}"
        retry_max_interval "#{ENV['FLUENT_ELASTICSEARCH_BUFFER_RETRY_MAX_INTERVAL'] || '60s'}"
        retry_forever false
    </buffer>
</match>
```

For more details, please refer the discussion:
https://github.com/uken/fluent-plugin-elasticsearch/issues/867

### How to specify index codec

Elasticsearch can handle compression methods for stored data such as LZ4 and best_compression.
fluent-plugin-elasticsearch doesn't provide API which specifies compression method.

Users can specify stored data compression method with template:

Create `compression.json` as follows:

```json
{
  "order": 100,
  "index_patterns": [
    "YOUR-INDEX-PATTERN"
  ],
  "settings": {
    "index": {
      "codec": "best_compression"
    }
  }
}
```

Then, specify the above template in your configuration:

```aconf
template_name best_compression_tmpl
template_file compression.json
```

Elasticsearch will store data with `best_compression`:

```
% curl -XGET 'http://localhost:9200/logstash-2019.12.06/_settings?pretty'
```

```json
{
  "logstash-2019.12.06" : {
    "settings" : {
      "index" : {
        "codec" : "best_compression",
        "number_of_shards" : "1",
        "provided_name" : "logstash-2019.12.06",
        "creation_date" : "1575622843800",
        "number_of_replicas" : "1",
        "uuid" : "THE_AWESOMEUUID",
        "version" : {
          "created" : "7040100"
        }
      }
    }
  }
}
```

### Cannot push logs to Elasticsearch with connect_write timeout reached, why?

It seems that Elasticsearch cluster is exhausted.

Usually, Fluentd complains like the following log:

```log
2019-12-29 00:23:33 +0000 [warn]: buffer flush took longer time than slow_flush_log_threshold: elapsed_time=27.283766102716327 slow_flush_log_threshold=15.0 plugin_id="object:aaaffaaaaaff"
2019-12-29 00:23:33 +0000 [warn]: buffer flush took longer time than slow_flush_log_threshold: elapsed_time=26.161768959928304 slow_flush_log_threshold=15.0 plugin_id="object:aaaffaaaaaff"
2019-12-29 00:23:33 +0000 [warn]: buffer flush took longer time than slow_flush_log_threshold: elapsed_time=28.713624476008117 slow_flush_log_threshold=15.0 plugin_id="object:aaaffaaaaaff"
2019-12-29 01:39:18 +0000 [warn]: Could not push logs to Elasticsearch, resetting connection and trying again. connect_write timeout reached
2019-12-29 01:39:18 +0000 [warn]: Could not push logs to Elasticsearch, resetting connection and trying again. connect_write timeout reached
```

This warnings is usually caused by exhaused Elasticsearch cluster due to resource shortage.

If CPU usage is spiked and Elasticsearch cluster is eating up CPU resource, this issue is caused by CPU resource shortage.

Check your Elasticsearch cluster health status and resource usage.
