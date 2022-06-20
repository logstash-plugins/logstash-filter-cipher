## 4.0.3
  - [Update cipher.rb] Access key length by .value.length as getLength is not exposed. [#33](https://api.github.com/repos/logstash-plugins/logstash-filter-cipher/pulls/33)

## 4.0.2
  - [DOC] Fixes "Note" formatting for the Key setting [#30](https://github.com/logstash-plugins/logstash-filter-cipher/pull/30)

## 4.0.1
  - General improvements to code and docs [#29](https://github.com/logstash-plugins/logstash-filter-cipher/pull/29)
    - Fixed threadsafety; this plugin can now be used in pipelines with more than one worker.
    - Fixed a potential leak of the configured key into logs; the key is now only included if trace-level logging is enabled.
    - Fixed an issue where configurations that used invalid `mode` or `algorithm` settings could produce unhelpful error messages.
    - Fixed an issue where a bad payload could cause the plugin to crash; when exceptions are encountered, the offending event will now be tagged with `_cipherfiltererror`.
    - Improved documentation substantially.

## 4.0.0
  - Removed obsolete iv field

## 3.0.1
  - Update gemspec summary

## 3.0.0
  - Mark deprecated iv field obsolete

## 2.0.7
  - Fix some documentation issues

## 2.0.5
 - internal,deps: Depend on logstash-core-plugin-api instead of logstash-core, removing the need to mass update plugins on major releases of logstash

## 2.0.4
 - internal,deps: New dependency requirements for logstash-core for the 5.0 release

## 2.0.3
 - bugfix: fixes base64 encoding issue, adds support for random IVs 

## 2.0.0
 - internal: Plugins were updated to follow the new shutdown semantic, this mainly allows Logstash to instruct input plugins to terminate gracefully, 
   instead of using Thread.raise on the plugins' threads. Ref: https://github.com/elastic/logstash/pull/3895
 - internal,deps: Dependency on logstash-core update to 2.0
