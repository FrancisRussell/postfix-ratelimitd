# Changelog

## Unreleased

* Initial release.
* TOML-based configuration.
* Syslog logging support.
* Valkey / Redis storage backend support via Unix Domain Socket and TCP/IP with optional TLS.
* Bucket based coalescing of send times with a maximum overcount of 2% of
  user-chosen time windows.
* Rate-limiting based on literal and regex matches on SASL username along with fallback rule.
* Postfix policy support via Unix domain socket endpoint.
* Integration tests against temporary Valkey instances.
* Multiple connection support via Tokio async.
