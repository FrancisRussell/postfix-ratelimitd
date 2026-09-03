# postfix-ratelimitd

[![CI](https://github.com/FrancisRussell/postfix-ratelimitd/actions/workflows/ci.yml/badge.svg)](https://github.com/FrancisRussell/postfix-ratelimitd/actions/workflows/ci.yml)

A Postfix SMTP access policy daemon that rate-limits recipients per SASL
username within a sliding time window, backed by Valkey/Redis.

## Configuration

A copy of the file below, ready to edit and install to
`/etc/postfix-ratelimitd/config.toml`, lives at `contrib/config.toml`.

```toml
[redis]
# Connection to the RESP-compatible backend (Redis, Valkey, etc). Also accepts
# a unix socket: url = "redis+unix:///run/valkey/valkey.sock", or TLS via a
# "rediss://" scheme, verified against the system's trusted CAs.
url = "redis://127.0.0.1:6379"

# The numeric ID of the database to connect to.
# db = 0

# The prefix for all keys inserted into Redis/Valkey.
# key_prefix = "postfix-ratelimitd"

# Optional password file. Alternatively, the password can be embedded
# into the URL (e.g. "redis://:secret@host") but it's an error to
# supply both.
# password_file = "/etc/valkey/password"

[server]

# Unix socket that Postfix's check_policy_service connects to. The parent
# folder is typically created via something like systemd's RuntimeDirectory
# directive. For both chrooted and non-chrooted setups, the postfix user
# should be added to the postfix-ratelimitd group.

# If not running smtpd in a chroot, configure Postfix
# to use the socket by specifying an absolute path.

# If smtpd is chrooted (common on Debian/Ubuntu), put the socket under
# the chroot instead, e.g.:
#   socket = "/var/spool/postfix/postfix-ratelimitd/ratelimit.sock"
# and reference it from master.cf as a path relative to Postfix's queue
# directory rather than by absolute path:
# "unix:postfix-ratelimitd/ratelimit.sock" (relative paths are resolved the
# same way regardless of whether smtpd is chrooted). In this case the parent
# folder must exist before this daemon starts and should be owned by
# postfix-ratelimitd:postfix-ratelimitd with a permissions mode of 0750.
socket = "/run/postfix-ratelimitd/ratelimit.sock"

# Action to take when a Valkey/Redis error prevents completing a check: "defer"
# or "permit". To avoid a key-store access failure silently disabling rate-limiting,
# the default is "defer".
on_redis_error = "defer"

# Typically authenticated and unauthenticated mail is received on different
# smtpd instances. Unauthenticated mail will neither be blocked nor rate-limited
# but since this is suggestive of a Postfix configuration error it is logged.
# If there is a legitimate expectation of authenticated and unauthenticated mail
# sharing this restriction class, this value can be set to `false` to disable
# logging of it.
warn_on_unauthenticated = true

# Rules matching against the SASL username, evaluated top-to-bottom; the
# first match wins. Exactly one `type = "default"` rule must be present, as
# the fallback when nothing else matches. Each window's duration must be a
# whole number of seconds, at least 60s and at most 31 days. A rule can opt
# out of rate limiting entirely with `unrestricted = true` instead of
# `windows`.

#[[sasl]]
#type = "username"
#username = "alice"
#windows = [
#    { count = 20, duration = "1h" },
#    { count = 100, duration = "1d" },
#]

#[[sasl]]
#type = "regex"
#regex = '@example\.com$'
#windows = [
#    { count = 10, duration = "1h" },
#]

#[[sasl]]
#type = "username"
#username = "monitoring"
#unrestricted = true

[[sasl]]
type = "default"
windows = [
    { count = 50, duration = "1h" },
    { count = 200, duration = "1d" },
]
```

`redis.db` selects a numbered Valkey/Redis database, defaulting to 0 like a
plain client connection would; set it to a dedicated, non-default number so
this daemon's keys never collide with an unrelated application sharing the
same server. `redis.key_prefix` is then purely for human-readability when
inspecting the keyspace directly, not for isolation.

Sending the running daemon `SIGHUP` reloads the config file, including
reconnecting to a changed `[redis]` backend. `server.socket` can't be changed
this way - that requires a restart.

## Postfix wiring

This goes on the `submission` service block in `master.cf` only - this
mechanism only applies to authenticated senders, so it has no place on the
plain inbound `smtp` service:

```
-o smtpd_data_restrictions=check_policy_service { unix:/run/postfix-ratelimitd/ratelimit.sock, { default_action = defer_if_permit Service temporarily unavailable } }
```

(If `server.socket` points under `/var/spool/postfix` instead, as noted above,
reference it here as a path relative to Postfix's queue directory rather than
by absolute path - `unix:postfix-ratelimitd/ratelimit.sock`.)

This **must** be wired into `smtpd_data_restrictions`, since only at the
`DATA` stage has Postfix seen all recipients. If it's wired to any other
restriction class instead, the daemon defers every request with "Rate limit
service misconfigured" rather than risk enforcing limits against a wrong or
partial recipient count, and logs an error naming the unexpected
`protocol_state`.

The nested `default_action` covers the case where Postfix can't reach the
daemon's socket at all (it's down, or crashed); the daemon's own responses
cover every case where it *is* reachable but the check itself failed or hit
the limit.

## Usage

```
postfix-ratelimitd --config /etc/postfix-ratelimitd/config.toml
```

| Flag | Description |
| --- | --- |
| `-c`, `--config <PATH>` | Path to the TOML config file (default `/etc/postfix-ratelimitd/config.toml`) |
| `-t`, `--check-config` | Validate the config file and exit |
| `--log-target <stdout\|syslog>` | Where to send log output (default `stdout`) |
| `--syslog-ident <NAME>` | Syslog "ident" prefix on each line; defaults to the binary name. Ignored unless `--log-target=syslog` |
| `--log-level <off\|error\|warn\|info\|debug\|trace>` | Minimum severity to log (default `info`) |

`-t` parses the config, resolves `redis.url`/`redis.password_file` into a
connection (without opening it or touching Valkey), compiles regexes, checks
the "exactly one default rule" invariant, and confirms a unix socket can be
created in the configured socket's directory (without touching the
configured socket path itself). A config referencing paths that don't exist
yet on the machine running the check will fail `-t` until those paths are in
place.

## Logging

`--log-target stdout` (the default) writes timestamped lines to stdout, safe
for local runs, containers, or anywhere else not necessarily wired to a
syslog socket. `--log-target syslog` instead sends RFC 3164 syslog via
`/dev/log` - this works whether the system uses journald (which preserves
message priority and attributes entries to this service's systemd unit the
same as native journal capture) or a standalone rsyslog/syslog-ng.

`--log-level` controls verbosity for both targets. At `debug`, every check
logs its own accept/reject outcome along with the SASL username and
recipient count involved - noisy enough that it's meant for confirming a new
deployment is wired up correctly, not for routine use.

Every 60s, an INFO line summarizes activity since the last one:

```
stats interval_secs=60 accepted=1423 rejected=37 failed_deferred=1 failed_permitted=0 unauthenticated=0 malformed=0 connections_accepted=12 connections_rejected=0 accept_errors=0 active_connections=8
```

`accepted`/`rejected` count checks that passed or hit a configured limit;
`failed_deferred`/`failed_permitted` count a Valkey/Redis error, split by
which `on_redis_error` action it took; `unauthenticated` counts a well-formed
policy request with no SASL username reaching this daemon (see
`warn_on_unauthenticated` above); `malformed` counts a request that failed to
parse at all;
`connections_rejected` counts hitting the concurrent-connection limit,
distinct from `accept_errors` (the underlying `accept()` call itself
failing, e.g. file descriptor exhaustion). Every field but
`active_connections` is a count since the last line, reset to 0 once
reported - `active_connections` is a live gauge, not a count.

A wrong `protocol_state` or a missing `recipient_count` aren't in this line
at all - see [Postfix wiring](#postfix-wiring); either means this daemon is
wired to the wrong restriction class, which should never happen in a working
deployment and is logged as an error immediately rather than tallied.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.

## AI usage

This repository discloses AI involvement per the
[ai-disclosure](https://github.com/ggfevans/ai-disclosure) convention - see
[AI_DISCLOSURE.md](AI_DISCLOSURE.md) for details.
