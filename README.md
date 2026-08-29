# postfix-ratelimitd

A Postfix SMTP access policy daemon that rate-limits recipients per SASL
username within a sliding time window, backed by Valkey/Redis.

## Configuration

```toml
[redis]
# Connection to the RESP-compatible backend (Redis, Valkey, etc). Also accepts
# a unix socket: url = "redis+unix:///run/valkey/valkey.sock", or TLS via a
# "rediss://" scheme, verified against the system's trusted CAs.
url = "redis://127.0.0.1:6379"
db = 1
key_prefix = "postfix-ratelimitd:"

# Optional; read as the connection password. Error if url also embeds one
# (e.g. "redis://:secret@host") - supply it only one way.
password_file = "/etc/valkey/password"

[server]
# Unix socket Postfix's check_policy_service connects to. This path doesn't
# depend on Postfix at all - it's created fresh on each start (e.g. via
# systemd's RuntimeDirectory=). It works as an absolute path only if
# Postfix's smtpd isn't chrooted - a chrooted smtpd can't see anything
# outside its chroot (usually /var/spool/postfix), regardless of path.
#
# If your smtpd is chrooted (common on Debian/Ubuntu), put the socket under
# the chroot instead, e.g.:
#   socket = "/var/spool/postfix/postfix-ratelimitd/ratelimit.sock"
# and reference it from master.cf as a path relative to Postfix's queue
# directory rather than by absolute path: "unix:postfix-ratelimitd/ratelimit.sock".
# A queue-relative reference resolves the same way whether or not smtpd is
# chrooted, so it's a fine choice for this location either way.
socket = "/run/postfix-ratelimitd/ratelimit.sock"

# Action to take when a Valkey/Redis error prevents completing a check: "defer"
# (fail closed, the default) or "permit" (fail open).
on_redis_error = "defer"

# A request with no SASL username is always permitted - there's no identity to
# rate-limit against - but by default it's also logged, since it usually means
# smtpd_data_restrictions is applied somewhere it shouldn't be (see "Postfix
# wiring" below). Set to false only if that's an intentional, known setup and
# the warning is just noise.
warn_on_unauthenticated = true

# Non-default rules are evaluated top-to-bottom; the first match wins.
# Exactly one `type = "default"` rule must be present, as the fallback when
# nothing else matches - its position in the list doesn't matter. Each
# window's duration must be a whole number of seconds, at least 60s and at
# most 31 days.

[[limits]]
type = "username"
username = "alice"
windows = [
    { count = 20, duration = "1h" },
    { count = 100, duration = "1d" },
]

[[limits]]
type = "regex"
regex = '@contractors\.example\.com$'
windows = [
    { count = 10, duration = "1h" },
]

[[limits]]
type = "default"
windows = [
    { count = 50, duration = "1h" },
    { count = 200, duration = "1d" },
]
```

`redis.db` picks a dedicated numbered Valkey/Redis database so this daemon's
keys never collide with an unrelated application sharing the same server;
`redis.key_prefix` is then purely for human-readability when inspecting the
keyspace directly, not for isolation.

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
