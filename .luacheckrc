-- Redis/Valkey's Lua scripting sandbox provides these as pre-set globals -
-- read-only from a script's own perspective, so accidentally assigning to
-- one is still flagged as a mistake rather than silently permitted.
read_globals = {
    "KEYS",
    "ARGV",
    "redis",
    "cjson",
}
