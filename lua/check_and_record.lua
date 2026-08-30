-- KEYS: one hash per distinct bucket size actually used by this check's
-- windows - multiple windows share a key if they compute the same bucket
-- size (see limiter.rs). Each hash field is a bucket id (a whole multiple of
-- that key's bucket size); its value is the accumulated recipient count
-- recorded in that bucket.
--
-- ARGV[1]: JSON-encoded request (see limiter.rs's CheckRequest), sent as one
-- value rather than flattened into positional arguments so field names
-- travel with the data instead of relying on this script and limiter.rs
-- agreeing on an implicit argument order:
--   recipient_count: recipient count for this message.
--   now_override: optional; a fixed unix timestamp to use as "now" instead of
--     calling TIME, for tests that need to exercise weeks- or months-long
--     windows without real time passing. Never sent outside tests.
--   plan: this check's precomputed bucket sizes and windows -
--     bucket_sizes: each KEYS[i]'s bucket size in seconds, parallel to KEYS.
--     retention_secs: how long KEYS[i] must retain buckets, parallel to
--       KEYS - the longest span of any window sharing that key, since a key
--       must keep history for whichever sharing window needs the most. Used
--       as both that key's EXPIRE and its prune cutoff.
--     windows: one { key_index, span_secs, limit } object per configured
--       window. key_index arrives 0-based (matching bucket_sizes/limiter.rs);
--       this script switches it to 1-based right after decoding, below.
--       span_secs is the window's duration rounded up to a whole number of
--       buckets (computed once from config, not here, since it doesn't
--       depend on anything in KEYS).

local request = cjson.decode(ARGV[1])
local recipient_count = request.recipient_count
local plan = request.plan
local bucket_sizes = plan.bucket_sizes
local num_keys = #bucket_sizes

local now = request.now_override or tonumber(redis.call('TIME')[1])

-- plan.windows' key_index is 0-based (matching bucket_sizes/limiter.rs);
-- switch it to 1-based here, once, rather than adding 1 at every use below.
for _, window in ipairs(plan.windows) do
    window.key_index = window.key_index + 1
end

-- Fetch and parse each key's buckets once, even if multiple windows share it.
-- buckets_by_key[i] is an array of { id = <bucket id>, count = <recipients
-- recorded in that bucket> }, one per field in KEYS[i]'s hash.
local buckets_by_key = {}
for i = 1, num_keys do
    local fields = redis.call('HGETALL', KEYS[i])
    local buckets = {}
    for j = 1, #fields, 2 do
        buckets[#buckets + 1] = { id = tonumber(fields[j]), count = tonumber(fields[j + 1]) }
    end
    buckets_by_key[i] = buckets
end

-- Check every window before recording anything: if a later window rejects,
-- this avoids having already recorded against an earlier window's key, which
-- would double-count the message when Postfix retries after the deferral.
for _, window in ipairs(plan.windows) do
    local bucket_size = bucket_sizes[window.key_index]
    local oldest = now - window.span_secs

    local total = recipient_count
    for _, entry in ipairs(buckets_by_key[window.key_index]) do
        -- Count a bucket in full as long as its end hasn't passed the cutoff yet, even if
        -- only part of it is still within the window - this can only ever overcount a
        -- window, never undercount it.
        if (entry.id + 1) * bucket_size > oldest then
            total = total + entry.count
        end
    end

    if total > window.limit then
        return 0
    end
end

-- Record: one HINCRBY per unique key, not per window, and prune each key's
-- buckets that are stale even for its longest-retention window while we're
-- there.
for i = 1, num_keys do
    local bucket_size = bucket_sizes[i]
    local bucket = math.floor(now / bucket_size)
    redis.call('HINCRBY', KEYS[i], bucket, recipient_count)
    -- EXPIRE lets the key clean itself up via TTL if this sender goes quiet.
    redis.call('EXPIRE', KEYS[i], plan.retention_secs[i])

    local oldest = now - plan.retention_secs[i]
    local stale = {}
    for _, entry in ipairs(buckets_by_key[i]) do
        if (entry.id + 1) * bucket_size <= oldest then
            stale[#stale + 1] = entry.id
        end
    end
    if #stale > 0 then
        redis.call('HDEL', KEYS[i], unpack(stale))
    end
end

return 1
