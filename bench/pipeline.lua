-- Deep HTTP/1.1 pipelining, the shape TechEmpower's "Plaintext" test
-- measures: DEPTH requests written back to back into one buffer, one
-- syscall carrying all of them, one read carrying all the answers.
-- RFC 9112 9.3 allows it (a client MAY send multiple requests without
-- waiting); virtually no real user agent does, so this measures the
-- FRAMER's amortized cost with the per-round-trip cost divided away -
-- not a shape any browser will ever send us.
--
-- DEPTH comes from the environment (bench/pipeline.sh sets it) because
-- wrk's -s script takes no arguments of its own.
local depth = tonumber(os.getenv("PIPELINE_DEPTH")) or 16

request = function()
   local one = wrk.format(nil, wrk.path, wrk.headers, nil)
   local all = {}
   for i = 1, depth do all[i] = one end
   return table.concat(all)
end
