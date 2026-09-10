package cdk_preflight

import rego.v1

# Both sides are opaque strings: the jq object constructor on one side and
# the !{partitionKeyFromQuery:...} namespaces on the other. Only a simple
# top level constructor is parsed; anything else is left alone.
_pf_fhdpk_keys(q) := ks if {
	regex.match(`^\{[^{}]*\}$`, q)
	ks := {k |
		some m in regex.find_n(`[{,]\s*"?[A-Za-z0-9_-]+"?\s*:`, q, -1)
		k := trim(trim_right(trim_left(m, "{,"), ":"), " \"")
	}
}

_pf_fhdpq_prefix_keys(c) := ks if {
	p := object.get(c, "Prefix", "")
	is_string(p)
	ks := {v |
		some e in _pf_fhlib_exprs(p)
		_pf_fhlib_ns(e) == "partitionKeyFromQuery"
		v := _pf_fhlib_val(e)
	}
}

_pf_fhdpq_bad contains [name, path, k] if {
	some [name, path, _, t, pr] in _pf_fhlib_procs
	t == "MetadataExtraction"
	some [nm, p, c] in _pf_fhlib_dests
	nm == name
	p == path
	some q in _pf_fhlib_params(pr, "MetadataExtractionQuery")
	_pf_fhlib_lit(q)
	some k in _pf_fhdpk_keys(q)
	not k in _pf_fhdpq_prefix_keys(c)
}

violation contains make_diag_full("pf-firehose-dynamic-partitioning-query-key", "ERROR", name,
	sprintf("%s.ProcessingConfiguration", [path]),
	sprintf("the MetadataExtraction query produces key '%s' but the prefix never interpolates !{partitionKeyFromQuery:%s}; the stream create fails with \"MetaDataExtraction JQ Query can't contain keys that are not present in the S3 Prefix expression\"", [k, k]),
	"Interpolate every extracted key into Prefix, or drop it from the query",
	"https://docs.aws.amazon.com/firehose/latest/dev/dynamic-partitioning-partitioning-keys.html") if {
	some [name, path, k] in _pf_fhdpq_bad
}
