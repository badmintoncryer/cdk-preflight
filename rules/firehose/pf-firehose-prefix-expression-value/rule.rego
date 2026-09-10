package cdk_preflight

import rego.v1

_pf_fhpev_bad contains [name, path, key, e] if {
	some [name, path, c] in _pf_fhlib_prefixed
	some key in {"Prefix", "ErrorOutputPrefix"}
	v := object.get(c, key, null)
	_pf_fhlib_lit(v)
	some e in _pf_fhlib_exprs(v)
	_pf_fhlib_ns(e) == "firehose"
	not _pf_fhlib_val(e) in {"error-output-type", "random-string"}
}

_pf_fhpev_bad contains [name, path, key, e] if {
	some [name, path, c] in _pf_fhlib_prefixed
	some key in {"Prefix", "ErrorOutputPrefix"}
	v := object.get(c, key, null)
	_pf_fhlib_lit(v)
	some e in _pf_fhlib_exprs(v)
	_pf_fhlib_ns(e) == "timestamp"
	unquoted := regex.replace(_pf_fhlib_val(e), `'[^']*'`, "")
	some i in numbers.range(0, count(unquoted) - 1)
	substring(unquoted, i, 1) in _pf_fhlib_ts_bad
}

violation contains make_diag_full("pf-firehose-prefix-expression-value", "ERROR", name,
	sprintf("%s.%s", [path, key]),
	sprintf("'%s' is not a value the namespace accepts; the stream create fails with \"Invalid conversion character used in the value of the expression in %s\"", [e, key]),
	"firehose takes error-output-type or random-string; timestamp takes a Joda pattern (C I J P R T U V b f i j l o p r t are not pattern letters)",
	"https://docs.aws.amazon.com/firehose/latest/dev/s3-prefixes.html") if {
	some [name, path, key, e] in _pf_fhpev_bad
}
