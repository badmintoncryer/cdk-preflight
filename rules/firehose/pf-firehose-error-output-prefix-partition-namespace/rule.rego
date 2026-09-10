package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-firehose-error-output-prefix-partition-namespace", "ERROR", name,
	sprintf("%s.ErrorOutputPrefix", [path]),
	sprintf("ErrorOutputPrefix interpolates '%s'; the stream create fails with \"Dynamic Partitioning Namespaces can't be part of an error prefix expression\"", [e]),
	"Keep partitionKeyFromQuery / partitionKeyFromLambda in Prefix only",
	"https://docs.aws.amazon.com/firehose/latest/dev/s3-prefixes.html") if {
	some [name, path, c] in _pf_fhlib_prefixed
	v := object.get(c, "ErrorOutputPrefix", null)
	_pf_fhlib_lit(v)
	some e in _pf_fhlib_exprs(v)
	startswith(_pf_fhlib_ns(e), "partitionKeyFrom")
}
