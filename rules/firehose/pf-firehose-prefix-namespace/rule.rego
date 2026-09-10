package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-firehose-prefix-namespace", "ERROR", name,
	sprintf("%s.%s", [path, key]),
	sprintf("'%s' names the namespace '%s'; the stream create fails with \"Namespace to the left of colon (%s) is an invalid keyword!\"", [e, ns, ns]),
	"Use timestamp, firehose, partitionKeyFromQuery or partitionKeyFromLambda",
	"https://docs.aws.amazon.com/firehose/latest/dev/s3-prefixes.html") if {
	some [name, path, c] in _pf_fhlib_prefixed
	some key in {"Prefix", "ErrorOutputPrefix"}
	v := object.get(c, key, null)
	_pf_fhlib_lit(v)
	some e in _pf_fhlib_exprs(v)
	ns := _pf_fhlib_ns(e)
	not ns in _pf_fhlib_namespaces
}
