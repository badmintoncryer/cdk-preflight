package cdk_preflight

import rego.v1

# The prefix DSL lives inside an opaque string, so no schema layer sees it.
violation contains make_diag_full("pf-firehose-prefix-expression-syntax", "ERROR", name,
	sprintf("%s.%s", [path, key]),
	sprintf("%s '%s' contains a '!{' that does not open a !{namespace:value} expression; the stream create fails with \"Invalid expression usage\"", [key, v]),
	"Close the expression as !{namespace:value}, or remove the stray !{",
	"https://docs.aws.amazon.com/firehose/latest/dev/s3-prefixes.html") if {
	some [name, path, c] in _pf_fhlib_prefixed
	some key in {"Prefix", "ErrorOutputPrefix"}
	v := object.get(c, key, null)
	_pf_fhlib_lit(v)
	_pf_fhlib_stray(v)
}
