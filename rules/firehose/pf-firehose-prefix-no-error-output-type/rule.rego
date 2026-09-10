package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-firehose-prefix-no-error-output-type", "ERROR", name,
	sprintf("%s.Prefix", [path]),
	sprintf("Prefix '%s' interpolates !{firehose:error-output-type}, which only ErrorOutputPrefix may use; the stream create fails with \"Prefix must not contain any occurrence of !{firehose:error-output-type}\"", [p]),
	"Move !{firehose:error-output-type} to ErrorOutputPrefix",
	"https://docs.aws.amazon.com/firehose/latest/dev/s3-prefixes.html") if {
	some [name, path, c] in _pf_fhlib_prefixed
	p := object.get(c, "Prefix", null)
	_pf_fhlib_lit(p)
	contains(p, "!{firehose:error-output-type}")
}
