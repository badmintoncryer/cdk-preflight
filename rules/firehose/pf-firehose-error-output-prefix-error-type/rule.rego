package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-firehose-error-output-prefix-error-type", "ERROR", name,
	sprintf("%s.ErrorOutputPrefix", [path]),
	sprintf("ErrorOutputPrefix '%s' uses expressions but never interpolates !{firehose:error-output-type}; the stream create fails with \"ErrorOutputPrefix must contain at least one occurrence of !{firehose:error-output-type}\"", [e]),
	"Add !{firehose:error-output-type} to the ErrorOutputPrefix",
	"https://docs.aws.amazon.com/firehose/latest/dev/s3-prefixes.html") if {
	some [name, path, c] in _pf_fhlib_prefixed
	e := object.get(c, "ErrorOutputPrefix", null)
	_pf_fhlib_lit(e)
	count(_pf_fhlib_exprs(e)) > 0
	not contains(e, "!{firehose:error-output-type}")
}
