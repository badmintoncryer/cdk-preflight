package cdk_preflight

import rego.v1

_pf_fherop_set(c) if {
	e := object.get(c, "ErrorOutputPrefix", "")
	is_string(e)
	count(e) > 0
}

# An intrinsic is unknowable here, so treat it as set and stay quiet.
_pf_fherop_set(c) if is_object(object.get(c, "ErrorOutputPrefix", ""))

violation contains make_diag_full("pf-firehose-error-output-prefix-required", "ERROR", name,
	sprintf("%s.ErrorOutputPrefix", [path]),
	sprintf("Prefix '%s' contains expressions but ErrorOutputPrefix is not set; the stream create fails with \"ErrorOutputPrefix cannot be null or empty when Prefix contains expressions\"", [p]),
	"Add an ErrorOutputPrefix containing !{firehose:error-output-type}",
	"https://docs.aws.amazon.com/firehose/latest/dev/s3-prefixes.html") if {
	some [name, path, c] in _pf_fhlib_prefixed
	p := object.get(c, "Prefix", null)
	_pf_fhlib_lit(p)
	count(_pf_fhlib_exprs(p)) > 0
	not _pf_fherop_set(c)
}
