package cdk_preflight

import rego.v1

# Expressions expand at delivery time, so only a lower bound is knowable:
# every literal character survives and every expression yields at least one.
_pf_fhpl_min(s) := n if {
	stripped := regex.replace(s, `!\{[^{}]*\}`, "")
	n := count(stripped) + count(_pf_fhlib_exprs(s))
}

violation contains make_diag_full("pf-firehose-prefix-length", "ERROR", name,
	sprintf("%s.%s", [path, key]),
	sprintf("%s evaluates to at least %d characters; the stream create fails with \"Length of evaluated prefix cannot be greater than 512\"", [key, n]),
	"Shorten the prefix to 512 characters or fewer once evaluated",
	"https://docs.aws.amazon.com/firehose/latest/dev/s3-prefixes.html") if {
	some [name, path, c] in _pf_fhlib_prefixed
	some key in {"Prefix", "ErrorOutputPrefix"}
	v := object.get(c, key, null)
	_pf_fhlib_lit(v)
	n := _pf_fhpl_min(v)
	n > 512
}
