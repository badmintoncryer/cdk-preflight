package cdk_preflight

import rego.v1

_pf_lpps_fix := "Split the statements across fewer, broader permissions"

_pf_lpps_url := "https://docs.aws.amazon.com/lambda/latest/dg/gettingstarted-limits.html"

violation contains make_diag_full("pf-lambda-perm-policy-size", "ERROR", name,
	"Properties.SourceArn",
	sprintf("about %v characters of source ARNs across the permissions on this function; they all land in one resource policy, which fails with PolicyLengthExceededException past 20 KB", [total]),
	_pf_lpps_fix, _pf_lpps_url) if {
	some name in _pf_lam_perm
	target := resolve(name, "Properties.FunctionName")
	total := sum([n |
		some p in _pf_lam_perm
		resolve(p, "Properties.FunctionName") == target
		v := resolve(p, "Properties.SourceArn")
		is_string(v)
		n := count(v)
	])
	total >= 20480
}
