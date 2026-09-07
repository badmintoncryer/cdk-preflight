package cdk_preflight

import rego.v1

_pf_lpsr_fix := "Raise ReservedConcurrentExecutions or lower the provisioned concurrency"

_pf_lpsr_url := "https://docs.aws.amazon.com/lambda/latest/dg/provisioned-concurrency.html"

violation contains make_diag_full("pf-lambda-provisioned-sum-not-exceed-reserved", "ERROR", name,
	"Properties.ReservedConcurrentExecutions",
	sprintf("%v of provisioned concurrency against ReservedConcurrentExecutions %v; the allocations of every version and alias are drawn from the reserved pool", [total, reserved]),
	_pf_lpsr_fix, _pf_lpsr_url) if {
	some name in _pf_lam_fn
	reserved := object.get(_pf_lam_props(name), "ReservedConcurrentExecutions", "__pf_absent")
	is_number(reserved)
	total := sum([n | some [_, fnref, n] in _pf_lam_pc; _pf_lam_ref(fnref) == name])
	total > reserved
}
