package cdk_preflight

import rego.v1

_pf_lemcr_fix := "Lower MaximumConcurrency to the function ReservedConcurrentExecutions, or raise the reservation"

_pf_lemcr_url := "https://docs.aws.amazon.com/lambda/latest/dg/services-sqs-scaling.html"

violation contains make_diag_full("pf-lambda-esm-max-concurrency-vs-reserved", "ERROR", name,
	"Properties.ScalingConfig.MaximumConcurrency",
	sprintf("MaximumConcurrency %v exceeds the %v reserved executions of function '%v'; the mapping can never reach that concurrency", [m, r, fn]),
	_pf_lemcr_fix, _pf_lemcr_url) if {
	some name in _pf_lam_esm
	m := to_number(object.get(_pf_lam_obj(_pf_lam_props(name), "ScalingConfig"), "MaximumConcurrency", 0))
	fn := resolve(name, "Properties.FunctionName")
	fn in resources_of_type("AWS::Lambda::Function")
	r := to_number(_pf_lam_get(fn, "ReservedConcurrentExecutions"))
	m > r
}
