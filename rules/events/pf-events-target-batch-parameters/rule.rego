package cdk_preflight

import rego.v1

# BatchParameters has two numeric bounds the service states outright.
# Measured 2026-09-07, events:PutTargets, us-east-1: "Parameter
# ArrayProperties is not valid. Reason: Size must be in between 2 and 10000."
# and "Parameter RetryStrategy is not valid. Reason: Attempts must be in
# between 1 and 10."
_pf_evbp_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-batchparameters.html"

_pf_evbp_targets(name) := [t |
	some t in flatten_list(name, "Properties.Targets")
	is_object(t.value)
	is_object(object.get(t.value, "BatchParameters", null))
]

_pf_evbp_out_of_range(v, lo, hi) if v < lo

_pf_evbp_out_of_range(v, lo, hi) if v > hi

violation contains make_diag_full("pf-events-target-batch-parameters", "ERROR", name,
	sprintf("Properties.Targets.%d.BatchParameters.ArrayProperties.Size", [t.index]),
	sprintf("Array job size %v is outside 2-10000; PutTargets fails with \"Parameter ArrayProperties is not valid. Reason: Size must be in between 2 and 10000\"", [v]),
	"Use an array size between 2 and 10000",
	_pf_evbp_url) if {
	some name in resources_of_type("AWS::Events::Rule")
	some t in _pf_evbp_targets(name)
	ap := object.get(t.value.BatchParameters, "ArrayProperties", null)
	is_object(ap)
	v := to_number(object.get(ap, "Size", "__pf_absent"))
	_pf_evbp_out_of_range(v, 2, 10000)
}

violation contains make_diag_full("pf-events-target-batch-parameters", "ERROR", name,
	sprintf("Properties.Targets.%d.BatchParameters.RetryStrategy.Attempts", [t.index]),
	sprintf("Retry attempts %v is outside 1-10; PutTargets fails with \"Parameter RetryStrategy is not valid. Reason: Attempts must be in between 1 and 10\"", [v]),
	"Use between 1 and 10 attempts",
	_pf_evbp_url) if {
	some name in resources_of_type("AWS::Events::Rule")
	some t in _pf_evbp_targets(name)
	rs := object.get(t.value.BatchParameters, "RetryStrategy", null)
	is_object(rs)
	v := to_number(object.get(rs, "Attempts", "__pf_absent"))
	_pf_evbp_out_of_range(v, 1, 10)
}
