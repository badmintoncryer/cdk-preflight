package cdk_preflight

import rego.v1

_pf_slow_start_out(n) if n < 0

_pf_slow_start_out(n) if {
	n > 0
	n < 30
}

_pf_slow_start_out(n) if n > 900

violation contains make_diag_full("pf-elbv2-tg-slow-start-range", "ERROR", name,
	sprintf("Properties.TargetGroupAttributes.%d.Value", [item.index]),
	sprintf("slow_start.duration_seconds is %v but must be 0 (disabled) or between 30 and 900 seconds", [num]),
	"Set slow_start.duration_seconds to 0 or a value between 30 and 900",
	"https://docs.aws.amazon.com/elasticloadbalancing/latest/application/edit-target-group-attributes.html#slow-start-mode") if {
	some name in resources_of_type("AWS::ElasticLoadBalancingV2::TargetGroup")
	some item in flatten_list(name, "Properties.TargetGroupAttributes")
	attr := item.value
	is_object(attr)
	object.get(attr, "Key", "") == "slow_start.duration_seconds"
	num := to_number(object.get(attr, "Value", null))
	_pf_slow_start_out(num)
}
