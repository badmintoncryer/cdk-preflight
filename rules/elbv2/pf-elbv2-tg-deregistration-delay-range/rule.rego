package cdk_preflight

import rego.v1

_pf_dereg_delay_out(n) if n < 0

_pf_dereg_delay_out(n) if n > 3600

violation contains make_diag_full("pf-elbv2-tg-deregistration-delay-range", "ERROR", name,
	sprintf("Properties.TargetGroupAttributes.%d.Value", [item.index]),
	sprintf("deregistration_delay.timeout_seconds is %v but must be between 0 and 3600 seconds", [num]),
	"Set deregistration_delay.timeout_seconds to a value between 0 and 3600",
	"https://docs.aws.amazon.com/elasticloadbalancing/latest/application/edit-target-group-attributes.html#deregistration-delay") if {
	some name in resources_of_type("AWS::ElasticLoadBalancingV2::TargetGroup")
	some item in flatten_list(name, "Properties.TargetGroupAttributes")
	attr := item.value
	is_object(attr)
	object.get(attr, "Key", "") == "deregistration_delay.timeout_seconds"
	num := to_number(object.get(attr, "Value", null))
	_pf_dereg_delay_out(num)
}
