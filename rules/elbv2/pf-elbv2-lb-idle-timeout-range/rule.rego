package cdk_preflight

import rego.v1

_pf_idle_timeout_out(n) if n < 1

_pf_idle_timeout_out(n) if n > 4000

_pf_non_alb(name) if {
	t := resolve(name, "Properties.Type")
	t != "application"
}

violation contains make_diag_full("pf-elbv2-lb-idle-timeout-range", "ERROR", name,
	sprintf("Properties.LoadBalancerAttributes.%d.Value", [item.index]),
	sprintf("idle_timeout.timeout_seconds is %v but must be between 1 and 4000 seconds", [num]),
	"Set idle_timeout.timeout_seconds to a value between 1 and 4000",
	"https://docs.aws.amazon.com/elasticloadbalancing/latest/application/application-load-balancers.html#connection-idle-timeout") if {
	some name in resources_of_type("AWS::ElasticLoadBalancingV2::LoadBalancer")
	not _pf_non_alb(name)
	some item in flatten_list(name, "Properties.LoadBalancerAttributes")
	attr := item.value
	is_object(attr)
	object.get(attr, "Key", "") == "idle_timeout.timeout_seconds"
	num := to_number(object.get(attr, "Value", null))
	_pf_idle_timeout_out(num)
}
