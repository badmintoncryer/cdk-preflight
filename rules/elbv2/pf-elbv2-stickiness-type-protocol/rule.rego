package cdk_preflight

import rego.v1

_pf_elbstp_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/application/sticky-sessions.html"

_pf_elbstp_attr(name, key) := v if {
	some item in flatten_list(name, "Properties.TargetGroupAttributes")
	entry := item.value
	is_object(entry)
	object.get(entry, "Key", "") == key
	v := object.get(entry, "Value", null)
	is_string(v)
}

# Only the two benched pairs are claimed.
_pf_elbstp_bad(name) := ["lb_cookie", "TCP"] if {
	resolve(name, "Properties.Protocol") == "TCP"
	_pf_elbstp_attr(name, "stickiness.type") == "lb_cookie"
}

_pf_elbstp_bad(name) := ["source_ip", "HTTP"] if {
	resolve(name, "Properties.Protocol") == "HTTP"
	_pf_elbstp_attr(name, "stickiness.type") == "source_ip"
}

violation contains make_diag_full("pf-elbv2-stickiness-type-protocol", "ERROR", name,
	"Properties.TargetGroupAttributes",
	sprintf("Stickiness type '%s' is not supported for target groups with the %s protocol", [pair[0], pair[1]]),
	"Use source_ip stickiness for TCP target groups and cookie stickiness for HTTP ones",
	_pf_elbstp_url) if {
	some name in resources_of_type("AWS::ElasticLoadBalancingV2::TargetGroup")
	pair := _pf_elbstp_bad(name)
}
