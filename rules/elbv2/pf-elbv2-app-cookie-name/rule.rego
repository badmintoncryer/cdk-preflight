package cdk_preflight

import rego.v1

_pf_elbacn_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/application/sticky-sessions.html"

_pf_elbacn_attr(name, key) := v if {
	some item in flatten_list(name, "Properties.TargetGroupAttributes")
	entry := item.value
	is_object(entry)
	object.get(entry, "Key", "") == key
	v := object.get(entry, "Value", null)
	is_string(v)
}

_pf_elbacn_has(name, key) if _pf_elbacn_attr(name, key)

violation contains make_diag_full("pf-elbv2-app-cookie-name", "ERROR", name,
	"Properties.TargetGroupAttributes",
	"stickiness.type app_cookie has no stickiness.app_cookie.cookie_name (\"You must set an application cookie name to enable stickiness of type 'app_cookie'\")",
	"Add the stickiness.app_cookie.cookie_name attribute",
	_pf_elbacn_url) if {
	some name in resources_of_type("AWS::ElasticLoadBalancingV2::TargetGroup")
	_pf_elbacn_attr(name, "stickiness.enabled") == "true"
	_pf_elbacn_attr(name, "stickiness.type") == "app_cookie"
	not _pf_elbacn_has(name, "stickiness.app_cookie.cookie_name")
}
