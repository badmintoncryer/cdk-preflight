package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-failover-alias-evaluate-target-health", "ERROR", name,
	"Properties.AliasTarget.EvaluateTargetHealth",
	"A primary failover alias must evaluate the target's health, otherwise Route 53 has no way to fail over",
	"Set AliasTarget.EvaluateTargetHealth to true (or attach a HealthCheckId to a non-alias record)",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/routing-policy.html") if {
	some name in resources_of_type("AWS::Route53::RecordSet")
	rs := _pf_r53lib_props(name)
	_pf_r53lib_str(rs, "Failover") == "PRIMARY"
	a := _pf_r53lib_alias(rs)
	not _pf_r53lib_has(rs, "HealthCheckId")
	object.get(a, "EvaluateTargetHealth", false) != true
}

violation contains make_diag_full("pf-route53-failover-alias-evaluate-target-health", "ERROR", name,
	sprintf("Properties.RecordSets[%d].AliasTarget.EvaluateTargetHealth", [_pf_it.index]),
	"A primary failover alias must evaluate the target's health, otherwise Route 53 has no way to fail over",
	"Set AliasTarget.EvaluateTargetHealth to true (or attach a HealthCheckId to a non-alias record)",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/routing-policy.html") if {
	some name in resources_of_type("AWS::Route53::RecordSetGroup")
	some _pf_it in flatten_list(name, "Properties.RecordSets")
	rs := _pf_it.value
	is_object(rs)
	_pf_r53lib_str(rs, "Failover") == "PRIMARY"
	a := _pf_r53lib_alias(rs)
	not _pf_r53lib_has(rs, "HealthCheckId")
	object.get(a, "EvaluateTargetHealth", false) != true
}
