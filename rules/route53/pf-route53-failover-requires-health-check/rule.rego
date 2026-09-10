package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-failover-requires-health-check", "ERROR", name,
	"Properties.HealthCheckId",
	"A non-alias primary failover record set must reference a health check; Route 53 rejects it with \"A non-alias primary ResourceRecordSet must have an associated health check\"",
	"Add HealthCheckId, or make the primary record an alias with EvaluateTargetHealth: true",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/routing-policy.html") if {
	some name in resources_of_type("AWS::Route53::RecordSet")
	rs := _pf_r53lib_props(name)
	_pf_r53lib_str(rs, "Failover") == "PRIMARY"
	not _pf_r53lib_has(rs, "AliasTarget")
	not _pf_r53lib_has(rs, "HealthCheckId")
}

violation contains make_diag_full("pf-route53-failover-requires-health-check", "ERROR", name,
	sprintf("Properties.RecordSets[%d].HealthCheckId", [_pf_it.index]),
	"A non-alias primary failover record set must reference a health check; Route 53 rejects it with \"A non-alias primary ResourceRecordSet must have an associated health check\"",
	"Add HealthCheckId, or make the primary record an alias with EvaluateTargetHealth: true",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/routing-policy.html") if {
	some name in resources_of_type("AWS::Route53::RecordSetGroup")
	some _pf_it in flatten_list(name, "Properties.RecordSets")
	rs := _pf_it.value
	is_object(rs)
	_pf_r53lib_str(rs, "Failover") == "PRIMARY"
	not _pf_r53lib_has(rs, "AliasTarget")
	not _pf_r53lib_has(rs, "HealthCheckId")
}
