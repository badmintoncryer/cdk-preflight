package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-alias-globalaccelerator-zone-id", "ERROR", name,
	"Properties.AliasTarget.HostedZoneId",
	sprintf("The alias targets a Global Accelerator, so AliasTarget.HostedZoneId must be Z2BJ6XQ5FK7U4H, not '%s'", [zid]),
	"Set AliasTarget.HostedZoneId to Z2BJ6XQ5FK7U4H (in the CDK, route53_targets.GlobalAcceleratorTarget does this)",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resource-record-sets-values-alias.html") if {
	some name in resources_of_type("AWS::Route53::RecordSet")
	rs := _pf_r53lib_props(name)
	dns := _pf_r53lib_alias_dns(rs)
	endswith(dns, ".awsglobalaccelerator.com")
	zid := _pf_r53lib_alias_zoneid(rs)
	zid != "Z2BJ6XQ5FK7U4H"
}

violation contains make_diag_full("pf-route53-alias-globalaccelerator-zone-id", "ERROR", name,
	sprintf("Properties.RecordSets[%d].AliasTarget.HostedZoneId", [_pf_it.index]),
	sprintf("The alias targets a Global Accelerator, so AliasTarget.HostedZoneId must be Z2BJ6XQ5FK7U4H, not '%s'", [zid]),
	"Set AliasTarget.HostedZoneId to Z2BJ6XQ5FK7U4H (in the CDK, route53_targets.GlobalAcceleratorTarget does this)",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resource-record-sets-values-alias.html") if {
	some name in resources_of_type("AWS::Route53::RecordSetGroup")
	some _pf_it in flatten_list(name, "Properties.RecordSets")
	rs := _pf_it.value
	is_object(rs)
	dns := _pf_r53lib_alias_dns(rs)
	endswith(dns, ".awsglobalaccelerator.com")
	zid := _pf_r53lib_alias_zoneid(rs)
	zid != "Z2BJ6XQ5FK7U4H"
}
