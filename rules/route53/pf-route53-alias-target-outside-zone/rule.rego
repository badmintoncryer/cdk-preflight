package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-alias-target-outside-zone", "ERROR", name,
	"Properties.AliasTarget.DNSName",
	sprintf("AliasTarget.HostedZoneId points at the hosted zone '%s' created here, but the target name '%s' does not lie within it", [zn, dns]),
	"Target a name inside the zone, or set AliasTarget.HostedZoneId to the zone that actually hosts the target",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resource-record-sets-values-alias.html") if {
	some name in resources_of_type("AWS::Route53::RecordSet")
	rs := _pf_r53lib_props(name)
	z := _pf_r53lib_alias_ownzone(rs)
	zn := _pf_r53lib_zone_name(z)
	dns := _pf_r53lib_alias_dns(rs)
	not _pf_r53lib_within(dns, zn)
}

violation contains make_diag_full("pf-route53-alias-target-outside-zone", "ERROR", name,
	sprintf("Properties.RecordSets[%d].AliasTarget.DNSName", [_pf_it.index]),
	sprintf("AliasTarget.HostedZoneId points at the hosted zone '%s' created here, but the target name '%s' does not lie within it", [zn, dns]),
	"Target a name inside the zone, or set AliasTarget.HostedZoneId to the zone that actually hosts the target",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resource-record-sets-values-alias.html") if {
	some name in resources_of_type("AWS::Route53::RecordSetGroup")
	some _pf_it in flatten_list(name, "Properties.RecordSets")
	rs := _pf_it.value
	is_object(rs)
	z := _pf_r53lib_alias_ownzone(rs)
	zn := _pf_r53lib_zone_name(z)
	dns := _pf_r53lib_alias_dns(rs)
	not _pf_r53lib_within(dns, zn)
}
