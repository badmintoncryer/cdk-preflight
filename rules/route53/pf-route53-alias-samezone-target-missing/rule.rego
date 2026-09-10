package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-alias-samezone-target-missing", "ERROR", name,
	"Properties.AliasTarget.DNSName",
	sprintf("The alias targets '%s' in the hosted zone '%s' that this template creates, but no record set with that name is created; the new zone holds only its own NS and SOA records", [dns, zn]),
	"Add the target record set to the template (and order it before the alias), or point the alias at a zone that already holds the target",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resource-record-sets-values-alias.html") if {
	some name in resources_of_type("AWS::Route53::RecordSet")
	rs := _pf_r53lib_props(name)
	z := _pf_r53lib_alias_ownzone(rs)
	zn := _pf_r53lib_zone_name(z)
	dns := _pf_r53lib_alias_dns(rs)
	_pf_r53lib_within(dns, zn)
	dns != zn
	not dns in _pf_r53lib_names
}

violation contains make_diag_full("pf-route53-alias-samezone-target-missing", "ERROR", name,
	sprintf("Properties.RecordSets[%d].AliasTarget.DNSName", [_pf_it.index]),
	sprintf("The alias targets '%s' in the hosted zone '%s' that this template creates, but no record set with that name is created; the new zone holds only its own NS and SOA records", [dns, zn]),
	"Add the target record set to the template (and order it before the alias), or point the alias at a zone that already holds the target",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resource-record-sets-values-alias.html") if {
	some name in resources_of_type("AWS::Route53::RecordSetGroup")
	some _pf_it in flatten_list(name, "Properties.RecordSets")
	rs := _pf_it.value
	is_object(rs)
	z := _pf_r53lib_alias_ownzone(rs)
	zn := _pf_r53lib_zone_name(z)
	dns := _pf_r53lib_alias_dns(rs)
	_pf_r53lib_within(dns, zn)
	dns != zn
	not dns in _pf_r53lib_names
}
