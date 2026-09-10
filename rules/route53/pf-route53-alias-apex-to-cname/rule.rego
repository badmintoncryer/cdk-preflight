package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-alias-apex-to-cname", "ERROR", name,
	"Properties.AliasTarget.DNSName",
	sprintf("The apex alias targets '%s', which this template creates as a CNAME; an alias at the apex cannot resolve through a CNAME", [dns]),
	"Point the apex alias at an A/AAAA record (or at the AWS resource directly) instead of at a CNAME",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resource-record-sets-values-alias.html") if {
	some name in resources_of_type("AWS::Route53::RecordSet")
	rs := _pf_r53lib_props(name)
	z := _pf_r53lib_alias_ownzone(rs)
	zn := _pf_r53lib_zone_name(z)
	_pf_r53lib_name(rs) == zn
	dns := _pf_r53lib_alias_dns(rs)
	sprintf("%s|CNAME", [dns]) in _pf_r53lib_keys
}

violation contains make_diag_full("pf-route53-alias-apex-to-cname", "ERROR", name,
	sprintf("Properties.RecordSets[%d].AliasTarget.DNSName", [_pf_it.index]),
	sprintf("The apex alias targets '%s', which this template creates as a CNAME; an alias at the apex cannot resolve through a CNAME", [dns]),
	"Point the apex alias at an A/AAAA record (or at the AWS resource directly) instead of at a CNAME",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resource-record-sets-values-alias.html") if {
	some name in resources_of_type("AWS::Route53::RecordSetGroup")
	some _pf_it in flatten_list(name, "Properties.RecordSets")
	rs := _pf_it.value
	is_object(rs)
	z := _pf_r53lib_alias_ownzone(rs)
	zn := _pf_r53lib_zone_name(z)
	_pf_r53lib_name(rs) == zn
	dns := _pf_r53lib_alias_dns(rs)
	sprintf("%s|CNAME", [dns]) in _pf_r53lib_keys
}
