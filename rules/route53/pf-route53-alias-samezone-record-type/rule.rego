package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-alias-samezone-record-type", "ERROR", name,
	"Properties.Type",
	sprintf("A %s record set cannot carry an AliasTarget: \"aliases of that type are not supported\"", [t]),
	"Use a supported type (A, AAAA, CNAME, MX, TXT, ...) for the alias, or replace the alias with a plain record set",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resource-record-sets-values-alias.html") if {
	some name in resources_of_type("AWS::Route53::RecordSet")
	rs := _pf_r53lib_props(name)
	_pf_r53lib_alias_ownzone(rs)
	t := _pf_r53lib_type(rs)
	t in {"NS", "SOA"}
}

violation contains make_diag_full("pf-route53-alias-samezone-record-type", "ERROR", name,
	sprintf("Properties.RecordSets[%d].Type", [_pf_it.index]),
	sprintf("A %s record set cannot carry an AliasTarget: \"aliases of that type are not supported\"", [t]),
	"Use a supported type (A, AAAA, CNAME, MX, TXT, ...) for the alias, or replace the alias with a plain record set",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resource-record-sets-values-alias.html") if {
	some name in resources_of_type("AWS::Route53::RecordSetGroup")
	some _pf_it in flatten_list(name, "Properties.RecordSets")
	rs := _pf_it.value
	is_object(rs)
	_pf_r53lib_alias_ownzone(rs)
	t := _pf_r53lib_type(rs)
	t in {"NS", "SOA"}
}
