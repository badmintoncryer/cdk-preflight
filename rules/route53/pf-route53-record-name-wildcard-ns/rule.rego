package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-record-name-wildcard-ns", "ERROR", name,
	"Properties.Name",
	"Route 53 refuses wildcard NS record sets: \"Changing wildcard NS record sets are not supported\"",
	"Delegate each subdomain with its own NS record set instead of a wildcard",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/DomainNameFormat.html") if {
	some name in resources_of_type("AWS::Route53::RecordSet")
	rs := _pf_r53lib_props(name)
	n := _pf_r53lib_str(rs, "Name")
	startswith(n, "*.")
	_pf_r53lib_type(rs) == "NS"
}

violation contains make_diag_full("pf-route53-record-name-wildcard-ns", "ERROR", name,
	sprintf("Properties.RecordSets[%d].Name", [_pf_it.index]),
	"Route 53 refuses wildcard NS record sets: \"Changing wildcard NS record sets are not supported\"",
	"Delegate each subdomain with its own NS record set instead of a wildcard",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/DomainNameFormat.html") if {
	some name in resources_of_type("AWS::Route53::RecordSetGroup")
	some _pf_it in flatten_list(name, "Properties.RecordSets")
	rs := _pf_it.value
	is_object(rs)
	n := _pf_r53lib_str(rs, "Name")
	startswith(n, "*.")
	_pf_r53lib_type(rs) == "NS"
}
