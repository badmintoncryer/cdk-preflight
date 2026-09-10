package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-record-name-total-length", "ERROR", name,
	"Properties.Name",
	sprintf("The record name is %d characters; a DNS name may not exceed 255", [count(n)]),
	"Shorten the name to 255 characters or fewer",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/DomainNameFormat.html") if {
	some name in resources_of_type("AWS::Route53::RecordSet")
	rs := _pf_r53lib_props(name)
	n := _pf_r53lib_str(rs, "Name")
	count(n) > 255
}

violation contains make_diag_full("pf-route53-record-name-total-length", "ERROR", name,
	sprintf("Properties.RecordSets[%d].Name", [_pf_it.index]),
	sprintf("The record name is %d characters; a DNS name may not exceed 255", [count(n)]),
	"Shorten the name to 255 characters or fewer",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/DomainNameFormat.html") if {
	some name in resources_of_type("AWS::Route53::RecordSetGroup")
	some _pf_it in flatten_list(name, "Properties.RecordSets")
	rs := _pf_it.value
	is_object(rs)
	n := _pf_r53lib_str(rs, "Name")
	count(n) > 255
}
