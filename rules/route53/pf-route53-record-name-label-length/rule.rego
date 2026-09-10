package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-record-name-label-length", "ERROR", name,
	"Properties.Name",
	sprintf("The label '%s' is %d characters; a DNS label may not exceed 63", [l, count(l)]),
	"Shorten the label to 63 characters or fewer",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/DomainNameFormat.html") if {
	some name in resources_of_type("AWS::Route53::RecordSet")
	rs := _pf_r53lib_props(name)
	n := _pf_r53lib_str(rs, "Name")
	some l in split(n, ".")
	count(l) > 63
}

violation contains make_diag_full("pf-route53-record-name-label-length", "ERROR", name,
	sprintf("Properties.RecordSets[%d].Name", [_pf_it.index]),
	sprintf("The label '%s' is %d characters; a DNS label may not exceed 63", [l, count(l)]),
	"Shorten the label to 63 characters or fewer",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/DomainNameFormat.html") if {
	some name in resources_of_type("AWS::Route53::RecordSetGroup")
	some _pf_it in flatten_list(name, "Properties.RecordSets")
	rs := _pf_it.value
	is_object(rs)
	n := _pf_r53lib_str(rs, "Name")
	some l in split(n, ".")
	count(l) > 63
}
