package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-record-name-punycode", "ERROR", name,
	"Properties.Name",
	sprintf("The record name '%s' contains a non-ASCII character; Route 53 rejects it with \"Value contains unsupported characters\"", [n]),
	"Convert the internationalized name to Punycode (xn--...) before putting it in the template",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/DomainNameFormat.html") if {
	some name in resources_of_type("AWS::Route53::RecordSet")
	rs := _pf_r53lib_props(name)
	n := _pf_r53lib_str(rs, "Name")
	regex.match("[^ -~]", n)
}

violation contains make_diag_full("pf-route53-record-name-punycode", "ERROR", name,
	sprintf("Properties.RecordSets[%d].Name", [_pf_it.index]),
	sprintf("The record name '%s' contains a non-ASCII character; Route 53 rejects it with \"Value contains unsupported characters\"", [n]),
	"Convert the internationalized name to Punycode (xn--...) before putting it in the template",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/DomainNameFormat.html") if {
	some name in resources_of_type("AWS::Route53::RecordSetGroup")
	some _pf_it in flatten_list(name, "Properties.RecordSets")
	rs := _pf_it.value
	is_object(rs)
	n := _pf_r53lib_str(rs, "Name")
	regex.match("[^ -~]", n)
}
