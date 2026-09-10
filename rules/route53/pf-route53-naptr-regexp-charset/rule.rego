package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-naptr-regexp-charset", "ERROR", name,
	"Properties.ResourceRecords",
	sprintf("The NAPTR value '%s' contains a character outside printable ASCII; Route 53 rejects it with \"Value contains unsupported characters\"", [v]),
	"Write such characters as a three-digit octal escape",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/ResourceRecordTypes.html") if {
	some name in resources_of_type("AWS::Route53::RecordSet")
	rs := _pf_r53lib_props(name)
	_pf_r53lib_type(rs) == "NAPTR"
	some v in _pf_r53lib_vals(rs)
	regex.match("[^ -~]", v)
}

violation contains make_diag_full("pf-route53-naptr-regexp-charset", "ERROR", name,
	sprintf("Properties.RecordSets[%d].ResourceRecords", [_pf_it.index]),
	sprintf("The NAPTR value '%s' contains a character outside printable ASCII; Route 53 rejects it with \"Value contains unsupported characters\"", [v]),
	"Write such characters as a three-digit octal escape",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/ResourceRecordTypes.html") if {
	some name in resources_of_type("AWS::Route53::RecordSetGroup")
	some _pf_it in flatten_list(name, "Properties.RecordSets")
	rs := _pf_it.value
	is_object(rs)
	_pf_r53lib_type(rs) == "NAPTR"
	some v in _pf_r53lib_vals(rs)
	regex.match("[^ -~]", v)
}
