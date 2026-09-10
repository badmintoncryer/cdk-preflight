package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-srv-field-count", "ERROR", name,
	"Properties.ResourceRecords",
	sprintf("An SRV value must have 4 space-separated fields, got %d in '%s'", [count(f), v]),
	"Use: <priority> <weight> <port> <target domain name>",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/ResourceRecordTypes.html") if {
	some name in resources_of_type("AWS::Route53::RecordSet")
	rs := _pf_r53lib_props(name)
	_pf_r53lib_type(rs) == "SRV"
	some v in _pf_r53lib_vals(rs)
	f := _pf_r53lib_fields(v)
	count(f) != 4
}

violation contains make_diag_full("pf-route53-srv-field-count", "ERROR", name,
	sprintf("Properties.RecordSets[%d].ResourceRecords", [_pf_it.index]),
	sprintf("An SRV value must have 4 space-separated fields, got %d in '%s'", [count(f), v]),
	"Use: <priority> <weight> <port> <target domain name>",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/ResourceRecordTypes.html") if {
	some name in resources_of_type("AWS::Route53::RecordSetGroup")
	some _pf_it in flatten_list(name, "Properties.RecordSets")
	rs := _pf_it.value
	is_object(rs)
	_pf_r53lib_type(rs) == "SRV"
	some v in _pf_r53lib_vals(rs)
	f := _pf_r53lib_fields(v)
	count(f) != 4
}
