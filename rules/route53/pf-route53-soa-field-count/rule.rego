package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-soa-field-count", "ERROR", name,
	"Properties.ResourceRecords",
	sprintf("An SOA value must have 7 space-separated fields, got %d in '%s'", [count(f), v]),
	"Use: <primary name server> <hostmaster> <serial> <refresh> <retry> <expire> <minimum>",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/ResourceRecordTypes.html") if {
	some name in resources_of_type("AWS::Route53::RecordSet")
	rs := _pf_r53lib_props(name)
	_pf_r53lib_type(rs) == "SOA"
	some v in _pf_r53lib_vals(rs)
	f := _pf_r53lib_fields(v)
	count(f) != 7
}

violation contains make_diag_full("pf-route53-soa-field-count", "ERROR", name,
	sprintf("Properties.RecordSets[%d].ResourceRecords", [_pf_it.index]),
	sprintf("An SOA value must have 7 space-separated fields, got %d in '%s'", [count(f), v]),
	"Use: <primary name server> <hostmaster> <serial> <refresh> <retry> <expire> <minimum>",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/ResourceRecordTypes.html") if {
	some name in resources_of_type("AWS::Route53::RecordSetGroup")
	some _pf_it in flatten_list(name, "Properties.RecordSets")
	rs := _pf_it.value
	is_object(rs)
	_pf_r53lib_type(rs) == "SOA"
	some v in _pf_r53lib_vals(rs)
	f := _pf_r53lib_fields(v)
	count(f) != 7
}
