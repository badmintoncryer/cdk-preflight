package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-naptr-service-quotes", "ERROR", name,
	"Properties.ResourceRecords",
	sprintf("The NAPTR service field %s must be enclosed in double quotes", [f[3]]),
	"Write the service as \"E2U+sip\" (with the quotes)",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/ResourceRecordTypes.html") if {
	some name in resources_of_type("AWS::Route53::RecordSet")
	rs := _pf_r53lib_props(name)
	_pf_r53lib_type(rs) == "NAPTR"
	some v in _pf_r53lib_vals(rs)
	f := _pf_r53lib_fields(v)
	count(f) == 6
	not _pf_r53lib_quoted(f[3])
}

violation contains make_diag_full("pf-route53-naptr-service-quotes", "ERROR", name,
	sprintf("Properties.RecordSets[%d].ResourceRecords", [_pf_it.index]),
	sprintf("The NAPTR service field %s must be enclosed in double quotes", [f[3]]),
	"Write the service as \"E2U+sip\" (with the quotes)",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/ResourceRecordTypes.html") if {
	some name in resources_of_type("AWS::Route53::RecordSetGroup")
	some _pf_it in flatten_list(name, "Properties.RecordSets")
	rs := _pf_it.value
	is_object(rs)
	_pf_r53lib_type(rs) == "NAPTR"
	some v in _pf_r53lib_vals(rs)
	f := _pf_r53lib_fields(v)
	count(f) == 6
	not _pf_r53lib_quoted(f[3])
}
