package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-resourcerecord-value-length", "ERROR", name,
	"Properties.ResourceRecords",
	sprintf("A ResourceRecords value is %d characters; the limit is 4000", [count(v)]),
	"Split the value across several ResourceRecords entries",
	"https://docs.aws.amazon.com/general/latest/gr/r53.html") if {
	some name in resources_of_type("AWS::Route53::RecordSet")
	rs := _pf_r53lib_props(name)
	some v in _pf_r53lib_vals(rs)
	count(v) > 4000
}

violation contains make_diag_full("pf-route53-resourcerecord-value-length", "ERROR", name,
	sprintf("Properties.RecordSets[%d].ResourceRecords", [_pf_it.index]),
	sprintf("A ResourceRecords value is %d characters; the limit is 4000", [count(v)]),
	"Split the value across several ResourceRecords entries",
	"https://docs.aws.amazon.com/general/latest/gr/r53.html") if {
	some name in resources_of_type("AWS::Route53::RecordSetGroup")
	some _pf_it in flatten_list(name, "Properties.RecordSets")
	rs := _pf_it.value
	is_object(rs)
	some v in _pf_r53lib_vals(rs)
	count(v) > 4000
}
