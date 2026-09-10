package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-resourcerecords-max-400", "ERROR", name,
	"Properties.ResourceRecords",
	sprintf("The record set has %d values; Route 53 allows at most 400 per RRSet", [count(_pf_r53lib_rrs(rs))]),
	"Split the values across several record sets",
	"https://docs.aws.amazon.com/general/latest/gr/r53.html") if {
	some name in resources_of_type("AWS::Route53::RecordSet")
	rs := _pf_r53lib_props(name)
	count(_pf_r53lib_rrs(rs)) > 400
}

violation contains make_diag_full("pf-route53-resourcerecords-max-400", "ERROR", name,
	sprintf("Properties.RecordSets[%d].ResourceRecords", [_pf_it.index]),
	sprintf("The record set has %d values; Route 53 allows at most 400 per RRSet", [count(_pf_r53lib_rrs(rs))]),
	"Split the values across several record sets",
	"https://docs.aws.amazon.com/general/latest/gr/r53.html") if {
	some name in resources_of_type("AWS::Route53::RecordSetGroup")
	some _pf_it in flatten_list(name, "Properties.RecordSets")
	rs := _pf_it.value
	is_object(rs)
	count(_pf_r53lib_rrs(rs)) > 400
}
