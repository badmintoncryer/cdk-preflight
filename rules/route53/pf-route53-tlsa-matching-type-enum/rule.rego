package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-tlsa-matching-type-enum", "ERROR", name,
	"Properties.ResourceRecords",
	sprintf("The TLSA matching type must be 0 (exact), 1 (SHA-256) or 2 (SHA-512), got %v", [n]),
	"Use 0, 1 or 2",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/ResourceRecordTypes.html") if {
	some name in resources_of_type("AWS::Route53::RecordSet")
	rs := _pf_r53lib_props(name)
	_pf_r53lib_type(rs) == "TLSA"
	some v in _pf_r53lib_vals(rs)
	f := _pf_r53lib_fields(v)
	count(f) == 4
	n := to_number(f[2])
	not n in {0, 1, 2}
}

violation contains make_diag_full("pf-route53-tlsa-matching-type-enum", "ERROR", name,
	sprintf("Properties.RecordSets[%d].ResourceRecords", [_pf_it.index]),
	sprintf("The TLSA matching type must be 0 (exact), 1 (SHA-256) or 2 (SHA-512), got %v", [n]),
	"Use 0, 1 or 2",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/ResourceRecordTypes.html") if {
	some name in resources_of_type("AWS::Route53::RecordSetGroup")
	some _pf_it in flatten_list(name, "Properties.RecordSets")
	rs := _pf_it.value
	is_object(rs)
	_pf_r53lib_type(rs) == "TLSA"
	some v in _pf_r53lib_vals(rs)
	f := _pf_r53lib_fields(v)
	count(f) == 4
	n := to_number(f[2])
	not n in {0, 1, 2}
}
