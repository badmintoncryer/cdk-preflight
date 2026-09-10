package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-svcb-svcpriority-range", "ERROR", name,
	"Properties.ResourceRecords",
	sprintf("The SVCB SvcPriority must be between 0 and 32767, got %v", [n]),
	"Use a priority in 0-32767 (0 selects AliasMode)",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/ResourceRecordTypes.html") if {
	some name in resources_of_type("AWS::Route53::RecordSet")
	rs := _pf_r53lib_props(name)
	_pf_r53lib_type(rs) == "SVCB"
	some v in _pf_r53lib_vals(rs)
	f := _pf_r53lib_fields(v)
	count(f) >= 2
	n := to_number(f[0])
	n > 32767
}

violation contains make_diag_full("pf-route53-svcb-svcpriority-range", "ERROR", name,
	sprintf("Properties.RecordSets[%d].ResourceRecords", [_pf_it.index]),
	sprintf("The SVCB SvcPriority must be between 0 and 32767, got %v", [n]),
	"Use a priority in 0-32767 (0 selects AliasMode)",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/ResourceRecordTypes.html") if {
	some name in resources_of_type("AWS::Route53::RecordSetGroup")
	some _pf_it in flatten_list(name, "Properties.RecordSets")
	rs := _pf_it.value
	is_object(rs)
	_pf_r53lib_type(rs) == "SVCB"
	some v in _pf_r53lib_vals(rs)
	f := _pf_r53lib_fields(v)
	count(f) >= 2
	n := to_number(f[0])
	n > 32767
}
