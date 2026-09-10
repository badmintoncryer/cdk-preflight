package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-caa-tag-enum", "ERROR", name,
	"Properties.ResourceRecords",
	sprintf("The CAA tag '%s' is not one of issue / issuewild / iodef; Route 53 rejects it with \"Only issue/issuewild/iodef is allowed\"", [f[1]]),
	"Use issue, issuewild or iodef (a private tag needs flags 128, which Route 53 does not accept either)",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/ResourceRecordTypes.html") if {
	some name in resources_of_type("AWS::Route53::RecordSet")
	rs := _pf_r53lib_props(name)
	_pf_r53lib_type(rs) == "CAA"
	some v in _pf_r53lib_vals(rs)
	f := _pf_r53lib_fields(v)
	count(f) >= 3
	not f[1] in {"issue", "issuewild", "iodef"}
}

violation contains make_diag_full("pf-route53-caa-tag-enum", "ERROR", name,
	sprintf("Properties.RecordSets[%d].ResourceRecords", [_pf_it.index]),
	sprintf("The CAA tag '%s' is not one of issue / issuewild / iodef; Route 53 rejects it with \"Only issue/issuewild/iodef is allowed\"", [f[1]]),
	"Use issue, issuewild or iodef (a private tag needs flags 128, which Route 53 does not accept either)",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/ResourceRecordTypes.html") if {
	some name in resources_of_type("AWS::Route53::RecordSetGroup")
	some _pf_it in flatten_list(name, "Properties.RecordSets")
	rs := _pf_it.value
	is_object(rs)
	_pf_r53lib_type(rs) == "CAA"
	some v in _pf_r53lib_vals(rs)
	f := _pf_r53lib_fields(v)
	count(f) >= 3
	not f[1] in {"issue", "issuewild", "iodef"}
}
