package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-cname-name-collision", "ERROR", name,
	sprintf("Properties.RecordSets[%d]", [b.index]),
	sprintf("The template creates both a CNAME and a %s record set named '%s'; a CNAME must be the only record at its name", [tb, n]),
	"Rename one of the two, or drop the CNAME and use the other type alone",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/ResourceRecordTypes.html") if {
	some name in resources_of_type("AWS::Route53::RecordSetGroup")
	some a in flatten_list(name, "Properties.RecordSets")
	some b in flatten_list(name, "Properties.RecordSets")
	a.index != b.index
	n := _pf_r53lib_name(a.value)
	n == _pf_r53lib_name(b.value)
	_pf_r53lib_type(a.value) == "CNAME"
	tb := _pf_r53lib_type(b.value)
	tb != "CNAME"
}
