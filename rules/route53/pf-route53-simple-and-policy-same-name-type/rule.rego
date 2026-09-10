package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-simple-and-policy-same-name-type", "ERROR", name,
	sprintf("Properties.RecordSets[%d]", [b.index]),
	sprintf("'%s' has both a simple record set and one with a routing policy; Route 53 keeps the two shapes apart", [k]),
	"Give every record set for this name and type a routing policy, or keep only the simple one",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/routing-policy.html") if {
	some name in resources_of_type("AWS::Route53::RecordSetGroup")
	some a in flatten_list(name, "Properties.RecordSets")
	some b in flatten_list(name, "Properties.RecordSets")
	a.index != b.index
	k := _pf_r53lib_key(a.value)
	k == _pf_r53lib_key(b.value)
	count(_pf_r53lib_kinds(a.value)) == 0
	count(_pf_r53lib_kinds(b.value)) > 0
}
