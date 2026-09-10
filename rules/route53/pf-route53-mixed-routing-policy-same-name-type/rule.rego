package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-mixed-routing-policy-same-name-type", "ERROR", name,
	sprintf("Properties.RecordSets[%d]", [b.index]),
	sprintf("'%s' is served by two different routing policies (%v and %v); every record set sharing a name and type must use one policy", [k, ka, kb]),
	"Pick one routing policy for the whole group",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/routing-policy.html") if {
	some name in resources_of_type("AWS::Route53::RecordSetGroup")
	some a in flatten_list(name, "Properties.RecordSets")
	some b in flatten_list(name, "Properties.RecordSets")
	a.index < b.index
	k := _pf_r53lib_key(a.value)
	k == _pf_r53lib_key(b.value)
	ka := _pf_r53lib_kinds(a.value)
	kb := _pf_r53lib_kinds(b.value)
	count(ka) > 0
	count(kb) > 0
	ka != kb
}
