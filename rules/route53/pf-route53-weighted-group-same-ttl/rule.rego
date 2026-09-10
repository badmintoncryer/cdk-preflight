package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-weighted-group-same-ttl", "ERROR", name,
	sprintf("Properties.RecordSets[%d]", [b.index]),
	sprintf("The weighted record sets for '%s' have different TTLs (%v and %v); Route 53 requires one TTL across the group", [k, ta, tb]),
	"Give every weighted record set in the group the same TTL",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/routing-policy.html") if {
	some name in resources_of_type("AWS::Route53::RecordSetGroup")
	some a in flatten_list(name, "Properties.RecordSets")
	some b in flatten_list(name, "Properties.RecordSets")
	a.index < b.index
	k := _pf_r53lib_key(a.value)
	k == _pf_r53lib_key(b.value)
	"Weight" in _pf_r53lib_kinds(a.value)
	"Weight" in _pf_r53lib_kinds(b.value)
	ta := _pf_r53lib_get(a.value, "TTL")
	tb := _pf_r53lib_get(b.value, "TTL")
	to_number(ta) != to_number(tb)
}
