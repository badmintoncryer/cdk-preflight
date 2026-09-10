package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-cidr-same-collection-in-group", "ERROR", name,
	sprintf("Properties.RecordSets[%d]", [b.index]),
	sprintf("The IP-based record sets for '%s' reference two different CIDR collections (%s and %s)", [k, ca, cb]),
	"Point every record set in the group at the same CidrRoutingConfig.CollectionId",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/routing-policy.html") if {
	some name in resources_of_type("AWS::Route53::RecordSetGroup")
	some a in flatten_list(name, "Properties.RecordSets")
	some b in flatten_list(name, "Properties.RecordSets")
	a.index < b.index
	k := _pf_r53lib_key(a.value)
	k == _pf_r53lib_key(b.value)
	ca := object.get(_pf_r53lib_get(a.value, "CidrRoutingConfig"), "CollectionId", null)
	cb := object.get(_pf_r53lib_get(b.value, "CidrRoutingConfig"), "CollectionId", null)
	is_string(ca)
	is_string(cb)
	ca != cb
}
