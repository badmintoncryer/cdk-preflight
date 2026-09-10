package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-latency-one-record-per-region", "ERROR", name,
	sprintf("Properties.RecordSets[%d]", [b.index]),
	sprintf("Two latency record sets for '%s' both target the Region %s; Route 53 allows one per Region", [k, r]),
	"Keep one record set per Region, or switch to weighted routing",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/routing-policy.html") if {
	some name in resources_of_type("AWS::Route53::RecordSetGroup")
	some a in flatten_list(name, "Properties.RecordSets")
	some b in flatten_list(name, "Properties.RecordSets")
	a.index < b.index
	k := _pf_r53lib_key(a.value)
	k == _pf_r53lib_key(b.value)
	r := _pf_r53lib_str(a.value, "Region")
	r == _pf_r53lib_str(b.value, "Region")
}
