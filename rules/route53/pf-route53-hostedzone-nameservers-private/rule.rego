package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-hostedzone-nameservers-private", "ERROR", name,
	"Properties.ResourceRecords",
	sprintf("the record reads NameServers off %s, which is a private hosted zone; only public zones expose delegation name servers", [z]),
	"Drop the NS record, or read NameServers off a public hosted zone",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/hosted-zone-private-considerations.html") if {
	some name in resources_of_type("AWS::Route53::RecordSet")
	rr := object.get(_pf_r53z_props(name), "ResourceRecords", null)
	z := _pf_r53z_getatt(rr, "NameServers")
	_pf_r53lib_private_zone(z)
}

violation contains make_diag_full("pf-route53-hostedzone-nameservers-private", "ERROR", name,
	sprintf("Properties.RecordSets[%d].ResourceRecords", [_pf_it.index]),
	sprintf("the record reads NameServers off %s, which is a private hosted zone; only public zones expose delegation name servers", [z]),
	"Drop the NS record, or read NameServers off a public hosted zone",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/hosted-zone-private-considerations.html") if {
	some name in resources_of_type("AWS::Route53::RecordSetGroup")
	some _pf_it in flatten_list(name, "Properties.RecordSets")
	is_object(_pf_it.value)
	rr := object.get(_pf_it.value, "ResourceRecords", null)
	z := _pf_r53z_getatt(rr, "NameServers")
	_pf_r53lib_private_zone(z)
}
