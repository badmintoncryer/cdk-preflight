package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-cidr-collection-id-format", "ERROR", name,
	"Properties.CidrRoutingConfig.CollectionId",
	sprintf("CollectionId '%s' is not a UUID", [v]),
	"Use the collection's id (Fn::GetAtt on AWS::Route53::CidrCollection returns it)",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/routing-policy.html") if {
	some name in resources_of_type("AWS::Route53::RecordSet")
	rs := _pf_r53lib_props(name)
	c := _pf_r53lib_get(rs, "CidrRoutingConfig")
	is_object(c)
	v := object.get(c, "CollectionId", null)
	is_string(v)
	not regex.match("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", v)
}

violation contains make_diag_full("pf-route53-cidr-collection-id-format", "ERROR", name,
	sprintf("Properties.RecordSets[%d].CidrRoutingConfig.CollectionId", [_pf_it.index]),
	sprintf("CollectionId '%s' is not a UUID", [v]),
	"Use the collection's id (Fn::GetAtt on AWS::Route53::CidrCollection returns it)",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/routing-policy.html") if {
	some name in resources_of_type("AWS::Route53::RecordSetGroup")
	some _pf_it in flatten_list(name, "Properties.RecordSets")
	rs := _pf_it.value
	is_object(rs)
	c := _pf_r53lib_get(rs, "CidrRoutingConfig")
	is_object(c)
	v := object.get(c, "CollectionId", null)
	is_string(v)
	not regex.match("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", v)
}
