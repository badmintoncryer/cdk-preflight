package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-cidr-location-name-format", "ERROR", name,
	"Properties.CidrRoutingConfig.LocationName",
	sprintf("LocationName '%s' must be 1-16 characters of [0-9A-Za-z_-] (or the default location '*')", [v]),
	"Rename the CIDR location to match that pattern",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/routing-policy.html") if {
	some name in resources_of_type("AWS::Route53::RecordSet")
	rs := _pf_r53lib_props(name)
	c := _pf_r53lib_get(rs, "CidrRoutingConfig")
	is_object(c)
	v := object.get(c, "LocationName", null)
	is_string(v)
	not regex.match("^[0-9A-Za-z_*-]{1,16}$", v)
}

violation contains make_diag_full("pf-route53-cidr-location-name-format", "ERROR", name,
	sprintf("Properties.RecordSets[%d].CidrRoutingConfig.LocationName", [_pf_it.index]),
	sprintf("LocationName '%s' must be 1-16 characters of [0-9A-Za-z_-] (or the default location '*')", [v]),
	"Rename the CIDR location to match that pattern",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/routing-policy.html") if {
	some name in resources_of_type("AWS::Route53::RecordSetGroup")
	some _pf_it in flatten_list(name, "Properties.RecordSets")
	rs := _pf_it.value
	is_object(rs)
	c := _pf_r53lib_get(rs, "CidrRoutingConfig")
	is_object(c)
	v := object.get(c, "LocationName", null)
	is_string(v)
	not regex.match("^[0-9A-Za-z_*-]{1,16}$", v)
}
