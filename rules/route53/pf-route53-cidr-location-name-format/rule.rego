package cdk_preflight

import rego.v1

_pf_r53_cln_msg := "LocationName %s must be 1-16 characters of [0-9A-Za-z_-]"

_pf_r53_cln_fix := "Rename the CIDR location to match that pattern"

_pf_r53_cln_url := "https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/routing-policy.html"

_pf_r53_cln_bad(v) if {
	not regex.match("^[0-9A-Za-z_*-]{1,16}$", v)
}

violation contains make_diag_full("pf-route53-cidr-location-name-format", "ERROR", name,
	"Properties.CidrRoutingConfig.LocationName",
	sprintf("LocationName %s must be 1-16 characters of [0-9A-Za-z_-] (or the default location '*')", [v]),
	_pf_r53_cln_fix, _pf_r53_cln_url) if {
	some name in resources_of_type("AWS::Route53::RecordSet")
	rs := _pf_r53lib_props(name)
	c := _pf_r53lib_get(rs, "CidrRoutingConfig")
	is_object(c)
	v := object.get(c, "LocationName", null)
	is_string(v)
	_pf_r53_cln_bad(v)
}

violation contains make_diag_full("pf-route53-cidr-location-name-format", "ERROR", name,
	sprintf("Properties.RecordSets[%d].CidrRoutingConfig.LocationName", [_pf_it.index]),
	sprintf("LocationName %s must be 1-16 characters of [0-9A-Za-z_-] (or the default location '*')", [v]),
	_pf_r53_cln_fix, _pf_r53_cln_url) if {
	some name in resources_of_type("AWS::Route53::RecordSetGroup")
	some _pf_it in flatten_list(name, "Properties.RecordSets")
	rs := _pf_it.value
	is_object(rs)
	c := _pf_r53lib_get(rs, "CidrRoutingConfig")
	is_object(c)
	v := object.get(c, "LocationName", null)
	is_string(v)
	_pf_r53_cln_bad(v)
}

# コレクション側のロケーション名も同じパターン。ただし '*' は予約名なので
# ここでは通し、pf-route53-cidrcollection-locationname-wildcard が受け持つ。
violation contains make_diag_full("pf-route53-cidr-location-name-format", "ERROR", name,
	sprintf("Properties.Locations[%d].LocationName", [_pf_it.index]),
	sprintf(_pf_r53_cln_msg, [v]),
	_pf_r53_cln_fix, _pf_r53_cln_url) if {
	some name in resources_of_type("AWS::Route53::CidrCollection")
	some _pf_it in flatten_list(name, "Properties.Locations")
	is_object(_pf_it.value)
	v := object.get(_pf_it.value, "LocationName", null)
	is_string(v)
	v != "*"
	_pf_r53_cln_bad(v)
}
