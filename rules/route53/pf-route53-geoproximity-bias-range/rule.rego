package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-geoproximity-bias-range", "ERROR", name,
	"Properties.GeoProximityLocation.Bias",
	sprintf("Bias must be between -99 and 99, got %v", [n]),
	"Use a bias in -99..99",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resource-record-sets-values-geoproximity.html") if {
	some name in resources_of_type("AWS::Route53::RecordSet")
	rs := _pf_r53lib_props(name)
	g := _pf_r53lib_get(rs, "GeoProximityLocation")
	is_object(g)
	n := to_number(object.get(g, "Bias", null))
	abs(n) > 99
}

violation contains make_diag_full("pf-route53-geoproximity-bias-range", "ERROR", name,
	sprintf("Properties.RecordSets[%d].GeoProximityLocation.Bias", [_pf_it.index]),
	sprintf("Bias must be between -99 and 99, got %v", [n]),
	"Use a bias in -99..99",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resource-record-sets-values-geoproximity.html") if {
	some name in resources_of_type("AWS::Route53::RecordSetGroup")
	some _pf_it in flatten_list(name, "Properties.RecordSets")
	rs := _pf_it.value
	is_object(rs)
	g := _pf_r53lib_get(rs, "GeoProximityLocation")
	is_object(g)
	n := to_number(object.get(g, "Bias", null))
	abs(n) > 99
}
