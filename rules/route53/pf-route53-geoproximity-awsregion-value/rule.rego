package cdk_preflight

import rego.v1

# 実在する AWS リージョン（aws-cdk-lib の region-info、2026-09-10 時点）。
# 新設リージョンが aws-cdk-lib に入るまでの間だけ取りこぼす。
violation contains make_diag_full("pf-route53-geoproximity-awsregion-value", "ERROR", name,
	"Properties.GeoProximityLocation.AWSRegion",
	sprintf("'%s' is not an AWS Region; Route 53 rejects the record with \"Cannot find GeoProximityLocation with AWSRegion\"", [r]),
	"Use an existing Region name",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resource-record-sets-values-geoproximity.html") if {
	some name in resources_of_type("AWS::Route53::RecordSet")
	rs := _pf_r53lib_props(name)
	g := _pf_r53lib_get(rs, "GeoProximityLocation")
	is_object(g)
	r := object.get(g, "AWSRegion", null)
	is_string(r)
	not r in _pf_r53_regions
}

violation contains make_diag_full("pf-route53-geoproximity-awsregion-value", "ERROR", name,
	sprintf("Properties.RecordSets[%d].GeoProximityLocation.AWSRegion", [_pf_it.index]),
	sprintf("'%s' is not an AWS Region; Route 53 rejects the record with \"Cannot find GeoProximityLocation with AWSRegion\"", [r]),
	"Use an existing Region name",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resource-record-sets-values-geoproximity.html") if {
	some name in resources_of_type("AWS::Route53::RecordSetGroup")
	some _pf_it in flatten_list(name, "Properties.RecordSets")
	rs := _pf_it.value
	is_object(rs)
	g := _pf_r53lib_get(rs, "GeoProximityLocation")
	is_object(g)
	r := object.get(g, "AWSRegion", null)
	is_string(r)
	not r in _pf_r53_regions
}
