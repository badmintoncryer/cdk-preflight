package cdk_preflight

import rego.v1

# 実在する AWS リージョン（aws-cdk-lib の region-info、2026-09-10 時点）。
# 新設リージョンが aws-cdk-lib に入るまでの間だけ取りこぼす。
_pf_r53_regions := {
	"af-south-1", "ap-east-1", "ap-east-2", "ap-northeast-1", "ap-northeast-2", "ap-northeast-3", "ap-south-1", "ap-south-2", "ap-southeast-1", "ap-southeast-2",
	"ap-southeast-3", "ap-southeast-4", "ap-southeast-5", "ap-southeast-6", "ap-southeast-7", "ca-central-1", "ca-west-1", "cn-north-1", "cn-northwest-1", "eu-central-1",
	"eu-central-2", "eu-isoe-west-1", "eu-north-1", "eu-south-1", "eu-south-2", "eu-west-1", "eu-west-2", "eu-west-3", "eusc-de-east-1", "il-central-1",
	"me-central-1", "me-south-1", "mx-central-1", "sa-east-1", "us-east-1", "us-east-2", "us-gov-east-1", "us-gov-west-1", "us-iso-east-1", "us-iso-west-1",
	"us-isob-east-1", "us-isob-west-1", "us-isof-east-1", "us-isof-south-1", "us-west-1", "us-west-2",
}

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
