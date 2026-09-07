package cdk_preflight

import rego.v1

_pf_s3xloc_fix := "Use a zone id from the stack's own region (its ids all share the region prefix)"

_pf_s3xloc_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-s3express-directorybucket.html"

# data.cdk_preflight.deploy_region is injected only in enforce mode with a
# concrete region; the rule skips otherwise.
violation contains make_diag_full("pf-s3express-bucket-location-region", "ERROR", name, "Properties.LocationName",
	sprintf("LocationName '%v' belongs to another region; this stack deploys to '%v', whose zone ids start with '%v'", [loc, region, want]),
	_pf_s3xloc_fix, _pf_s3xloc_url) if {
	some name in resources_of_type("AWS::S3Express::DirectoryBucket")
	loc := _pf_s3xlib_lit(name, "Properties.LocationName")
	region := data.cdk_preflight.deploy_region
	is_string(region)
	want := _pf_s3xlib_zoneprefix(region)
	parts := split(loc, "-")
	count(parts) > 1
	parts[0] != want
}
