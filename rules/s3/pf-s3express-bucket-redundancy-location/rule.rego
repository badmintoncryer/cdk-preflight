package cdk_preflight

import rego.v1

_pf_s3xred_fix := "Pair DataRedundancy SingleAvailabilityZone with an Availability Zone id, and SingleLocalZone with a Local Zone id"

_pf_s3xred_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-s3express-directorybucket.html"

violation contains make_diag_full("pf-s3express-bucket-redundancy-location", "ERROR", name, "Properties.DataRedundancy",
	sprintf("DataRedundancy is 'SingleAvailabilityZone' but LocationName '%v' is a Local Zone id; use SingleLocalZone", [loc]),
	_pf_s3xred_fix, _pf_s3xred_url) if {
	some name in resources_of_type("AWS::S3Express::DirectoryBucket")
	resolve(name, "Properties.DataRedundancy") == "SingleAvailabilityZone"
	loc := _pf_s3xlib_lit(name, "Properties.LocationName")
	regex.match("^[a-z0-9]+-[a-z0-9]+-az[0-9]+$", loc)
}

violation contains make_diag_full("pf-s3express-bucket-redundancy-location", "ERROR", name, "Properties.DataRedundancy",
	sprintf("DataRedundancy is 'SingleLocalZone' but LocationName '%v' is an Availability Zone id; use SingleAvailabilityZone", [loc]),
	_pf_s3xred_fix, _pf_s3xred_url) if {
	some name in resources_of_type("AWS::S3Express::DirectoryBucket")
	resolve(name, "Properties.DataRedundancy") == "SingleLocalZone"
	loc := _pf_s3xlib_lit(name, "Properties.LocationName")
	regex.match("^[a-z0-9]+-az[0-9]+$", loc)
}
