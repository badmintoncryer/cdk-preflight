package cdk_preflight

import rego.v1

_pf_s3xapn_fix := "Name the access point <base>--<availability-zone-id>--xa-s3, e.g. myap--use1-az4--xa-s3"

_pf_s3xapn_url := "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-points-directory-buckets-restrictions-limitations-naming-rules.html"

violation contains make_diag_full("pf-s3express-ap-name-suffix", "ERROR", name, "Properties.Name",
	sprintf("access point name '%v' does not end with --<availability-zone-id>--xa-s3; CreateAccessPoint rejects it", [n]),
	_pf_s3xapn_fix, _pf_s3xapn_url) if {
	some name in resources_of_type("AWS::S3Express::AccessPoint")
	n := _pf_s3xlib_lit(name, "Properties.Name")
	not regex.match("--[a-z0-9-]+--xa-s3$", n)
}
