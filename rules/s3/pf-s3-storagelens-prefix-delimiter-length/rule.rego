package cdk_preflight

import rego.v1

_pf_s3slp_fix := "Use one character as the prefix delimiter"

_pf_s3slp_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-s3-storagelens-storagelensconfiguration.html"

violation contains make_diag_full("pf-s3-storagelens-prefix-delimiter-length", "ERROR", name,
	"Properties.StorageLensConfiguration.PrefixDelimiter",
	sprintf("PrefixDelimiter '%v' is %d characters; Storage Lens accepts a single character", [pd, count(pd)]),
	_pf_s3slp_fix, _pf_s3slp_url) if {
	some name in resources_of_type("AWS::S3::StorageLens")
	pd := _pf_s3lib_lit(resolve(name, "Properties.StorageLensConfiguration.PrefixDelimiter"))
	count(pd) > 1
}
