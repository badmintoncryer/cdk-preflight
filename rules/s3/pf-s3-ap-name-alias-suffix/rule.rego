package cdk_preflight

import rego.v1

_pf_s3apa_fix := "Drop the -s3alias or -ext-s3alias suffix from the access point name"

_pf_s3apa_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-s3-accesspoint.html"

violation contains make_diag_full("pf-s3-ap-name-alias-suffix", "ERROR", name, "Properties.Name",
	sprintf("access point name '%v' ends with the reserved suffix '%v'", [n, s]),
	_pf_s3apa_fix, _pf_s3apa_url) if {
	some name in resources_of_type("AWS::S3::AccessPoint")
	n := _pf_s3lib_lit(resolve(name, "Properties.Name"))
	some s in {"-s3alias", "-ext-s3alias"}
	endswith(n, s)
}
