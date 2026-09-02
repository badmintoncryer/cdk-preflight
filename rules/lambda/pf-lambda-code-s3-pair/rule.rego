package cdk_preflight

import rego.v1

# Half an S3 reference cannot be fetched. Only judged when neither ZipFile
# nor ImageUri is present (those shapes belong to the exclusive rule).
_pf_lcsp_code(name) := c if {
	props := input.resources[name].properties
	is_object(props)
	c := object.get(props, "Code", {})
	is_object(c)
}

_pf_lcsp_has(c, k) if object.get(c, k, "__pf_absent") != "__pf_absent"

_pf_lcsp_half(c) := ["S3Key", "S3Bucket"] if {
	_pf_lcsp_has(c, "S3Bucket")
	not _pf_lcsp_has(c, "S3Key")
}

_pf_lcsp_half(c) := ["S3Bucket", "S3Key"] if {
	_pf_lcsp_has(c, "S3Key")
	not _pf_lcsp_has(c, "S3Bucket")
}

violation contains make_diag_full("pf-lambda-code-s3-pair", "ERROR", name,
	sprintf("Properties.Code.%s", [missing[0]]),
	sprintf("Code has %s but no %s; the function create fails with \"S3 Bucket and Key are required for uploading with S3 parameters.\"", [missing[1], missing[0]]),
	"Set both S3Bucket and S3Key",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-lambda-function-code.html") if {
	some name in resources_of_type("AWS::Lambda::Function")
	c := _pf_lcsp_code(name)
	not _pf_lcsp_has(c, "ZipFile")
	not _pf_lcsp_has(c, "ImageUri")
	missing := _pf_lcsp_half(c)
}
