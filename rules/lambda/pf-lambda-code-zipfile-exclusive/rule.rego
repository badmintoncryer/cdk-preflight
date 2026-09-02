package cdk_preflight

import rego.v1

# Key presence in the Code object is the violation; checked against the
# preprocessed document (see AGENTS.md).
_pf_lczx_other := {"S3Bucket", "S3Key", "S3ObjectVersion", "ImageUri"}

_pf_lczx_code(name) := c if {
	props := input.resources[name].properties
	is_object(props)
	c := object.get(props, "Code", {})
	is_object(c)
}

violation contains make_diag_full("pf-lambda-code-zipfile-exclusive", "ERROR", name,
	sprintf("Properties.Code.%s", [k]),
	sprintf("Code sets ZipFile together with %s; the function create fails with \"Please do not provide other FunctionCode parameters when providing a ZipFile.\"", [k]),
	"Keep the inline ZipFile alone, or switch entirely to the S3/image reference",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-lambda-function-code.html") if {
	some name in resources_of_type("AWS::Lambda::Function")
	c := _pf_lczx_code(name)
	object.get(c, "ZipFile", "__pf_absent") != "__pf_absent"
	some k in _pf_lczx_other
	object.get(c, k, "__pf_absent") != "__pf_absent"
}
