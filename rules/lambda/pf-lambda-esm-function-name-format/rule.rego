package cdk_preflight

import rego.v1

_pf_lefnf_fix := "Use a plain function name, a function ARN or a version/alias ARN"

_pf_lefnf_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-lambda-eventsourcemapping.html"

violation contains make_diag_full("pf-lambda-esm-function-name-format", "ERROR", name,
	"Properties.FunctionName",
	sprintf("FunctionName '%v' is none of the accepted forms (name, function ARN, partial ARN, version or alias ARN)", [fn]),
	_pf_lefnf_fix, _pf_lefnf_url) if {
	some name in _pf_lam_esm
	fn := resolve(name, "Properties.FunctionName")
	_pf_lam_lit(fn)
	not regex.match("^(arn:(aws[a-zA-Z-]*)?:lambda:)?([a-z]{2}(-gov)?-[a-z]+-\\d{1}:)?(\\d{12}:)?(function:)?([a-zA-Z0-9-_]+)(:(\\$LATEST|[a-zA-Z0-9-_]+))?$", fn)
}
