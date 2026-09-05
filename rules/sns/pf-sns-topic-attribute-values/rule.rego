package cdk_preflight

import rego.v1

_pf_snstav_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-sns-topic.html"

_pf_snstav_fix := "Shorten DisplayName to 100 characters; use SignatureVersion \"1\"/\"2\" and TracingConfig PassThrough/Active"

violation contains make_diag_full("pf-sns-topic-attribute-values", "ERROR", name,
	"Properties.DisplayName",
	sprintf("DisplayName is %d characters long (maximum 100); CreateTopic fails with \"Invalid parameter: Attributes Reason: DisplayName\"", [count(v)]),
	_pf_snstav_fix, _pf_snstav_url) if {
	some name in resources_of_type("AWS::SNS::Topic")
	v := resolve(name, "Properties.DisplayName")
	is_string(v)
	count(v) > 100
}

violation contains make_diag_full("pf-sns-topic-attribute-values", "ERROR", name,
	"Properties.SignatureVersion",
	sprintf("SignatureVersion '%v' is not 1 or 2; CreateTopic fails with \"Invalid parameter: Attributes Reason: SignatureVersion: Invalid value. Must be 1 or 2.\"", [v]),
	_pf_snstav_fix, _pf_snstav_url) if {
	some name in resources_of_type("AWS::SNS::Topic")
	v := resolve(name, "Properties.SignatureVersion")
	_pf_snstav_scalar(v)
	not sprintf("%v", [v]) in {"1", "2"}
}

_pf_snstav_scalar(v) if is_string(v)

_pf_snstav_scalar(v) if is_number(v)

violation contains make_diag_full("pf-sns-topic-attribute-values", "ERROR", name,
	"Properties.TracingConfig",
	sprintf("TracingConfig '%s' is not PassThrough or Active; CreateTopic fails with \"Invalid parameter: Attributes Reason: Invalid tracing config value: %s\"", [v, v]),
	_pf_snstav_fix, _pf_snstav_url) if {
	some name in resources_of_type("AWS::SNS::Topic")
	v := resolve(name, "Properties.TracingConfig")
	is_string(v)
	not v in {"PassThrough", "Active"}
}
