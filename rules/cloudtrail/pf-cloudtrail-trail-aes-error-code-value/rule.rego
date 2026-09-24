package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cloudtrail-trail-aes-error-code-value", "ERROR", name,
	"Properties.AdvancedEventSelectors.FieldSelectors",
	sprintf("errorCode '%v' is not a value CloudTrail filters on; VpceAccessDenied is the only valid errorCode", [v]),
	"Use VpceAccessDenied, or drop the errorCode field selector",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-cloudtrail-trail-advancedfieldselector.html") if {
	some name in resources_of_type("AWS::CloudTrail::Trail")
	some s in _pf_ctlib_aes(name)
	some fs in _pf_ctlib_fields_named(s, "errorCode")
	some v in _pf_ctlib_operator_values(fs, "Equals")
	v != "VpceAccessDenied"
}
