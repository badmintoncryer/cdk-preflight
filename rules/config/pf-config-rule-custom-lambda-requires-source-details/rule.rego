package cdk_preflight

import rego.v1

_pf_cfgcsd_err := "the rule create fails: nothing would ever trigger the rule"

violation contains make_diag_full("pf-config-rule-custom-lambda-requires-source-details", "ERROR", name,
	"Properties.Source.SourceDetails",
	sprintf("Source.Owner is %v without SourceDetails; %s", [owner, _pf_cfgcsd_err]),
	"Add Source.SourceDetails with the event source and message type that trigger the rule",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-config-configrule.html") if {
	some name in resources_of_type("AWS::Config::ConfigRule")
	owner := _pf_cfglib_owner(name)
	owner in {"CUSTOM_LAMBDA", "CUSTOM_POLICY"}
	not _pf_cfglib_present(_pf_cfglib_source(name), "SourceDetails")
}
