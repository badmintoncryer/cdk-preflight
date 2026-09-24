package cdk_preflight

import rego.v1

_pf_cfgcpd_err := "the rule create fails: the policy text is what a CUSTOM_POLICY rule evaluates"

violation contains make_diag_full("pf-config-rule-custom-policy-requires-details", "ERROR", name,
	"Properties.Source.CustomPolicyDetails",
	sprintf("Source.Owner is CUSTOM_POLICY without CustomPolicyDetails; %s", [_pf_cfgcpd_err]),
	"Add Source.CustomPolicyDetails with the Guard runtime and policy text",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-config-configrule-source.html") if {
	some name in resources_of_type("AWS::Config::ConfigRule")
	_pf_cfglib_owner(name) == "CUSTOM_POLICY"
	not _pf_cfglib_present(_pf_cfglib_source(name), "CustomPolicyDetails")
}
