package cdk_preflight

import rego.v1

_pf_cfgcpm_allowed := {"ConfigurationItemChangeNotification", "OversizedConfigurationItemChangeNotification"}
_pf_cfgcpm_err := "the rule create fails: a Guard policy rule is only triggered by configuration changes"

violation contains make_diag_full("pf-config-rule-custom-policy-message-type", "ERROR", name,
	"Properties.Source.SourceDetails",
	sprintf("Source.Owner is CUSTOM_POLICY with MessageType %v; %s", [mt, _pf_cfgcpm_err]),
	"Use ConfigurationItemChangeNotification or OversizedConfigurationItemChangeNotification",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-config-configrule-source.html") if {
	some name in resources_of_type("AWS::Config::ConfigRule")
	_pf_cfglib_owner(name) == "CUSTOM_POLICY"
	some d in _pf_cfglib_source_details(name)
	mt := object.get(d, "MessageType", null)
	is_string(mt)
	not mt in _pf_cfgcpm_allowed
}
