package cdk_preflight

import rego.v1

_pf_cfgsdf_err := "the rule create fails: a change-triggered notification has no evaluation period to set"

violation contains make_diag_full("pf-config-rule-source-detail-frequency-requires-scheduled", "ERROR", name,
	"Properties.Source.SourceDetails",
	sprintf("a SourceDetail sets MaximumExecutionFrequency with MessageType %v; %s", [mt, _pf_cfgsdf_err]),
	"Drop MaximumExecutionFrequency, or set that SourceDetail's MessageType to ScheduledNotification",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-config-configrule-sourcedetail.html") if {
	some name in resources_of_type("AWS::Config::ConfigRule")
	some d in _pf_cfglib_source_details(name)
	_pf_cfglib_present(d, "MaximumExecutionFrequency")
	mt := object.get(d, "MessageType", null)
	is_string(mt)
	mt != "ScheduledNotification"
}
