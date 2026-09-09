package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cognito-log-delivery-event-source-duplicate", "ERROR", name,
	sprintf("Properties.LogConfigurations.%d.EventSource", [b.index]),
	sprintf("event source '%v' has two log configurations; the log delivery call fails with \"Following event sources appear more then once in a request\"", [es]),
	"Merge the configurations that share an event source",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-logdeliveryconfiguration.html") if {
	some name in resources_of_type("AWS::Cognito::LogDeliveryConfiguration")
	some a in flatten_list(name, "Properties.LogConfigurations")
	some b in flatten_list(name, "Properties.LogConfigurations")
	a.index < b.index
	es := _pf_coglib_at(a.value, "EventSource")
	is_string(es)
	es == _pf_coglib_at(b.value, "EventSource")
}
