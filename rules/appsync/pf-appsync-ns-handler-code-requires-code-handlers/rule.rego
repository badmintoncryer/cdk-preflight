package cdk_preflight

import rego.v1

_pf_nshandlercoderequirescodehandlers_absent(n, k) if {
	props := input.resources[n].properties
	is_object(props)
	object.get(props, k, "__pf_absent") == "__pf_absent"
}

violation contains make_diag_full("pf-appsync-ns-handler-code-requires-code-handlers", "ERROR", name,
	"Properties.CodeHandlers",
	sprintf("HandlerConfigs.%s.Behavior is CODE but neither CodeHandlers nor CodeS3Location is set; the namespace create has no handler code to run", [k]),
	"Set CodeHandlers (or CodeS3Location), or use Behavior: DIRECT",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-appsync-channelnamespace.html") if {
	some name in resources_of_type("AWS::AppSync::ChannelNamespace")
	hc := resolve(name, "Properties.HandlerConfigs")
	is_object(hc)
	some k, h in hc
	h.Behavior == "CODE"
	_pf_nshandlercoderequirescodehandlers_absent(name, "CodeHandlers")
	_pf_nshandlercoderequirescodehandlers_absent(name, "CodeS3Location")
}
