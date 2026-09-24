package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-iot-topicruledestination-https", "ERROR", name,
	"Properties.HttpUrlProperties.ConfirmationUrl",
	sprintf("ConfirmationUrl '%s' is not an HTTPS URL; CreateTopicRuleDestination answers \"Invalid confirmationUrl: '%s' is not a valid HTTPS URL\"", [u, u]),
	"Use an https:// URL for the confirmation endpoint",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-iot-topicruledestination.html") if {
	some name in resources_of_type("AWS::IoT::TopicRuleDestination")
	u := _pf_iotlib_lit(name, "Properties.HttpUrlProperties.ConfirmationUrl")
	not startswith(lower(u), "https://")
}
