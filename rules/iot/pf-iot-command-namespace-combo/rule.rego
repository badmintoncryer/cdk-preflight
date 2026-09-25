package cdk_preflight

import rego.v1

_pf_iotcmd_awsiot(name) if _pf_iotlib_lit(name, "Properties.Namespace") == "AWS-IoT"

violation contains make_diag_full("pf-iot-command-namespace-combo", "ERROR", name,
	"Properties.Payload",
	"a command in the AWS-IoT namespace has no Payload; CreateCommand answers \"ValidationException: The 'payload' field of the command is required when using the 'AWS-IoT' namespace.\"",
	"Add a Payload with Content and ContentType",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-iot-command.html") if {
	some name in resources_of_type("AWS::IoT::Command")
	_pf_iotcmd_awsiot(name)
	not _pf_iotlib_has(name, "Payload")
}

violation contains make_diag_full("pf-iot-command-namespace-combo", "ERROR", name,
	"Properties.MandatoryParameters",
	"a command in the AWS-IoT namespace cannot declare MandatoryParameters; CreateCommand answers \"ValidationException: AWS-IoT namespace does not support 'mandatoryParameters' with 'payload' option.\"",
	"Drop MandatoryParameters and put the values in the Payload",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-iot-command.html") if {
	some name in resources_of_type("AWS::IoT::Command")
	_pf_iotcmd_awsiot(name)
	_pf_iotlib_has(name, "MandatoryParameters")
}
