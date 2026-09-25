package cdk_preflight

import rego.v1

# The provisioning template body is a JSON document inside a CloudFormation
# string property; nothing between the CDK and the service looks inside it.
violation contains make_diag_full("pf-iot-provisioningtemplate-body-json", "ERROR", name,
	"Properties.TemplateBody",
	"TemplateBody is not parseable JSON; CreateProvisioningTemplate answers \"The template body is invalid\"",
	"Render the provisioning template body as JSON (JSON.stringify the document rather than hand-writing it)",
	"https://docs.aws.amazon.com/iot/latest/developerguide/provision-template.html") if {
	some name in resources_of_type("AWS::IoT::ProvisioningTemplate")
	raw := _pf_iotlib_lit(name, "Properties.TemplateBody")
	not json.is_valid(raw)
}
