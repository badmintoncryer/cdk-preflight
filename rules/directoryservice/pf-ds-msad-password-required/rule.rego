package cdk_preflight

import rego.v1

# CFn リファレンスでは Password は Required: No だが、CreateMicrosoftAD API では Required: Yes。
# Fn::If で包まれていてもキーがあれば黙る（片側が NoValue でも鳴らさない、偽陰性側）。

violation contains make_diag_full("pf-ds-msad-password-required", "ERROR", name,
	"Properties.Password",
	"Password is not set; CreateMicrosoftAD requires the Admin password even though the CloudFormation schema marks it optional",
	"Set Password, for example from a Secrets Manager dynamic reference",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-directoryservice-microsoftad.html") if {
	some name in resources_of_type("AWS::DirectoryService::MicrosoftAD")
	p := input.resources[name].properties
	is_object(p)
	not "Password" in object.keys(p)
}
