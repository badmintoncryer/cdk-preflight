package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-apigw-stage-name-charset", "ERROR", name,
	"Properties.StageName",
	sprintf("StageName '%s' has characters outside a-zA-Z0-9_; the stage create fails with \"Stage name only allows a-zA-Z0-9_\"", [s]),
	"Use only letters, digits and underscores in the stage name",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigateway-stage.html") if {
	some name in resources_of_type("AWS::ApiGateway::Stage")
	s := resolve(name, "Properties.StageName")
	is_string(s)
	not input.resources[s]
	not regex.match(`^[a-zA-Z0-9_]+$`, s)
}
