package cdk_preflight

import rego.v1

# CreateStage accepts letters, digits, hyphens and underscores ("Stage names can only contain
# alphanumeric characters, hyphens, and underscores"), although its error text for a rejected
# name still lists only a-zA-Z0-9_. The real-deploy evidence covers a space; hyphenated stage
# names deploy (#411), so the rule must not reject them.
violation contains make_diag_full("pf-apigw-stage-name-charset", "ERROR", name,
	"Properties.StageName",
	sprintf("StageName '%s' has characters outside a-zA-Z0-9_-; the stage create fails with \"Stage name only allows a-zA-Z0-9_\"", [s]),
	"Use only letters, digits, hyphens and underscores in the stage name",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigateway-stage.html") if {
	some name in resources_of_type("AWS::ApiGateway::Stage")
	s := resolve(name, "Properties.StageName")
	is_string(s)
	not input.resources[s]
	not regex.match(`^[a-zA-Z0-9_-]+$`, s)
}
