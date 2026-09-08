package cdk_preflight

import rego.v1

_pf_agvsnc_ok(s) if s == "$default"

_pf_agvsnc_ok(s) if regex.match(`^[a-zA-Z0-9_]+$`, s)

violation contains make_diag_full("pf-apigwv2-stage-name-charset", "ERROR", name,
	"Properties.StageName",
	sprintf("StageName '%s' has characters outside a-zA-Z0-9_; the stage create fails with \"Stage name only allows a-zA-Z0-9_\"", [s]),
	"Use only letters, digits and underscores (or the special name $default)",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigatewayv2-stage.html") if {
	some name in resources_of_type("AWS::ApiGatewayV2::Stage")
	s := resolve(name, "Properties.StageName")
	is_string(s)
	not input.resources[s]
	not _pf_agvsnc_ok(s)
}
