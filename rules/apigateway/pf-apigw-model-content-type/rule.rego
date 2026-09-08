package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-apigw-model-content-type", "ERROR", name,
	"Properties.ContentType",
	sprintf("ContentType '%s' is not a media type; the model create fails with \"Invalid content type specified: %s\"", [ct, ct]),
	"Use a media type such as application/json",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigateway-model.html") if {
	some name in resources_of_type("AWS::ApiGateway::Model")
	ct := resolve(name, "Properties.ContentType")
	is_string(ct)
	not input.resources[ct]
	not regex.match(`^[a-zA-Z0-9.+-]+/[a-zA-Z0-9.+-]+$`, ct)
}
