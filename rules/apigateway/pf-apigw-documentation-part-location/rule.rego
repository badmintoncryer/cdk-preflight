package cdk_preflight

import rego.v1

# Location.Type decides which of the other Location fields may appear; API is
# the measured case (it takes none of them).
_pf_apgdpl_set(name, key) if is_string(resolve(name, sprintf("Properties.Location.%s", [key])))

violation contains make_diag_full("pf-apigw-documentation-part-location", "ERROR", name,
	"Properties.Location",
	sprintf("Location.Type is API but Location.%s is also set; the documentation part create fails with \"[Location type: API cannot have path, method, statusCode or name defined.]\"", [key]),
	"Drop Path, Method, StatusCode and Name from an API-level documentation part, or use a Location.Type that takes them",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-apigateway-documentationpart-location.html") if {
	some name in resources_of_type("AWS::ApiGateway::DocumentationPart")
	resolve(name, "Properties.Location.Type") == "API"
	some key in ["Method", "StatusCode", "Name"]
	_pf_apgdpl_set(name, key)
}
