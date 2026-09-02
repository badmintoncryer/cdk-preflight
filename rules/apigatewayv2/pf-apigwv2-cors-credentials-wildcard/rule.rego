package cdk_preflight

import rego.v1

# The CORS spec forbids credentialed requests against a wildcard origin,
# and the API create enforces it.
violation contains make_diag_full("pf-apigwv2-cors-credentials-wildcard", "ERROR", name,
	sprintf("Properties.CorsConfiguration.AllowOrigins.%d", [o.index]),
	"CorsConfiguration sets AllowCredentials with a '*' origin; the API create fails with \"allow-credentials is not supported if 'allow-origin' is *\"",
	"List explicit origins, or drop AllowCredentials",
	"https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-cors.html") if {
	some name in resources_of_type("AWS::ApiGatewayV2::Api")
	coerce_to_bool(resolve(name, "Properties.CorsConfiguration.AllowCredentials")) == true
	some o in flatten_list(name, "Properties.CorsConfiguration.AllowOrigins")
	o.value == "*"
}
