package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-apigwv2-domain-endpoint-type-regional", "ERROR", name,
	"Properties.DomainNameConfigurations",
	"DomainNameConfigurations asks for an EDGE endpoint; the domain name create fails with \"EDGE endpoint type is not supported for APIGatewayV2 domainName\"",
	"Use EndpointType: REGIONAL (HTTP and WebSocket custom domains are regional only)",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-apigatewayv2-domainname-domainnameconfiguration.html") if {
	some name in resources_of_type("AWS::ApiGatewayV2::DomainName")
	some item in flatten_list(name, "Properties.DomainNameConfigurations")
	c := item.value
	is_object(c)
	c.EndpointType == "EDGE"
}
