package cdk_preflight

import rego.v1

_pf_apgveip_private(name) if {
	some t in flatten_list(name, "Properties.EndpointConfiguration.Types")
	t.value == "PRIVATE"
}

violation contains make_diag_full("pf-apigw-vpc-endpoint-ids-private-only", "ERROR", name,
	"Properties.EndpointConfiguration.VpcEndpointIds",
	"VpcEndpointIds is set on an API whose endpoint type is not PRIVATE; the API create fails with \"VPCEndpoints can only be specified with PRIVATE apis.\"",
	"Set EndpointConfiguration.Types to [PRIVATE], or drop VpcEndpointIds",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-apigateway-restapi-endpointconfiguration.html") if {
	some name in resources_of_type("AWS::ApiGateway::RestApi")
	count(flatten_list(name, "Properties.EndpointConfiguration.VpcEndpointIds")) > 0
	not _pf_apgveip_private(name)
}
