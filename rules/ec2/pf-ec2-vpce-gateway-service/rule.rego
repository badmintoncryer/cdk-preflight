package cdk_preflight

import rego.v1

# VpcEndpointType defaults to Gateway (measured: a type-less endpoint
# fails with "Endpoint type (Gateway) ..." messages).
_pf_ec2vgs_gateway(name) if {
	props := input.resources[name].properties
	is_object(props)
	object.get(props, "VpcEndpointType", "Gateway") == "Gateway"
}

violation contains make_diag_full("pf-ec2-vpce-gateway-service", "ERROR", name,
	"Properties.ServiceName",
	sprintf("Only S3 and DynamoDB offer Gateway endpoints; \"%s\" fails with \"Endpoint type (Gateway) does not match available service types\"", [concat(".", parts)]),
	"Use com.amazonaws.<region>.s3 or .dynamodb, or switch VpcEndpointType to Interface",
	"https://docs.aws.amazon.com/vpc/latest/privatelink/gateway-endpoints.html") if {
	some name in resources_of_type("AWS::EC2::VPCEndpoint")
	_pf_ec2vgs_gateway(name)
	sn := resolve(name, "Properties.ServiceName")
	is_string(sn)
	parts := split(sn, ".")
	count(parts) == 4
	parts[0] == "com"
	parts[1] == "amazonaws"
	not parts[3] in {"s3", "dynamodb"}
}
