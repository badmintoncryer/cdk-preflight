package cdk_preflight

import rego.v1

_pf_ec2vtc_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-vpcendpoint.html"

_pf_ec2vtc_type(name) := t if {
	props := input.resources[name].properties
	is_object(props)
	t := object.get(props, "VpcEndpointType", "Gateway")
}

_pf_ec2vtc_has(name, key) if {
	props := input.resources[name].properties
	is_object(props)
	object.get(props, key, "__pf_absent") != "__pf_absent"
}

violation contains make_diag_full("pf-ec2-vpce-type-config", "ERROR", name,
	"Properties.SubnetIds",
	"A Gateway endpoint cannot take SubnetIds (\"Subnet IDs are only supported for Interface and GatewayLoadBalancer type VPC Endpoints.\")",
	"Remove SubnetIds, or set VpcEndpointType: Interface",
	_pf_ec2vtc_url) if {
	some name in resources_of_type("AWS::EC2::VPCEndpoint")
	_pf_ec2vtc_type(name) == "Gateway"
	_pf_ec2vtc_has(name, "SubnetIds")
}

violation contains make_diag_full("pf-ec2-vpce-type-config", "ERROR", name,
	"Properties.RouteTableIds",
	sprintf("A %s endpoint cannot take RouteTableIds; only Gateway endpoints attach to route tables", [t]),
	"Remove RouteTableIds, or set VpcEndpointType: Gateway",
	_pf_ec2vtc_url) if {
	some name in resources_of_type("AWS::EC2::VPCEndpoint")
	t := _pf_ec2vtc_type(name)
	t != "Gateway"
	is_string(t)
	_pf_ec2vtc_has(name, "RouteTableIds")
}
