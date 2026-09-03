package cdk_preflight

import rego.v1

# The 11 target properties, straight from the EC2 error message.
_pf_ec2rte_targets := ["GatewayId", "LocalGatewayId", "CarrierGatewayId", "NatGatewayId", "NetworkInterfaceId", "VpcPeeringConnectionId", "EgressOnlyInternetGatewayId", "TransitGatewayId", "VpcEndpointId", "CoreNetworkArn", "InstanceId"]

_pf_ec2rte_count(name) := n if {
	props := input.resources[name].properties
	is_object(props)
	n := count([k | some k in _pf_ec2rte_targets; object.get(props, k, "__pf_absent") != "__pf_absent"])
}

violation contains make_diag_full("pf-ec2-route-target-exactly-one", "ERROR", name,
	"Properties",
	sprintf("The route names %v targets; EC2 requires exactly one of GatewayId, LocalGatewayId, CarrierGatewayId, NatGatewayId, NetworkInterfaceId, VpcPeeringConnectionId, EgressOnlyInternetGatewayId, TransitGatewayId, VpcEndpointId, CoreNetworkArn or InstanceId", [n]),
	"Set exactly one target property on the route",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-route.html") if {
	some name in resources_of_type("AWS::EC2::Route")
	n := _pf_ec2rte_count(name)
	n != 1
}
