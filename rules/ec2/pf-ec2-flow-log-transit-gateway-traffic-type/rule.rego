package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ec2-flow-log-transit-gateway-traffic-type", "ERROR", name,
	"Properties.TrafficType",
	"A flow log on a Transit Gateway resource cannot take TrafficType; it always records all traffic",
	"Remove TrafficType, or point ResourceType at a VPC, Subnet or NetworkInterface",
	_pf_ec2fl_url) if {
	some name in resources_of_type("AWS::EC2::FlowLog")
	resolve(name, "Properties.ResourceType") in {"TransitGateway", "TransitGatewayAttachment"}
	not _pf_ec2fl_absent(name, "TrafficType")
}
