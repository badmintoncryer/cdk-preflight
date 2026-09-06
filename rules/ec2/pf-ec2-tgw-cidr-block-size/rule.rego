package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ec2-tgw-cidr-block-size", "ERROR", name,
	sprintf("Properties.TransitGatewayCidrBlocks.%d", [item.index]),
	sprintf("Transit gateway CIDR block '%s' has netmask /%v; the IPv4 block must be /24 or larger", [c, p]),
	"Widen the block to /24 or larger",
	"https://docs.aws.amazon.com/vpc/latest/tgw/tgw-transit-gateways.html") if {
	some name in resources_of_type("AWS::EC2::TransitGateway")
	some item in flatten_list(name, "Properties.TransitGatewayCidrBlocks")
	c := item.value
	is_string(c)
	regex.match(`^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$`, c)
	p := to_number(split(c, "/")[1])
	p > 24
}
