package cdk_preflight

import rego.v1

_pf_ec2nga_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-natgateway.html"

_pf_ec2nga_absent(name, key) if {
	props := input.resources[name].properties
	is_object(props)
	object.get(props, key, "__pf_absent") == "__pf_absent"
}

# ConnectivityType defaults to public; an unresolvable value skips both directions.
_pf_ec2nga_public(name) if _pf_ec2nga_absent(name, "ConnectivityType")

_pf_ec2nga_public(name) if resolve(name, "Properties.ConnectivityType") == "public"

violation contains make_diag_full("pf-ec2-natgw-allocation", "ERROR", name,
	"Properties.AllocationId",
	"A private NAT gateway cannot take AllocationId (\"AllocationId cannot be specified for a NAT Gateway with Connectivity Type private.\")",
	"Remove AllocationId, or switch ConnectivityType to public",
	_pf_ec2nga_url) if {
	some name in resources_of_type("AWS::EC2::NatGateway")
	resolve(name, "Properties.ConnectivityType") == "private"
	not _pf_ec2nga_absent(name, "AllocationId")
}

violation contains make_diag_full("pf-ec2-natgw-allocation", "ERROR", name,
	"Properties.AllocationId",
	"A public NAT gateway requires AllocationId (\"The request must include the AllocationId parameter.\")",
	"Allocate an EIP and pass its AllocationId, or set ConnectivityType: private",
	_pf_ec2nga_url) if {
	some name in resources_of_type("AWS::EC2::NatGateway")
	_pf_ec2nga_public(name)
	_pf_ec2nga_absent(name, "AllocationId")
}
