package cdk_preflight

import rego.v1

_pf_ec2sigw_vpc(n) := v if {
	v := resolve(n, "Properties.VpcId")
	is_string(v)
	not _pf_ec2lib_absent(n, "InternetGatewayId")
}

_pf_ec2sigw_peers(v) := {n |
	some n in resources_of_type("AWS::EC2::VPCGatewayAttachment")
	_pf_ec2sigw_vpc(n) == v
}

violation contains make_diag_full("pf-ec2-vpc-single-igw", "ERROR", name,
	"Properties.InternetGatewayId",
	sprintf("VPC '%s' already takes an internet gateway from '%s'; a second attachment fails with \"already has an internet gateway attached\"", [v, min(peers)]),
	"Attach one internet gateway per VPC, and route the rest through a different gateway type",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-vpcgatewayattachment.html") if {
	some name in resources_of_type("AWS::EC2::VPCGatewayAttachment")
	v := _pf_ec2sigw_vpc(name)
	peers := _pf_ec2sigw_peers(v)
	count(peers) > 1
	name != min(peers)
}
