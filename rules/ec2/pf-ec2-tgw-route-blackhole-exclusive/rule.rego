package cdk_preflight

import rego.v1

_pf_ec2tgwbh_url := "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateTransitGatewayRoute.html"

violation contains make_diag_full("pf-ec2-tgw-route-blackhole-exclusive", "ERROR", name,
	"Properties.TransitGatewayAttachmentId",
	"A blackhole route also names TransitGatewayAttachmentId (\"The request must contain exactly one of Blackhole, or TransitGatewayAttachmentId\")",
	"Drop TransitGatewayAttachmentId from the blackhole route, or set Blackhole to false to route to the attachment",
	_pf_ec2tgwbh_url) if {
	some name in resources_of_type("AWS::EC2::TransitGatewayRoute")
	bh := resolve(name, "Properties.Blackhole")
	bh in [true, "true"]
	not _pf_ec2lib_absent(name, "TransitGatewayAttachmentId")
}
