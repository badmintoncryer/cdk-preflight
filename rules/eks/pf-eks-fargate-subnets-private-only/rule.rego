package cdk_preflight

import rego.v1

# EKS refuses a Fargate subnet that can reach an internet gateway. The visible
# proxy MapPublicIpOnLaunch is not the criterion - phase B was refused with a
# subnet that had it false (2026-09-24) - so the route table is what is read.
# Only an in-template association is readable; a subnet with none falls back to
# the VPC main route table, which carries no internet route, and the rule stays
# silent there.
_pf_eksfpsub_default(r) if resolve(r, "Properties.DestinationCidrBlock") == "0.0.0.0/0"

_pf_eksfpsub_default(r) if resolve(r, "Properties.DestinationIpv6CidrBlock") == "::/0"

_pf_eksfpsub_gateway(r) if {
	g := resolve(r, "Properties.GatewayId")
	g in resources_of_type("AWS::EC2::InternetGateway")
}

_pf_eksfpsub_gateway(r) if {
	g := resolve(r, "Properties.GatewayId")
	is_string(g)
	startswith(g, "igw-")
}

_pf_eksfpsub_public(sub) if {
	some a in resources_of_type("AWS::EC2::SubnetRouteTableAssociation")
	resolve(a, "Properties.SubnetId") == sub
	rt := resolve(a, "Properties.RouteTableId")
	some r in resources_of_type("AWS::EC2::Route")
	resolve(r, "Properties.RouteTableId") == rt
	_pf_eksfpsub_default(r)
	_pf_eksfpsub_gateway(r)
}

violation contains make_diag_full("pf-eks-fargate-subnets-private-only", "ERROR", name,
	sprintf("Properties.Subnets.%v", [s.index]),
	sprintf("subnet %v has a default route to an internet gateway (\"Subnet ... provided in Fargate Profile is not a private subnet\")", [sub]),
	"List only private subnets - no default route to an internet gateway - in Properties.Subnets",
	"https://docs.aws.amazon.com/eks/latest/userguide/fargate-profile.html") if {
	some name in resources_of_type("AWS::EKS::FargateProfile")
	some s in flatten_list(name, "Properties.Subnets")
	sub := object.get(s.value, "__ref", "__pf_absent")
	sub != "__pf_absent"
	_pf_eksfpsub_public(sub)
}
