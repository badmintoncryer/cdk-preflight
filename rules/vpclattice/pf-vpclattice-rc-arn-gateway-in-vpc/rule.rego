package cdk_preflight

import rego.v1

# An ARN resource is resolved through public DNS, so CreateResourceConfiguration
# rejects an ARN type on a resource gateway whose ResourceConfigDnsResolution is
# IN_VPC ("IN_VPC resolution is not supported for ARN type resource
# configurations"). Checked when the gateway is in the same template.
violation contains make_diag_full("pf-vpclattice-rc-arn-gateway-in-vpc", "ERROR", name,
	"Properties.ResourceGatewayId",
	sprintf("Resource gateway '%s' resolves DNS IN_VPC; the ARN resource configuration fails with \"IN_VPC resolution is not supported for ARN type resource configurations\"", [g]),
	"Use a resource gateway without ResourceConfigDnsResolution IN_VPC for ARN resource configurations",
	"https://docs.aws.amazon.com/vpc-lattice/latest/ug/resource-gateway.html") if {
	some name in resources_of_type("AWS::VpcLattice::ResourceConfiguration")
	resolve(name, "Properties.ResourceConfigurationType") == "ARN"
	g := resolve(name, "Properties.ResourceGatewayId")
	g in resources_of_type("AWS::VpcLattice::ResourceGateway")
	resolve(g, "Properties.ResourceConfigDnsResolution") == "IN_VPC"
}
