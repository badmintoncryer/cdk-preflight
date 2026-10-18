package cdk_preflight

import rego.v1

# CIDR resource configurations are reached through the gateway's VPC, so the
# gateway must resolve DNS IN_VPC; a gateway that leaves
# ResourceConfigDnsResolution out or sets PUBLIC is rejected ("CIDR type
# resource configurations require a resource gateway with IN_VPC DNS
# resolution"). Checked when the gateway is in the same template.
violation contains make_diag_full("pf-vpclattice-rc-cidr-gateway-public", "ERROR", name,
	"Properties.ResourceGatewayId",
	sprintf("Resource gateway '%s' does not resolve DNS IN_VPC; the CIDR resource configuration fails with \"CIDR type resource configurations require a resource gateway with IN_VPC DNS resolution\"", [g]),
	"Set ResourceConfigDnsResolution to IN_VPC on the resource gateway",
	"https://docs.aws.amazon.com/vpc-lattice/latest/ug/resource-gateway.html") if {
	some name in resources_of_type("AWS::VpcLattice::ResourceConfiguration")
	resolve(name, "Properties.ResourceConfigurationType") == "CIDR"
	g := resolve(name, "Properties.ResourceGatewayId")
	g in resources_of_type("AWS::VpcLattice::ResourceGateway")
	_pf_vpcl_str(g, "Properties.ResourceConfigDnsResolution", "PUBLIC") != "IN_VPC"
}
