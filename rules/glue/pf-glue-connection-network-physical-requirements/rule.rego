package cdk_preflight

import rego.v1

# A NETWORK connection carries no connection parameters at all; the subnet and
# security groups in PhysicalConnectionRequirements are the whole definition.
violation contains make_diag_full("pf-glue-connection-network-physical-requirements", "ERROR", name,
	"Properties.ConnectionInput.PhysicalConnectionRequirements",
	"A NETWORK connection has no PhysicalConnectionRequirements; CreateConnection fails with \"PhysicalConnectionRequirements cannot be null\"",
	"Add PhysicalConnectionRequirements with SubnetId, SecurityGroupIdList and the subnet's AvailabilityZone",
	"https://docs.aws.amazon.com/glue/latest/dg/connection-properties.html") if {
	some name in resources_of_type("AWS::Glue::Connection")
	_pf_gluelib_connection_type(name) == "NETWORK"
	ci := _pf_gluelib_connection_input(name)
	object.get(ci, "PhysicalConnectionRequirements", "__pf_absent") == "__pf_absent"
}
