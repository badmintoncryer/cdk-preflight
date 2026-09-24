package cdk_preflight

import rego.v1

# Cloud Map derives the address attributes from the EC2 instance, so anything else
# the caller supplies is a conflict rather than an addition.
violation contains make_diag_full("pf-servicediscovery-instance-ec2-id-exclusive", "ERROR", name,
	"Properties.InstanceAttributes",
	sprintf("AWS_EC2_INSTANCE_ID is registered together with %v; RegisterInstance fails with \"Invalid combination of attributes received. AWS_EC2_INSTANCE_ID is not supported with [%v].\"", [k, k]),
	"Register AWS_EC2_INSTANCE_ID on its own (AWS_INIT_HEALTH_STATUS is the only attribute it accepts); Cloud Map fills in the address from the EC2 instance",
	"https://docs.aws.amazon.com/cloud-map/latest/api/API_RegisterInstance.html") if {
	some name in resources_of_type("AWS::ServiceDiscovery::Instance")
	_pf_sd_has_attr(name, "AWS_EC2_INSTANCE_ID")
	some k, _ in _pf_sd_attrs(name)
	not upper(k) in {"AWS_EC2_INSTANCE_ID", "AWS_INIT_HEALTH_STATUS"}
}
