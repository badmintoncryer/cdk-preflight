package cdk_preflight

import rego.v1

# An SRV record carries a host and a port; the host comes from one of the two IP
# attributes. ALIAS and EC2 instances are exempt (Cloud Map derives the address).
violation contains make_diag_full("pf-servicediscovery-instance-srv-requires-ip", "ERROR", name,
	"Properties.InstanceAttributes",
	sprintf("An SRV record is published by service '%v', but this instance has neither AWS_INSTANCE_IPV4 nor AWS_INSTANCE_IPV6; RegisterInstance fails with \"At least one of AWS_INSTANCE_IPV4 AWS_INSTANCE_IPV6 is required.\"", [svc]),
	"Add AWS_INSTANCE_IPV4 or AWS_INSTANCE_IPV6 to InstanceAttributes",
	"https://docs.aws.amazon.com/cloud-map/latest/api/API_RegisterInstance.html") if {
	some name in resources_of_type("AWS::ServiceDiscovery::Instance")
	svc := _pf_sd_inst_svc(name)
	"SRV" in _pf_sd_record_types(svc)
	not _pf_sd_derived_instance(name)
	not _pf_sd_has_attr(name, "AWS_INSTANCE_IPV4")
	not _pf_sd_has_attr(name, "AWS_INSTANCE_IPV6")
}
