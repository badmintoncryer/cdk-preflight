package cdk_preflight

import rego.v1

# The record type the service publishes decides which attributes RegisterInstance
# demands. ALIAS and EC2 instances are exempt: Cloud Map derives the address for
# those, and the AWS_INSTANCE_* attributes are rejected alongside them.
violation contains make_diag_full("pf-servicediscovery-instance-cname-requires-cname-attr", "ERROR", name,
	"Properties.InstanceAttributes.AWS_INSTANCE_CNAME",
	sprintf("A CNAME record is published by service '%v', but this instance has no AWS_INSTANCE_CNAME; RegisterInstance fails with \"Required attribute(s) AWS_INSTANCE_CNAME are missing.\"", [svc]),
	"Add AWS_INSTANCE_CNAME to InstanceAttributes",
	"https://docs.aws.amazon.com/cloud-map/latest/api/API_RegisterInstance.html") if {
	some name in resources_of_type("AWS::ServiceDiscovery::Instance")
	svc := _pf_sd_inst_svc(name)
	"CNAME" in _pf_sd_record_types(svc)
	not _pf_sd_derived_instance(name)
	not _pf_sd_has_attr(name, "AWS_INSTANCE_CNAME")
}
