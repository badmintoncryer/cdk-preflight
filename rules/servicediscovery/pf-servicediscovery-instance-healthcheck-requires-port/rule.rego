package cdk_preflight

import rego.v1

# Route 53 needs a port to send the health check to. ALIAS and EC2 instances are
# exempt: they cannot carry AWS_INSTANCE_* attributes at all.
violation contains make_diag_full("pf-servicediscovery-instance-healthcheck-requires-port", "ERROR", name,
	"Properties.InstanceAttributes.AWS_INSTANCE_PORT",
	sprintf("Service '%v' carries a HealthCheckConfig, but this instance has no AWS_INSTANCE_PORT; RegisterInstance fails with \"A port must be supplied in order to register this instance.\"", [svc]),
	"Add AWS_INSTANCE_PORT to InstanceAttributes, or drop HealthCheckConfig from the service",
	"https://docs.aws.amazon.com/cloud-map/latest/api/API_HealthCheckConfig.html") if {
	some name in resources_of_type("AWS::ServiceDiscovery::Instance")
	svc := _pf_sd_inst_svc(name)
	is_object(_pf_sd_healthcheck(svc))
	not _pf_sd_derived_instance(name)
	not _pf_sd_has_attr(name, "AWS_INSTANCE_PORT")
}
