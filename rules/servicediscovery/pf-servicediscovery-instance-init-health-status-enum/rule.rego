package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-servicediscovery-instance-init-health-status-enum", "ERROR", name,
	"Properties.InstanceAttributes.AWS_INIT_HEALTH_STATUS",
	sprintf("AWS_INIT_HEALTH_STATUS is %v; RegisterInstance fails with \"No enum constant com.amazon.route53.autonaming.model.InitHealthStatus.%v\"", [v, v]),
	"Set AWS_INIT_HEALTH_STATUS to HEALTHY or UNHEALTHY",
	"https://docs.aws.amazon.com/cloud-map/latest/api/API_RegisterInstance.html") if {
	some name in resources_of_type("AWS::ServiceDiscovery::Instance")
	v := object.get(_pf_sd_attrs(name), "AWS_INIT_HEALTH_STATUS", null)
	is_string(v)
	not v in {"HEALTHY", "UNHEALTHY"}
}
