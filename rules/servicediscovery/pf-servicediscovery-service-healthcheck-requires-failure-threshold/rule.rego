package cdk_preflight

import rego.v1

# The Cloud Map API defaults FailureThreshold to 1, but the CloudFormation resource
# handler unboxes it without a null check, so an omitted FailureThreshold takes the
# whole stack down with an InternalFailure that names no property.
violation contains make_diag_full("pf-servicediscovery-service-healthcheck-requires-failure-threshold", "ERROR", name,
	"Properties.HealthCheckConfig.FailureThreshold",
	"HealthCheckConfig has no FailureThreshold; the CloudFormation service handler dereferences it and the create fails with \"Cannot invoke \\\"java.lang.Double.intValue()\\\" because the return value of \\\"...HealthCheckConfig.getFailureThreshold()\\\" is null\" (InternalFailure)",
	"Set HealthCheckConfig.FailureThreshold explicitly (the API would default it to 1, the CloudFormation handler does not)",
	"https://docs.aws.amazon.com/cloud-map/latest/api/API_HealthCheckConfig.html") if {
	some name in resources_of_type("AWS::ServiceDiscovery::Service")
	hc := _pf_sd_healthcheck(name)
	object.get(hc, "FailureThreshold", "__pf_absent") == "__pf_absent"
}
