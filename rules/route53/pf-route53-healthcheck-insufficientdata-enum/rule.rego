package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-healthcheck-insufficientdata-enum", "ERROR", name,
	"Properties.HealthCheckConfig.InsufficientDataHealthStatus",
	sprintf("InsufficientDataHealthStatus %s is not one of Healthy, LastKnownStatus, Unhealthy", [v]),
	"Use one of Healthy, LastKnownStatus or Unhealthy",
	"https://docs.aws.amazon.com/Route53/latest/APIReference/API_HealthCheckConfig.html") if {
	some name in resources_of_type("AWS::Route53::HealthCheck")
	cfg := _pf_r53z_hcc(name)
	v := _pf_r53z_str(cfg, "InsufficientDataHealthStatus")
	not v in {"Healthy", "LastKnownStatus", "Unhealthy"}
}
