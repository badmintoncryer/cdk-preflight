package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-healthcheck-insufficientdata-cloudwatch-only", "ERROR", name,
	"Properties.HealthCheckConfig.InsufficientDataHealthStatus",
	sprintf("InsufficientDataHealthStatus is set on a %s health check; it only describes what to do while a CloudWatch alarm has no data", [t]),
	"Drop InsufficientDataHealthStatus, or set Type to CLOUDWATCH_METRIC",
	"https://docs.aws.amazon.com/Route53/latest/APIReference/API_HealthCheckConfig.html") if {
	some name in resources_of_type("AWS::Route53::HealthCheck")
	cfg := _pf_r53z_hcc(name)
	_pf_r53z_has(cfg, "InsufficientDataHealthStatus")
	t := _pf_r53z_str(cfg, "Type")
	t != "CLOUDWATCH_METRIC"
}
