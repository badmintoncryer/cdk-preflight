package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-healthcheck-type-enum", "ERROR", name,
	"Properties.HealthCheckConfig.Type",
	sprintf("health check type %s is not one of CALCULATED, CLOUDWATCH_METRIC, HTTP, HTTPS, HTTP_STR_MATCH, HTTPS_STR_MATCH, TCP, RECOVERY_CONTROL", [t]),
	"Use one of the eight documented health check types",
	"https://docs.aws.amazon.com/Route53/latest/APIReference/API_HealthCheckConfig.html") if {
	some name in resources_of_type("AWS::Route53::HealthCheck")
	cfg := _pf_r53z_hcc(name)
	t := _pf_r53z_str(cfg, "Type")
	not t in _pf_r53z_hc_types
}
