package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-healthcheck-alarmidentifier-cloudwatch-only", "ERROR", name,
	"Properties.HealthCheckConfig.AlarmIdentifier",
	sprintf("AlarmIdentifier is set on a %s health check; it belongs to CLOUDWATCH_METRIC only", [t]),
	"Drop AlarmIdentifier, or set Type to CLOUDWATCH_METRIC",
	"https://docs.aws.amazon.com/Route53/latest/APIReference/API_HealthCheckConfig.html") if {
	some name in resources_of_type("AWS::Route53::HealthCheck")
	cfg := _pf_r53z_hcc(name)
	_pf_r53z_has(cfg, "AlarmIdentifier")
	t := _pf_r53z_str(cfg, "Type")
	t != "CLOUDWATCH_METRIC"
}
