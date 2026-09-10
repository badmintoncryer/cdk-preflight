package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-healthcheck-alarmidentifier-required-cloudwatch", "ERROR", name,
	"Properties.HealthCheckConfig",
	"a CLOUDWATCH_METRIC health check has no AlarmIdentifier, so Route 53 has no alarm to watch",
	"Add AlarmIdentifier with the alarm's Name and Region",
	"https://docs.aws.amazon.com/Route53/latest/APIReference/API_HealthCheckConfig.html") if {
	some name in resources_of_type("AWS::Route53::HealthCheck")
	cfg := _pf_r53z_hcc(name)
	_pf_r53z_str(cfg, "Type") == "CLOUDWATCH_METRIC"
	not _pf_r53z_has(cfg, "AlarmIdentifier")
}
