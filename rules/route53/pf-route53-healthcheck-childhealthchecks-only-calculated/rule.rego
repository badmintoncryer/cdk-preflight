package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-healthcheck-childhealthchecks-only-calculated", "ERROR", name,
	"Properties.HealthCheckConfig.ChildHealthChecks",
	sprintf("ChildHealthChecks is set on a %s health check; only CALCULATED aggregates other health checks", [t]),
	"Drop ChildHealthChecks, or set Type to CALCULATED",
	"https://docs.aws.amazon.com/Route53/latest/APIReference/API_HealthCheckConfig.html") if {
	some name in resources_of_type("AWS::Route53::HealthCheck")
	cfg := _pf_r53z_hcc(name)
	_pf_r53z_has(cfg, "ChildHealthChecks")
	t := _pf_r53z_str(cfg, "Type")
	t != "CALCULATED"
}
