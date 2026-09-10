package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-healthcheck-calculated-child-calculated", "ERROR", name,
	"Properties.HealthCheckConfig.ChildHealthChecks",
	sprintf("child health check %s is itself CALCULATED; Route 53 does not nest calculated health checks", [ch]),
	"Point ChildHealthChecks at endpoint or CloudWatch alarm health checks",
	"https://docs.aws.amazon.com/Route53/latest/APIReference/API_HealthCheckConfig.html") if {
	some name in resources_of_type("AWS::Route53::HealthCheck")
	cfg := _pf_r53z_hcc(name)
	_pf_r53z_str(cfg, "Type") == "CALCULATED"
	some ch in _pf_r53z_children(cfg)
	_pf_r53z_str(_pf_r53z_hcc(ch), "Type") == "CALCULATED"
}
