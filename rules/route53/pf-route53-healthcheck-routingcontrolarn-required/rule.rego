package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-healthcheck-routingcontrolarn-required", "ERROR", name,
	"Properties.HealthCheckConfig",
	"a RECOVERY_CONTROL health check has no RoutingControlArn, so Route 53 has no routing control to read",
	"Add RoutingControlArn pointing at the Application Recovery Controller routing control",
	"https://docs.aws.amazon.com/Route53/latest/APIReference/API_HealthCheckConfig.html") if {
	some name in resources_of_type("AWS::Route53::HealthCheck")
	cfg := _pf_r53z_hcc(name)
	_pf_r53z_str(cfg, "Type") == "RECOVERY_CONTROL"
	not _pf_r53z_has(cfg, "RoutingControlArn")
}
