package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-healthcheck-regions-endpoint-types-only", "ERROR", name,
	"Properties.HealthCheckConfig.Regions",
	sprintf("Regions is set on a %s health check; only endpoint checks place health checkers in regions", [t]),
	"Drop Regions, or use an endpoint health check type",
	"https://docs.aws.amazon.com/Route53/latest/APIReference/API_HealthCheckConfig.html") if {
	some name in resources_of_type("AWS::Route53::HealthCheck")
	cfg := _pf_r53z_hcc(name)
	_pf_r53z_has(cfg, "Regions")
	t := _pf_r53z_str(cfg, "Type")
	not t in _pf_r53z_endpoint_types
}
