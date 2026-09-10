package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-healthcheck-endpoint-required", "ERROR", name,
	"Properties.HealthCheckConfig",
	sprintf("a %s health check has neither IPAddress nor FullyQualifiedDomainName, so there is no endpoint to check", [t]),
	"Add FullyQualifiedDomainName (or IPAddress) to the health check config",
	"https://docs.aws.amazon.com/Route53/latest/APIReference/API_HealthCheckConfig.html") if {
	some name in resources_of_type("AWS::Route53::HealthCheck")
	cfg := _pf_r53z_hcc(name)
	t := _pf_r53z_str(cfg, "Type")
	t in _pf_r53z_endpoint_types
	not _pf_r53z_has(cfg, "IPAddress")
	not _pf_r53z_has(cfg, "FullyQualifiedDomainName")
}
