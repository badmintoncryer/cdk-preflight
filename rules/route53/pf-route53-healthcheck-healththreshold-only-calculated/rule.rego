package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-healthcheck-healththreshold-only-calculated", "ERROR", name,
	"Properties.HealthCheckConfig.HealthThreshold",
	sprintf("HealthThreshold is set on a %s health check; it only counts healthy children of a CALCULATED check", [t]),
	"Drop HealthThreshold, or set Type to CALCULATED",
	"https://docs.aws.amazon.com/Route53/latest/APIReference/API_HealthCheckConfig.html") if {
	some name in resources_of_type("AWS::Route53::HealthCheck")
	cfg := _pf_r53z_hcc(name)
	_pf_r53z_has(cfg, "HealthThreshold")
	t := _pf_r53z_str(cfg, "Type")
	t != "CALCULATED"
}
