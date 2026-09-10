package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-healthcheck-enablesni-https-only", "ERROR", name,
	"Properties.HealthCheckConfig.EnableSNI",
	sprintf("EnableSNI is set on a %s health check; SNI only applies to HTTPS and HTTPS_STR_MATCH", [t]),
	"Drop EnableSNI, or switch the health check to HTTPS",
	"https://docs.aws.amazon.com/Route53/latest/APIReference/API_HealthCheckConfig.html") if {
	some name in resources_of_type("AWS::Route53::HealthCheck")
	cfg := _pf_r53z_hcc(name)
	_pf_r53z_has(cfg, "EnableSNI")
	t := _pf_r53z_str(cfg, "Type")
	not t in _pf_r53z_https_types
}
