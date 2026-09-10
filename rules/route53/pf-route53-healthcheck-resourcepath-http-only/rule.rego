package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-healthcheck-resourcepath-http-only", "ERROR", name,
	"Properties.HealthCheckConfig.ResourcePath",
	sprintf("ResourcePath is set on a %s health check; only HTTP and HTTPS checks request a path", [t]),
	"Drop ResourcePath, or use an HTTP/HTTPS health check type",
	"https://docs.aws.amazon.com/Route53/latest/APIReference/API_HealthCheckConfig.html") if {
	some name in resources_of_type("AWS::Route53::HealthCheck")
	cfg := _pf_r53z_hcc(name)
	_pf_r53z_has(cfg, "ResourcePath")
	t := _pf_r53z_str(cfg, "Type")
	not t in _pf_r53z_http_types
}
