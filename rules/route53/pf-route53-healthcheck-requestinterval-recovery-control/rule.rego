package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-healthcheck-requestinterval-recovery-control", "WARN", name,
	"Properties.HealthCheckConfig.RequestInterval",
	"RequestInterval is set on a RECOVERY_CONTROL health check, which never contacts an endpoint",
	"Drop RequestInterval from the recovery control health check",
	"https://docs.aws.amazon.com/Route53/latest/APIReference/API_HealthCheckConfig.html") if {
	some name in resources_of_type("AWS::Route53::HealthCheck")
	cfg := _pf_r53z_hcc(name)
	_pf_r53z_str(cfg, "Type") == "RECOVERY_CONTROL"
	_pf_r53z_has(cfg, "RequestInterval")
}
