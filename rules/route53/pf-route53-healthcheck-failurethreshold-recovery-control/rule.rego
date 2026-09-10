package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-healthcheck-failurethreshold-recovery-control", "WARN", name,
	"Properties.HealthCheckConfig.FailureThreshold",
	"FailureThreshold is set on a RECOVERY_CONTROL health check; the routing control decides the state, so Route 53 rejects the property",
	"Drop FailureThreshold from the recovery control health check",
	"https://docs.aws.amazon.com/Route53/latest/APIReference/API_HealthCheckConfig.html") if {
	some name in resources_of_type("AWS::Route53::HealthCheck")
	cfg := _pf_r53z_hcc(name)
	_pf_r53z_str(cfg, "Type") == "RECOVERY_CONTROL"
	_pf_r53z_has(cfg, "FailureThreshold")
}
