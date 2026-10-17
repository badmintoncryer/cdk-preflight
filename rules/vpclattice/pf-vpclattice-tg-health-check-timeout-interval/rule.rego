package cdk_preflight

import rego.v1

# The schema bounds HealthCheckTimeoutSeconds (1..120) and
# HealthCheckIntervalSeconds (5..300) separately. CreateTargetGroup orders them
# ("Health check timeout value must be less than or equal to the health check
# interval"); equal values are accepted. Only explicit values are compared.
violation contains make_diag_full("pf-vpclattice-tg-health-check-timeout-interval", "ERROR", name,
	"Properties.Config.HealthCheck.HealthCheckTimeoutSeconds",
	sprintf("HealthCheckTimeoutSeconds (%v) exceeds HealthCheckIntervalSeconds (%v); CreateTargetGroup fails with \"Health check timeout value must be less than or equal to the health check interval\"", [to, iv]),
	"Lower HealthCheckTimeoutSeconds to at most HealthCheckIntervalSeconds",
	"https://docs.aws.amazon.com/vpc-lattice/latest/ug/target-group-health-checks.html") if {
	some name in _pf_vpcl_tgs
	to := _pf_num(name, "Properties.Config.HealthCheck.HealthCheckTimeoutSeconds")
	iv := _pf_num(name, "Properties.Config.HealthCheck.HealthCheckIntervalSeconds")
	to > iv
}
