package cdk_preflight

import rego.v1

# A TCP target group has no protocol to inherit for its health check, and
# CreateTargetGroup rejects an enabled health check without one ("Must provide
# health check protocol for target group of TCP"). HealthCheck.Enabled false is
# accepted; only an explicit Enabled true is checked.
violation contains make_diag_full("pf-vpclattice-tg-tcp-health-check-protocol", "ERROR", name,
	"Properties.Config.HealthCheck.Protocol",
	"The health check of a TCP target group has no Protocol; CreateTargetGroup fails with \"Must provide health check protocol for target group of TCP\"",
	"Set HealthCheck.Protocol (HTTP or HTTPS) and ProtocolVersion, or disable the health check",
	"https://docs.aws.amazon.com/vpc-lattice/latest/ug/tls-listeners.html") if {
	some name in _pf_vpcl_tgs
	resolve(name, "Properties.Config.Protocol") == "TCP"
	resolve(name, "Properties.Config.HealthCheck.Enabled") == true
	not _pf_vpcl_has(name, "Properties.Config.HealthCheck.Protocol")
}
