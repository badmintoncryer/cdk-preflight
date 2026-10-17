package cdk_preflight

import rego.v1

# Health checks of an ALB target come from the load balancer itself, and
# CreateTargetGroup rejects a HealthCheck block on Type ALB ("ALB Target Group
# does not support health check config"). The schema does not tie HealthCheck
# to the type.
violation contains make_diag_full("pf-vpclattice-tg-alb-health-check", "ERROR", name,
	"Properties.Config.HealthCheck",
	"An ALB target group takes no HealthCheck; CreateTargetGroup fails with \"ALB Target Group does not support health check config\"",
	"Drop Config.HealthCheck and configure health checks on the Application Load Balancer target group instead",
	"https://docs.aws.amazon.com/vpc-lattice/latest/ug/target-group-health-checks.html") if {
	some name in _pf_vpcl_tgs_of("ALB")
	_pf_vpcl_has(name, "Properties.Config.HealthCheck")
}
