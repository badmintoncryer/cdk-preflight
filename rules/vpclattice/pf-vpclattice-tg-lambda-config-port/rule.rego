package cdk_preflight

import rego.v1

# The schema lets every Config field appear on every target group type. For
# Type LAMBDA, CreateTargetGroup rejects Port, Protocol, ProtocolVersion,
# VpcIdentifier and HealthCheck alike ("Config contains invalid properties for
# Lambda Target Group"); only LambdaEventStructureVersion is accepted.
_pf_vpcltlc_keys := ["Port", "Protocol", "ProtocolVersion", "VpcIdentifier", "HealthCheck"]

violation contains make_diag_full("pf-vpclattice-tg-lambda-config-port", "ERROR", name,
	sprintf("Properties.Config.%s", [k]),
	sprintf("A LAMBDA target group takes no Config.%s; CreateTargetGroup fails with \"Config contains invalid properties for Lambda Target Group\"", [k]),
	"Drop the field; a LAMBDA target group Config holds only LambdaEventStructureVersion",
	"https://docs.aws.amazon.com/vpc-lattice/latest/APIReference/API_TargetGroupConfig.html") if {
	some name in _pf_vpcl_tgs_of("LAMBDA")
	some k in _pf_vpcltlc_keys
	_pf_vpcl_has(name, concat(".", ["Properties.Config", k]))
}
