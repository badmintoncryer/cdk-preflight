package cdk_preflight

import rego.v1

# A TLS_PASSTHROUGH listener does not terminate TLS, so it cannot answer with
# a fixed response. CreateListener rejects DefaultAction.FixedResponse on it
# ("Only forward action is allowed for TLS_PASSTHROUGH listener protocol").
violation contains make_diag_full("pf-vpclattice-listener-tls-fixed-response", "ERROR", name,
	"Properties.DefaultAction.FixedResponse",
	"A TLS_PASSTHROUGH listener cannot use a fixed response; CreateListener fails with \"Only forward action is allowed for TLS_PASSTHROUGH listener protocol\"",
	"Forward to a TCP target group instead",
	"https://docs.aws.amazon.com/vpc-lattice/latest/ug/tls-listeners.html") if {
	some name in resources_of_type("AWS::VpcLattice::Listener")
	resolve(name, "Properties.Protocol") == "TLS_PASSTHROUGH"
	_pf_vpcl_has(name, "Properties.DefaultAction.FixedResponse")
}
