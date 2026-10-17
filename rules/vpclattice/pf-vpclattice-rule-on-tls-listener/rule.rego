package cdk_preflight

import rego.v1

# A TLS_PASSTHROUGH listener cannot look at HTTP, so it has only its default
# action; CreateRule rejects any rule on it ("Invalid listener type:
# TLS_PASSTHROUGH listener can only have default rule"). Checked when
# ListenerIdentifier references a listener in the same template.
violation contains make_diag_full("pf-vpclattice-rule-on-tls-listener", "ERROR", name,
	"Properties.ListenerIdentifier",
	sprintf("Listener '%s' is TLS_PASSTHROUGH; CreateRule fails with \"TLS_PASSTHROUGH listener can only have default rule\"", [l]),
	"Remove the rule, or attach it to an HTTP or HTTPS listener",
	"https://docs.aws.amazon.com/vpc-lattice/latest/ug/tls-listeners.html") if {
	some name in resources_of_type("AWS::VpcLattice::Rule")
	l := resolve(name, "Properties.ListenerIdentifier")
	l in resources_of_type("AWS::VpcLattice::Listener")
	resolve(l, "Properties.Protocol") == "TLS_PASSTHROUGH"
}
