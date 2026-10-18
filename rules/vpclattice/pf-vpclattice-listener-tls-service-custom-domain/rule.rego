package cdk_preflight

import rego.v1

# TLS passthrough routes on the SNI name, so the service needs its own domain.
# CreateListener rejects a TLS_PASSTHROUGH listener on a service without
# CustomDomainName ("TLS_PASSTHROUGH listener can only be created for a service
# with a custom domain name"). Checked only when ServiceIdentifier references
# an AWS::VpcLattice::Service in the same template.
violation contains make_diag_full("pf-vpclattice-listener-tls-service-custom-domain", "ERROR", name,
	"Properties.ServiceIdentifier",
	sprintf("Service '%s' has no CustomDomainName; CreateListener fails with \"TLS_PASSTHROUGH listener can only be created for a service with a custom domain name\"", [s]),
	"Set CustomDomainName on the service, or use an HTTP or HTTPS listener",
	"https://docs.aws.amazon.com/vpc-lattice/latest/ug/tls-listeners.html") if {
	some name in resources_of_type("AWS::VpcLattice::Listener")
	resolve(name, "Properties.Protocol") == "TLS_PASSTHROUGH"
	s := resolve(name, "Properties.ServiceIdentifier")
	s in resources_of_type("AWS::VpcLattice::Service")
	_pf_vpcl_raw(s, "CustomDomainName") == "__pf_absent"
}
