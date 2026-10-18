package cdk_preflight

import rego.v1

# Services may share a CustomDomainName, but a service network resolves each
# name to one service. The second association fails ("Custom domain name ...
# already exists in service network sn-..."). Checked when both associations
# reference services in the same template and the same service network.
_pf_vpclcdd_dom(a) := [s, d] if {
	s := resolve(a, "Properties.ServiceIdentifier")
	s in resources_of_type("AWS::VpcLattice::Service")
	d := resolve(s, "Properties.CustomDomainName")
	is_string(d)
}

violation contains make_diag_full("pf-vpclattice-service-custom-domain-duplicate-in-sn", "ERROR", name,
	"Properties.ServiceIdentifier",
	sprintf("Service '%s' has CustomDomainName '%s', already used by service '%s' in the same service network; the association fails with \"Custom domain name ... already exists in service network\"", [sd[0], sd[1], od[0]]),
	"Give each service in the service network its own CustomDomainName",
	"https://docs.aws.amazon.com/vpc-lattice/latest/ug/service-custom-domain-name.html") if {
	some name in resources_of_type("AWS::VpcLattice::ServiceNetworkServiceAssociation")
	sd := _pf_vpclcdd_dom(name)
	n := resolve(name, "Properties.ServiceNetworkIdentifier")
	is_string(n)
	some other in resources_of_type("AWS::VpcLattice::ServiceNetworkServiceAssociation")
	other < name
	resolve(other, "Properties.ServiceNetworkIdentifier") == n
	od := _pf_vpclcdd_dom(other)
	od[0] != sd[0]
	lower(od[1]) == lower(sd[1])
}
