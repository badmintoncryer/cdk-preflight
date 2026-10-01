package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cassandra-table-udt-dependency", "ERROR", name, path,
	sprintf("%v %v uses the UDT %v created by %v, but nothing makes this resource wait for it; CloudFormation creates both in parallel and Keyspaces answers \"UDT %v does not exist\"", [path, t, n.n, ty, n.n]),
	"Add DependsOn on the AWS::Cassandra::Type",
	"https://docs.aws.amazon.com/keyspaces/latest/devguide/udts.html") if {
	some [name, _, path, t] in _pf_cass_col
	ks := _pf_cass_ks(name)
	some n in _pf_cass_nodes(t)
	not n.open
	some u in _pf_cass_udts
	u[0] == ks
	u[1] == n.n
	ty := u[2]
	ty != name
	deps := _pf_cass_deps(name)
	not ty in deps
}
