package cdk_preflight

import rego.v1

# The schema types Policy as a bare object. PutAuthPolicy counts the serialized
# document and rejects anything over 10240 bytes ("Access policy size exceeds
# maximum allowed size of 10240 bytes"; a non-adjustable quota). json.marshal is
# the compact form, so this fires only on documents that are over the limit
# however they are serialized. Characters, not bytes, are counted, so a
# document with non-ASCII text can slip under.
violation contains make_diag_full("pf-vpclattice-authpolicy-size", "ERROR", name,
	"Properties.Policy",
	sprintf("The auth policy serializes to %d bytes; PutAuthPolicy fails with \"Access policy size exceeds maximum allowed size of 10240 bytes\"", [n]),
	"Shorten the policy: drop Sid strings, merge statements, or move conditions into fewer statements",
	"https://docs.aws.amazon.com/vpc-lattice/latest/ug/quotas.html") if {
	some name in resources_of_type("AWS::VpcLattice::AuthPolicy")
	doc := resolve(name, "Properties.Policy")
	is_object(doc)
	n := count(json.marshal(doc))
	n > 10240
}
