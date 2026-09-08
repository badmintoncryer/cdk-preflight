package cdk_preflight

import rego.v1

# The quota counts the serialized document including whitespace; json.marshal
# is the compact form, so this rule only fires on documents that are over the
# limit however they are serialized.
violation contains make_diag_full("pf-dynamodb-resource-policy-size", "ERROR", name,
	"Properties.ResourcePolicy.PolicyDocument",
	sprintf("The resource policy serializes to %d bytes; PutResourcePolicy fails with \"Maximum policy size of 20480 bytes exceeded\"", [n]),
	"Shorten the policy: drop Sid strings, merge statements, or move principals into a shared IAM role",
	"https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/rbac-considerations.html") if {
	some name in resources_of_type("AWS::DynamoDB::Table")
	doc := resolve(name, "Properties.ResourcePolicy.PolicyDocument")
	is_object(doc)
	n := count(json.marshal(doc))
	n > 20480
}
