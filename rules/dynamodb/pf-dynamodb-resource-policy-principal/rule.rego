package cdk_preflight

import rego.v1

# A resource-based policy is not an identity policy: Principal (or
# NotPrincipal) is required in every statement. IAM's own policy validator
# never sees this document, so nothing before deploy catches it.
violation contains make_diag_full("pf-dynamodb-resource-policy-principal", "ERROR", name,
	sprintf("Properties.ResourcePolicy.PolicyDocument.Statement.%d", [s.index]),
	sprintf("Resource policy statement %d has no Principal; PutResourcePolicy fails with \"Invalid policy document: Missing required field Principal\"", [s.index]),
	"Add a Principal (or NotPrincipal) to every statement of the table's resource policy",
	"https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/rbac-considerations.html") if {
	some name in resources_of_type("AWS::DynamoDB::Table")
	some s in flatten_list(name, "Properties.ResourcePolicy.PolicyDocument.Statement")
	object.get(s.value, "Principal", "__pf_absent") == "__pf_absent"
	object.get(s.value, "NotPrincipal", "__pf_absent") == "__pf_absent"
}
