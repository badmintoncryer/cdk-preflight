package cdk_preflight

import rego.v1

# Exports only exist once the stack that declares them has been created, so a
# template that imports its own export always fails on the first deploy. The
# engine flattens Fn::ImportValue into a marker inside the properties, at any
# depth, so the whole property tree is matched as marshalled JSON.
_pf_cfnivself_bad contains [name, ename] if {
	some name, res in input.resources
	props := json.marshal(object.get(res, "properties", {}))
	some o in input.outputs
	ename := object.get(o, "exportName", null)
	is_string(ename)
	contains(props, sprintf(`"cross-stack import: %s"`, [ename]))
}

violation contains make_diag_full("pf-cfn-importvalue-self-export", "ERROR", name,
	"Properties",
	sprintf("This resource imports '%s', which the same template exports; the export does not exist yet when the stack is created and CloudFormation fails it with \"No export named %s found\"", [ename, ename]),
	"Reference the value directly (Ref/GetAtt) instead of importing this stack's own export, or split the two stacks",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-stack-exports.html") if {
	some [name, ename] in _pf_cfnivself_bad
}
