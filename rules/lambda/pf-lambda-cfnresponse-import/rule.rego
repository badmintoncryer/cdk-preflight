package cdk_preflight

import rego.v1

# CloudFormation adds the cfnresponse module to an inline Python package only
# when the code contains the statement `import cfnresponse` as written. Any other
# form (`import json, cfnresponse`, `from cfnresponse import send`) deploys fine
# and then fails every invocation with Runtime.ImportModuleError before the
# handler runs, so a custom resource never answers and the stack waits for
# ServiceTimeout. Only fires when that statement is absent everywhere in the code.
_pf_lcri_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-lambda-function-code-cfnresponsemodule.html"

violation contains make_diag_full("pf-lambda-cfnresponse-import", "ERROR", name,
	"Properties.Code.ZipFile",
	sprintf("The inline code imports cfnresponse as '%s'; CloudFormation bundles the module only for the exact statement 'import cfnresponse', so every invocation fails with Runtime.ImportModuleError: No module named 'cfnresponse'", [trim_space(line)]),
	"Write 'import cfnresponse' on a line of its own, or answer the ResponseURL yourself with urllib",
	_pf_lcri_url) if {
	some [name, rt, _, code] in _pf_lam_inline
	_pf_lam_no_layers(name)
	startswith(rt, "python")
	not contains(code, "import cfnresponse")
	line := regex.find_n(`(?m)^[ \t]*(import|from)[ \t].*\bcfnresponse\b.*$`, code, 1)[0]
}
