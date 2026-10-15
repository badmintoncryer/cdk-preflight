package cdk_preflight

import rego.v1

# An inline function's code lives in a file named index, so a Handler whose module
# is anything else deploys fine and then fails every invocation with
# Runtime.ImportModuleError. CreateFunction does not look inside the package.
# A Handler without a dot is a different error (Bad handler) and is left alone.
_pf_lzhm_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lambda-function-code.html#cfn-lambda-function-code-zipfile"

violation contains make_diag_full("pf-lambda-zipfile-handler-module", "ERROR", name,
	"Properties.Handler",
	sprintf("Code.ZipFile is saved as a file named index, but Handler '%s' loads module '%s'; every invocation fails with Runtime.ImportModuleError", [h, m]),
	sprintf("Set Handler to 'index.%s'", [_pf_lam_handler_fn(rt, h)]),
	_pf_lzhm_url) if {
	some [name, rt, h, _] in _pf_lam_inline
	m := _pf_lam_handler_module(rt, h)
	m != "index"
}
