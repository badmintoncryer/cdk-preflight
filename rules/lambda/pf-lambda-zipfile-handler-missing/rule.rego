package cdk_preflight

import rego.v1

# The handler's function has to be defined in the inline file. When its name does
# not appear anywhere in Code.ZipFile, the function deploys fine and every
# invocation fails with Runtime.HandlerNotFound. Only the name's absence is judged:
# an appearance anywhere (a comment, a string) counts as defined, so this never
# argues with what the code does. Skipped when the code can define names without
# spelling them: Python `import *`, `globals()`, `setattr`, `exec`; Node.js
# re-exports through `require(...)` assigned or spread into `module.exports`
# or `exports`, `Object.assign`, and `export *`. Names outside [A-Za-z_][A-Za-z0-9_]*
# are left alone.
_pf_lzhx_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lambda-function-code.html#cfn-lambda-function-code-zipfile"

_pf_lzhx_dynamic(rt, code) if {
	startswith(rt, "python")
	regex.match(`import\s+\*|globals\s*\(|setattr\s*\(|exec\s*\(`, code)
}

_pf_lzhx_dynamic(rt, code) if {
	startswith(rt, "nodejs")
	regex.match(`exports\s*=\s*require\s*\(|\.\.\.\s*require\s*\(|Object\.assign\s*\(|export\s*\*`, code)
}

violation contains make_diag_full("pf-lambda-zipfile-handler-missing", "ERROR", name,
	"Properties.Handler",
	sprintf("Handler '%s' names '%s', which does not appear in Code.ZipFile; every invocation fails with Runtime.HandlerNotFound", [h, fn]),
	"Point Handler at the function the inline code defines (and exports, on Node.js)",
	_pf_lzhx_url) if {
	some [name, rt, h, code] in _pf_lam_inline
	_pf_lam_handler_module(rt, h) == "index"
	fn := _pf_lam_handler_fn(rt, h)
	regex.match(`^[A-Za-z_][A-Za-z0-9_]*$`, fn)
	not _pf_lzhx_dynamic(rt, code)
	not regex.match(sprintf(`\b%s\b`, [fn]), code)
}
