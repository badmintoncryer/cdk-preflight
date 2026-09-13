package cdk_preflight

import rego.v1

_pf_coderequestresponseexportsrequired_exported(code, what) if {
	pat := sprintf(`export\s+(?:function\s+%s\b|(?:const|let|var)\s+%s\s*=|\{[^}]*\b%s\b)`, [what, what, what])
	count(regex.find_n(pat, code, -1)) > 0
}

_pf_coderequestresponseexportsrequired_missing(code) if not _pf_coderequestresponseexportsrequired_exported(code, "request")

_pf_coderequestresponseexportsrequired_missing(code) if not _pf_coderequestresponseexportsrequired_exported(code, "response")

violation contains make_diag_full("pf-appsync-code-request-response-exports-required", "ERROR", name,
	"Properties.Code",
	"the APPSYNC_JS handler does not export both request and response; the create call fails with \"Unable to find valid export for response\"",
	"Export a request(ctx) and a response(ctx) function from the handler",
	"https://docs.aws.amazon.com/appsync/latest/devguide/resolver-reference-js-version.html") if {
	some _t in {"AWS::AppSync::FunctionConfiguration", "AWS::AppSync::Resolver"}
	some name in resources_of_type(_t)
	code := resolve(name, "Properties.Code")
	is_string(code)
	_pf_coderequestresponseexportsrequired_missing(code)
}
