package cdk_preflight

import rego.v1

# Only an unambiguous literal position is judged (after =, ( or ,), so a
# division is never read as the start of a regex.
violation contains make_diag_full("pf-appsync-code-no-regex-literal", "ERROR", name,
	"Properties.Code",
	"the APPSYNC_JS handler contains a regular expression literal; the create call fails because the AppSync JavaScript runtime rejects them at parse time",
	"Use util.matches(pattern, value) instead of a /\u2026/ literal",
	"https://docs.aws.amazon.com/appsync/latest/devguide/resolver-reference-js-version.html") if {
	some _t in {"AWS::AppSync::FunctionConfiguration", "AWS::AppSync::Resolver"}
	some name in resources_of_type(_t)
	code := resolve(name, "Properties.Code")
	is_string(code)
	regex.match(`[=(,]\s*/[^/*\s][^/\n]*/[gimsuy]*`, code)
}
