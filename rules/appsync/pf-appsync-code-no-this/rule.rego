package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-appsync-code-no-this", "ERROR", name,
	"Properties.Code",
	"the APPSYNC_JS handler uses this expressions; the create call fails because the AppSync JavaScript runtime rejects them at parse time",
	"Reference the value directly instead of through this",
	"https://docs.aws.amazon.com/appsync/latest/devguide/resolver-reference-js-version.html") if {
	some _t in {"AWS::AppSync::FunctionConfiguration", "AWS::AppSync::Resolver"}
	some name in resources_of_type(_t)
	code := resolve(name, "Properties.Code")
	is_string(code)
	regex.match(`\bthis\b`, code)
}
