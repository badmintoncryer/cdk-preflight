package cdk_preflight

import rego.v1

_pf_schemaunknownscalar_clean(s) := c if {
	a := regex.replace(s, `"""[^"]*"""`, " ")
	b := regex.replace(a, `#[^\n]*`, " ")
	c := regex.replace(b, `@[A-Za-z_][A-Za-z0-9_]*\([^)]*\)`, " ")
}

_pf_schemaunknownscalar_defined(s) := {m[1] |
	some m in regex.find_all_string_submatch_n(`(?:type|input|interface|enum|union|scalar)\s+([A-Za-z_][A-Za-z0-9_]*)`, s, -1)
}

_pf_schemaunknownscalar_aws := {
	"AWSDate", "AWSTime", "AWSDateTime", "AWSTimestamp", "AWSEmail",
	"AWSJSON", "AWSURL", "AWSPhone", "AWSIPAddress",
}

violation contains make_diag_full("pf-appsync-schema-unknown-scalar", "ERROR", name,
	"Properties.Definition",
	sprintf("'%s' is not an AppSync scalar; the schema create fails with \"The field type '%s' is not present when required\"", [t, t]),
	"Use one of AWSDate, AWSTime, AWSDateTime, AWSTimestamp, AWSEmail, AWSJSON, AWSURL, AWSPhone, AWSIPAddress",
	"https://docs.aws.amazon.com/appsync/latest/devguide/scalars.html") if {
	some name in resources_of_type("AWS::AppSync::GraphQLSchema")
	sdl := resolve(name, "Properties.Definition")
	is_string(sdl)
	s0 := _pf_schemaunknownscalar_clean(sdl)
	s := regex.replace(s0, `schema\s*\{[^}]*\}`, " ")
	defined := _pf_schemaunknownscalar_defined(s0)
	some m in regex.find_all_string_submatch_n(`:\s*\[?\s*(AWS[A-Za-z0-9_]*)`, s, -1)
	t := m[1]
	not t in _pf_schemaunknownscalar_aws
	not t in defined
}
