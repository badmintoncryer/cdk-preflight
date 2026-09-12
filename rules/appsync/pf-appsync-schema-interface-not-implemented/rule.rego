package cdk_preflight

import rego.v1

_pf_schemainterfacenotimplemented_clean(s) := c if {
	a := regex.replace(s, `"""[^"]*"""`, " ")
	b := regex.replace(a, `#[^\n]*`, " ")
	c := regex.replace(b, `@[A-Za-z_][A-Za-z0-9_]*\([^)]*\)`, " ")
}

_pf_schemainterfacenotimplemented_fields(b) := {m[1] |
	some m in regex.find_all_string_submatch_n(`([A-Za-z_][A-Za-z0-9_]*)\s*:`, b, -1)
}

violation contains make_diag_full("pf-appsync-schema-interface-not-implemented", "ERROR", name,
	"Properties.Definition",
	sprintf("type '%s' implements '%s' but does not declare its field '%s'; the schema create fails with \"does not have a field\"", [t, iface, f]),
	"Declare the interface field on the implementing type",
	"https://docs.aws.amazon.com/appsync/latest/devguide/designing-your-schema.html") if {
	some name in resources_of_type("AWS::AppSync::GraphQLSchema")
	sdl := resolve(name, "Properties.Definition")
	is_string(sdl)
	s := regex.replace(_pf_schemainterfacenotimplemented_clean(sdl), `\([^)]*\)`, " ")
	some m in regex.find_all_string_submatch_n(`type\s+([A-Za-z_][A-Za-z0-9_]*)\s+implements\s+([^{]*)\{([^}]*)\}`, s, -1)
	t := m[1]
	some iface in regex.split(`[\s&]+`, m[2])
	iface != ""
	some ib in regex.find_all_string_submatch_n(`interface\s+([A-Za-z_][A-Za-z0-9_]*)[^{]*\{([^}]*)\}`, s, -1)
	ib[1] == iface
	some f in _pf_schemainterfacenotimplemented_fields(ib[2])
	not f in _pf_schemainterfacenotimplemented_fields(m[3])
}
