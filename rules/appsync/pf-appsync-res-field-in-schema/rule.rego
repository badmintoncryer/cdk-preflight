package cdk_preflight

import rego.v1

# Judged only when an inline schema for the same API is a sibling resource, and
# only when the type itself is found (res-type-field-in-schema owns the rest).
_pf_resfieldinschema_sdl(api) := s if {
	some g in resources_of_type("AWS::AppSync::GraphQLSchema")
	resolve(g, "Properties.ApiId") == api
	s := resolve(g, "Properties.Definition")
	is_string(s)
}

violation contains make_diag_full("pf-appsync-res-field-in-schema", "ERROR", name,
	"Properties.FieldName",
	sprintf("the resolver attaches to field '%s' of type '%s', which the schema in this template does not declare; the resolver create fails because there is no such field", [f, t]),
	"Attach the resolver to a field the schema declares on that type",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-appsync-resolver.html") if {
	some name in resources_of_type("AWS::AppSync::Resolver")
	api := resolve(name, "Properties.ApiId")
	sdl := _pf_resfieldinschema_sdl(api)
	t := resolve(name, "Properties.TypeName")
	is_string(t)
	f := resolve(name, "Properties.FieldName")
	is_string(f)
	some b in regex.find_all_string_submatch_n(sprintf(`type\s+%s\b[^{]*\{([^}]*)\}`, [t]), sdl, -1)
	count(regex.find_n(sprintf(`\b%s\s*[(:]`, [f]), b[1], -1)) == 0
}
