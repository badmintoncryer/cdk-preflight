package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-avp-schema-action-memberof-declared", "ERROR", name, "Properties.Schema.CedarJson",
	sprintf("action %v::%v is a member of the group %v, which the namespace does not declare; CreatePolicyStore answers \"undeclared action: Action::\\\"%v\\\"\"", [nsname, a, id, id]),
	"Declare the action group under the same actions object, or point memberOf at an action that exists",
	"https://docs.cedarpolicy.com/schema/json-schema.html") if {
	some [name, nsname, a, d] in _pf_avpsch_acts
	mo := object.get(d, "memberOf", [])
	is_array(mo)
	some m in mo
	is_object(m)
	object.get(m, "type", "__pf_absent") == "__pf_absent"
	id := object.get(m, "id", null)
	is_string(id)
	not [name, nsname, id] in _pf_avpsch_actids
}
