package cdk_preflight

import rego.v1

# Tags survive into the template from every scope that called Tags.of(), and the
# merge happens in cfnProperties at render time - after validateTree - so no L1
# or L2 validation can see the final key set. Applies to every resource type.
_pf_tagaws_bad contains [name, idx, key] if {
	some name in object.keys(input.resources)
	some t in flatten_list(name, "Properties.Tags")
	is_object(t.value)
	key := object.get(t.value, "Key", null)
	is_string(key)
	startswith(lower(key), "aws:")
	idx := t.index
}

violation contains make_diag_full("pf-tags-aws-prefix", "ERROR", name,
	sprintf("Properties.Tags.%d.Key", [idx]),
	sprintf("Tag key '%s' uses the reserved aws: prefix; AWS rejects the create call with \"aws: prefixed tag key names are not allowed for external use.\"", [key]),
	"Rename the tag key so it does not start with aws:",
	"https://docs.aws.amazon.com/tag-editor/latest/userguide/tagging.html") if {
	some [name, idx, key] in _pf_tagaws_bad
}
