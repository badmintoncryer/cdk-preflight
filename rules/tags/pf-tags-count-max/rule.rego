package cdk_preflight

import rego.v1

# The AWS-wide limit is 50 user tags per resource. Counted on the rendered
# template, which is the only place the merged Tags.of() result exists.
_pf_tagcount_bad contains [name, n] if {
	some name in object.keys(input.resources)
	tags := flatten_list(name, "Properties.Tags")
	n := count(tags)
	n > 50
}

violation contains make_diag_full("pf-tags-count-max", "ERROR", name,
	"Properties.Tags",
	sprintf("%d tags are attached to this resource; AWS allows at most 50 per resource and rejects the create call (\"More than 50 tags specified.\")", [n]),
	"Reduce the tag set to 50 or fewer - remember that Tags.of() adds tags from every enclosing scope",
	"https://docs.aws.amazon.com/tag-editor/latest/userguide/tagging.html") if {
	some [name, n] in _pf_tagcount_bad
}
