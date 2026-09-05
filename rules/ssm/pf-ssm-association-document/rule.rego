package cdk_preflight

import rego.v1

_pf_ssmad_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ssm-association.html"

_pf_ssmad_fix := "Drop DocumentVersion for AWS-* documents (or use $DEFAULT semantics by omission), reference a Command/Automation/Policy document in this region, pass only declared parameters and every required one, and set AutomationTargetParameterName for Automation documents with Targets"

_pf_ssmad_props(name) := props if {
	props := input.resources[name].properties
	is_object(props)
}

_pf_ssmad_name(name) := n if {
	n := resolve(name, "Properties.Name")
	is_string(n)
}

_pf_ssmad_amazon(n) if regex.match("^(?i)(aws|amazon|amzn)", n)

violation contains make_diag_full("pf-ssm-association-document", "ERROR", name,
	"Properties.DocumentVersion",
	sprintf("DocumentVersion cannot be used with the Amazon-owned document '%s'; CreateAssociation fails with \"Document version can not be used with Amazon document\"", [n]),
	_pf_ssmad_fix, _pf_ssmad_url) if {
	some name in resources_of_type("AWS::SSM::Association")
	n := _pf_ssmad_name(name)
	_pf_ssmad_amazon(n)
	object.get(_pf_ssmad_props(name), "DocumentVersion", "__pf_absent") != "__pf_absent"
}

# Region comparison needs the deploy region (enforce mode only).
violation contains make_diag_full("pf-ssm-association-document", "ERROR", name,
	"Properties.Name",
	sprintf("document ARN is in '%s' but the association deploys to '%s'; CreateAssociation fails with \"Document does not exist: %s\"", [parts[3], region, n]),
	_pf_ssmad_fix, _pf_ssmad_url) if {
	region := data.cdk_preflight.deploy_region
	some name in resources_of_type("AWS::SSM::Association")
	n := _pf_ssmad_name(name)
	startswith(n, "arn:")
	parts := split(n, ":")
	count(parts) >= 6
	parts[2] == "ssm"
	parts[3] != region
}

# documents defined in this template
_pf_ssmad_doc(name) := d if {
	d := _pf_ssmad_name(name)
	d in resources_of_type("AWS::SSM::Document")
}

_pf_ssmad_doctype(d) := t if {
	t := resolve(d, "Properties.DocumentType")
	is_string(t)
}

_pf_ssmad_doctype(d) := "Command" if {
	object.get(input.resources[d].properties, "DocumentType", "__pf_absent") == "__pf_absent"
}

_pf_ssmad_content(d) := c if {
	c := object.get(input.resources[d].properties, "Content", null)
	is_object(c)
}

_pf_ssmad_content(d) := c if {
	raw := object.get(input.resources[d].properties, "Content", null)
	is_string(raw)
	json.is_valid(raw)
	c := json.unmarshal(raw)
	is_object(c)
}

_pf_ssmad_params(d) := p if {
	p := object.get(_pf_ssmad_content(d), "parameters", null)
	is_object(p)
}

_pf_ssmad_params(d) := {} if {
	c := _pf_ssmad_content(d)
	not is_object(object.get(c, "parameters", null))
}

violation contains make_diag_full("pf-ssm-association-document", "ERROR", name,
	"Properties.DocumentVersion",
	sprintf("DocumentVersion %v refers to document '%s' created in this stack, which only has version 1; CreateAssociation fails with \"Document version: %v is invalid, latest version is 1\"", [v, d, v]),
	_pf_ssmad_fix, _pf_ssmad_url) if {
	some name in resources_of_type("AWS::SSM::Association")
	d := _pf_ssmad_doc(name)
	v := resolve(name, "Properties.DocumentVersion")
	regex.match("^[0-9]+$", sprintf("%v", [v]))
	sprintf("%v", [v]) != "1"
}

violation contains make_diag_full("pf-ssm-association-document", "ERROR", name,
	"Properties.Name",
	sprintf("document '%s' is a Session document; CreateAssociation fails with \"Document type Session is not supported for associations.\"", [d]),
	_pf_ssmad_fix, _pf_ssmad_url) if {
	some name in resources_of_type("AWS::SSM::Association")
	d := _pf_ssmad_doc(name)
	_pf_ssmad_doctype(d) == "Session"
}

violation contains make_diag_full("pf-ssm-association-document", "ERROR", name,
	"Properties.SyncCompliance",
	sprintf("SyncCompliance MANUAL passes an AssociationId parameter, but document '%s' does not declare one; CreateAssociation fails with \"Parameter \\\"AssociationId\\\" is not defined in the document.\"", [d]),
	_pf_ssmad_fix, _pf_ssmad_url) if {
	some name in resources_of_type("AWS::SSM::Association")
	resolve(name, "Properties.SyncCompliance") == "MANUAL"
	d := _pf_ssmad_doc(name)
	not _pf_ssmad_params(d).AssociationId
}

violation contains make_diag_full("pf-ssm-association-document", "ERROR", name,
	"Properties.AutomationTargetParameterName",
	sprintf("Automation document '%s' is associated with Targets but no AutomationTargetParameterName; CreateAssociation fails with \"Must specify both Automation Target Parameter Name and Targets\"", [d]),
	_pf_ssmad_fix, _pf_ssmad_url) if {
	some name in resources_of_type("AWS::SSM::Association")
	d := _pf_ssmad_doc(name)
	_pf_ssmad_doctype(d) == "Automation"
	t := object.get(_pf_ssmad_props(name), "Targets", null)
	is_array(t)
	count(t) > 0
	object.get(_pf_ssmad_props(name), "AutomationTargetParameterName", "__pf_absent") == "__pf_absent"
}

violation contains make_diag_full("pf-ssm-association-document", "ERROR", name,
	sprintf("Properties.Parameters.%s", [k]),
	sprintf("parameter '%s' is not declared by document '%s'; CreateAssociation fails with \"Parameter \\\"%s\\\" is not defined in the document.\"", [k, d, k]),
	_pf_ssmad_fix, _pf_ssmad_url) if {
	some name in resources_of_type("AWS::SSM::Association")
	d := _pf_ssmad_doc(name)
	given := object.get(_pf_ssmad_props(name), "Parameters", {})
	is_object(given)
	some k, _ in given
	not _pf_ssmad_params(d)[k]
}

violation contains make_diag_full("pf-ssm-association-document", "ERROR", name,
	"Properties.Parameters",
	sprintf("document '%s' requires parameter '%s' (no default) but the association does not pass it; CreateAssociation fails with \"Parameter \\\"%s\\\" requires a value.\"", [d, k, k]),
	_pf_ssmad_fix, _pf_ssmad_url) if {
	some name in resources_of_type("AWS::SSM::Association")
	d := _pf_ssmad_doc(name)
	some k, def in _pf_ssmad_params(d)
	is_object(def)
	object.get(def, "default", "__pf_absent") == "__pf_absent"
	given := object.get(_pf_ssmad_props(name), "Parameters", {})
	not _pf_ssmad_given(given, k)
}

_pf_ssmad_given(given, k) if {
	is_object(given)
	given[k]
}
