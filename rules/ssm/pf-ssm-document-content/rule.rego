package cdk_preflight

import rego.v1

_pf_ssmdc_url := "https://docs.aws.amazon.com/systems-manager/latest/userguide/documents-schemas-features.html"

_pf_ssmdc_fix := "Fix the Content object: see the message for the field; plugin and action names are listed in the SSM document plugin/action references"

# Content is a JSON object, or a string holding JSON (YAML strings are skipped)
_pf_ssmdc_content(name) := c if {
	c := object.get(input.resources[name].properties, "Content", null)
	is_object(c)
}

_pf_ssmdc_content(name) := c if {
	raw := object.get(input.resources[name].properties, "Content", null)
	is_string(raw)
	json.is_valid(raw)
	c := json.unmarshal(raw)
	is_object(c)
}

_pf_ssmdc_type(name) := t if {
	t := resolve(name, "Properties.DocumentType")
	is_string(t)
}

_pf_ssmdc_type(name) := "Command" if {
	object.get(input.resources[name].properties, "DocumentType", "__pf_absent") == "__pf_absent"
}

_pf_ssmdc_schema(name) := sprintf("%v", [v]) if {
	v := object.get(_pf_ssmdc_content(name), "schemaVersion", null)
	v != null
}

_pf_ssmdc_format(name) := f if {
	f := resolve(name, "Properties.DocumentFormat")
	is_string(f)
}

_pf_ssmdc_format(name) := "JSON" if {
	object.get(input.resources[name].properties, "DocumentFormat", "__pf_absent") == "__pf_absent"
}

violation contains make_diag_full("pf-ssm-document-content", "ERROR", name,
	"Properties.Content",
	"Content is a string that is not JSON while DocumentFormat is JSON (the default); CreateDocument fails with \"JSON not well-formed.\" (set DocumentFormat: YAML for YAML text)",
	_pf_ssmdc_fix, _pf_ssmdc_url) if {
	some name in resources_of_type("AWS::SSM::Document")
	raw := object.get(input.resources[name].properties, "Content", null)
	is_string(raw)
	not json.is_valid(raw)
	_pf_ssmdc_format(name) == "JSON"
}

_pf_ssmdc_steps_schema(sv) if startswith(sv, "2.")

_pf_ssmdc_steps_schema(sv) if sv == "0.3"

violation contains make_diag_full("pf-ssm-document-content", "ERROR", name,
	"Properties.Content.mainSteps",
	"schemaVersion 2.x/0.3 documents need a non-empty mainSteps list; CreateDocument fails with \"Missing \\\"mainSteps\\\" in the document.\"",
	_pf_ssmdc_fix, _pf_ssmdc_url) if {
	some name in resources_of_type("AWS::SSM::Document")
	c := _pf_ssmdc_content(name)
	_pf_ssmdc_steps_schema(_pf_ssmdc_schema(name))
	not _pf_ssmdc_has_steps(c)
}

_pf_ssmdc_has_steps(c) if {
	s := object.get(c, "mainSteps", null)
	is_array(s)
	count(s) > 0
}

violation contains make_diag_full("pf-ssm-document-content", "ERROR", name,
	"Properties.Content.runtimeConfig",
	"runtimeConfig belongs to schemaVersion 1.2; 2.x documents use mainSteps, and CreateDocument fails with \"Unknown property \\\"runtimeConfig\\\".\"",
	_pf_ssmdc_fix, _pf_ssmdc_url) if {
	some name in resources_of_type("AWS::SSM::Document")
	c := _pf_ssmdc_content(name)
	startswith(_pf_ssmdc_schema(name), "2.")
	object.get(c, "runtimeConfig", "__pf_absent") != "__pf_absent"
}

violation contains make_diag_full("pf-ssm-document-content", "ERROR", name,
	"Properties.Content.runtimeConfig",
	"schemaVersion 1.2 documents need runtimeConfig; CreateDocument fails with \"Missing \\\"runtimeConfig\\\" in the document.\"",
	_pf_ssmdc_fix, _pf_ssmdc_url) if {
	some name in resources_of_type("AWS::SSM::Document")
	c := _pf_ssmdc_content(name)
	_pf_ssmdc_type(name) in ["Command", "Policy"]
	_pf_ssmdc_schema(name) in ["1.0", "1.2"]
	not is_object(object.get(c, "runtimeConfig", null))
}

_pf_ssmdc_steps(name) := s if {
	s := object.get(_pf_ssmdc_content(name), "mainSteps", null)
	is_array(s)
}

_pf_ssmdc_plugins := ["aws:applications", "aws:cloudWatch", "aws:configureDocker", "aws:configurePackage", "aws:domainJoin", "aws:downloadContent", "aws:psModule", "aws:refreshAssociation", "aws:runDockerAction", "aws:runDocument", "aws:runPowerShellScript", "aws:runShellScript", "aws:softwareInventory", "aws:updateAgent", "aws:updateSsmAgent"]

_pf_ssmdc_actions := ["aws:approve", "aws:assertAwsResourceProperty", "aws:branch", "aws:changeInstanceState", "aws:copyImage", "aws:createImage", "aws:createStack", "aws:createTags", "aws:deleteImage", "aws:deleteStack", "aws:executeAutomation", "aws:executeAwsApi", "aws:executeScript", "aws:executeStateMachine", "aws:invokeLambdaFunction", "aws:invokeWebhook", "aws:loop", "aws:pause", "aws:runCommand", "aws:runInstances", "aws:sleep", "aws:updateVariable", "aws:waitForAwsResourceProperty"]

_pf_ssmdc_known(name) := _pf_ssmdc_actions if _pf_ssmdc_type(name) in ["Automation", "Automation.ChangeTemplate"]

_pf_ssmdc_known(name) := _pf_ssmdc_plugins if _pf_ssmdc_type(name) in ["Command", "Policy"]

violation contains make_diag_full("pf-ssm-document-content", "ERROR", name,
	sprintf("Properties.Content.mainSteps.%d.%s", [i, k]),
	sprintf("step %d has no %s; CreateDocument fails with \"Missing \\\"%s\\\" in step detail.\"", [i, k, k]),
	_pf_ssmdc_fix, _pf_ssmdc_url) if {
	some name in resources_of_type("AWS::SSM::Document")
	some i, s in _pf_ssmdc_steps(name)
	is_object(s)
	some k in ["name", "action"]
	object.get(s, k, "__pf_absent") == "__pf_absent"
}

violation contains make_diag_full("pf-ssm-document-content", "ERROR", name,
	sprintf("Properties.Content.mainSteps.%d.name", [i]),
	sprintf("step name '%s' is not made of letters, digits and _; CreateDocument fails with \"StepName: %s is invalid.\"", [n, n]),
	_pf_ssmdc_fix, _pf_ssmdc_url) if {
	some name in resources_of_type("AWS::SSM::Document")
	some i, s in _pf_ssmdc_steps(name)
	is_object(s)
	n := object.get(s, "name", null)
	is_string(n)
	not regex.match("^[A-Za-z0-9_]+$", n)
}

violation contains make_diag_full("pf-ssm-document-content", "ERROR", name,
	sprintf("Properties.Content.mainSteps.%d.name", [i]),
	sprintf("step name '%s' is used more than once; CreateDocument fails with \"Duplicate step names found in mainSteps of the document.\"", [n]),
	_pf_ssmdc_fix, _pf_ssmdc_url) if {
	some name in resources_of_type("AWS::SSM::Document")
	steps := _pf_ssmdc_steps(name)
	some i, s in steps
	is_object(s)
	n := object.get(s, "name", null)
	is_string(n)
	some j, o in steps
	j < i
	is_object(o)
	object.get(o, "name", null) == n
}

violation contains make_diag_full("pf-ssm-document-content", "ERROR", name,
	sprintf("Properties.Content.mainSteps.%d.action", [i]),
	sprintf("'%s' is not a known %s step action; CreateDocument fails with \"Unknown plugin name: %s\" / \"Unknown action: %s\"", [a, _pf_ssmdc_type(name), a, a]),
	_pf_ssmdc_fix, _pf_ssmdc_url) if {
	some name in resources_of_type("AWS::SSM::Document")
	some i, s in _pf_ssmdc_steps(name)
	is_object(s)
	a := object.get(s, "action", null)
	is_string(a)
	known := _pf_ssmdc_known(name)
	not a in known
}

violation contains make_diag_full("pf-ssm-document-content", "ERROR", name,
	sprintf("Properties.Content.runtimeConfig.%s", [k]),
	sprintf("'%s' is not a known Command plugin; CreateDocument fails with \"Unknown plugin name: %s\"", [k, k]),
	_pf_ssmdc_fix, _pf_ssmdc_url) if {
	some name in resources_of_type("AWS::SSM::Document")
	rc := object.get(_pf_ssmdc_content(name), "runtimeConfig", null)
	is_object(rc)
	some k, _ in rc
	not k in _pf_ssmdc_plugins
}

# parameters
_pf_ssmdc_params(name) := p if {
	p := object.get(_pf_ssmdc_content(name), "parameters", null)
	is_object(p)
}

_pf_ssmdc_ptypes := ["String", "StringList", "Boolean", "Integer", "MapList", "StringMap"]

violation contains make_diag_full("pf-ssm-document-content", "ERROR", name,
	sprintf("Properties.Content.parameters.%s", [pn]),
	sprintf("parameter name '%s' is not alphanumeric (letters and digits only, no underscore); CreateDocument fails with \"Parameter name \\\"%s\\\" is not alpha-numeric.\"", [pn, pn]),
	_pf_ssmdc_fix, _pf_ssmdc_url) if {
	some name in resources_of_type("AWS::SSM::Document")
	some pn, _ in _pf_ssmdc_params(name)
	not regex.match("^[A-Za-z0-9]+$", pn)
}

violation contains make_diag_full("pf-ssm-document-content", "ERROR", name,
	sprintf("Properties.Content.parameters.%s.type", [pn]),
	sprintf("parameter '%s' has type '%v' (allowed: %s, case-sensitive); CreateDocument fails with \"Parameter type: %v is invalid.\" / \"Missing \\\"type\\\" in parameter definition.\"", [pn, t, concat("/", _pf_ssmdc_ptypes), t]),
	_pf_ssmdc_fix, _pf_ssmdc_url) if {
	some name in resources_of_type("AWS::SSM::Document")
	some pn, def in _pf_ssmdc_params(name)
	is_object(def)
	t := object.get(def, "type", "(missing)")
	not t in _pf_ssmdc_ptypes
}

violation contains make_diag_full("pf-ssm-document-content", "ERROR", name,
	sprintf("Properties.Content.parameters.%s.default", [pn]),
	sprintf("default '%v' is not a valid %s; CreateDocument fails with \"Wrong default value for a \\\"%s\\\" parameters\"", [d, t, t]),
	_pf_ssmdc_fix, _pf_ssmdc_url) if {
	some name in resources_of_type("AWS::SSM::Document")
	some pn, def in _pf_ssmdc_params(name)
	is_object(def)
	t := object.get(def, "type", "")
	d := object.get(def, "default", null)
	d != null
	not _pf_ssmdc_default_ok(t, d)
}

_pf_ssmdc_default_ok(t, _) if not t in ["Integer", "Boolean", "StringList"]

_pf_ssmdc_default_ok("Integer", d) if is_number(d)

_pf_ssmdc_default_ok("Integer", d) if {
	is_string(d)
	regex.match("^-?[0-9]+$", d)
}

_pf_ssmdc_default_ok("Boolean", d) if is_boolean(d)

_pf_ssmdc_default_ok("StringList", d) if is_array(d)

# {{ name }} references (plain identifiers only; ssm:, global: and step.Output forms have other characters)
violation contains make_diag_full("pf-ssm-document-content", "ERROR", name,
	"Properties.Content.mainSteps",
	sprintf("'{{ %s }}' refers to a parameter that is not declared; CreateDocument fails with \"Parameter \\\"%s\\\" is not declared.\"", [ref, ref]),
	_pf_ssmdc_fix, _pf_ssmdc_url) if {
	some name in resources_of_type("AWS::SSM::Document")
	steps := _pf_ssmdc_steps(name)
	text := json.marshal(steps)
	some m in regex.find_all_string_submatch_n("\\{\\{ *([A-Za-z0-9_]+) *\\}\\}", text, -1)
	ref := m[1]
	not _pf_ssmdc_declared(name, ref)
}

_pf_ssmdc_declared(name, ref) if _pf_ssmdc_params(name)[ref]

# Automation step links
_pf_ssmdc_names(name) := {n | some s in _pf_ssmdc_steps(name); is_object(s); n := object.get(s, "name", null); is_string(n)}

violation contains make_diag_full("pf-ssm-document-content", "ERROR", name,
	sprintf("Properties.Content.mainSteps.%d.%s", [i, k]),
	sprintf("%s points at step '%s', which does not exist; CreateDocument fails with \"Unknown step name: \\\"%s\\\" in %s\"", [k, target, target, k]),
	_pf_ssmdc_fix, _pf_ssmdc_url) if {
	some name in resources_of_type("AWS::SSM::Document")
	some i, s in _pf_ssmdc_steps(name)
	is_object(s)
	some k in ["nextStep", "onFailure", "onCancel"]
	v := object.get(s, k, null)
	is_string(v)
	target := trim_prefix(v, "step:")
	not target in ["Abort", "Continue"]
	not target in _pf_ssmdc_names(name)
}

violation contains make_diag_full("pf-ssm-document-content", "ERROR", name,
	sprintf("Properties.Content.mainSteps.%d.nextStep", [i]),
	"a step with isEnd: true cannot also have nextStep; CreateDocument fails with \"\\\"isEnd == true\\\" and nextStep should not exist in same step.\"",
	_pf_ssmdc_fix, _pf_ssmdc_url) if {
	some name in resources_of_type("AWS::SSM::Document")
	some i, s in _pf_ssmdc_steps(name)
	is_object(s)
	object.get(s, "isEnd", false) in {true, "true"}
	object.get(s, "nextStep", "__pf_absent") != "__pf_absent"
}

violation contains make_diag_full("pf-ssm-document-content", "ERROR", name,
	sprintf("Properties.Content.outputs.%d", [i]),
	sprintf("output '%s' names step '%s', which does not exist; CreateDocument fails with \"Unknown step name in named output: %s\"", [o, step, o]),
	_pf_ssmdc_fix, _pf_ssmdc_url) if {
	some name in resources_of_type("AWS::SSM::Document")
	outs := object.get(_pf_ssmdc_content(name), "outputs", null)
	is_array(outs)
	some i, o in outs
	is_string(o)
	step := split(o, ".")[0]
	not step in _pf_ssmdc_names(name)
}

violation contains make_diag_full("pf-ssm-document-content", "ERROR", name,
	sprintf("Properties.Content.mainSteps.%d.precondition", [i]),
	sprintf("platformType '%v' is not Linux, Windows or MacOS (case-sensitive); CreateDocument fails with \"Invalid precondition, unrecognized values [platformType, %v] encountered.\"", [v, v]),
	_pf_ssmdc_fix, _pf_ssmdc_url) if {
	some name in resources_of_type("AWS::SSM::Document")
	some i, s in _pf_ssmdc_steps(name)
	is_object(s)
	pc := object.get(s, "precondition", null)
	is_object(pc)
	eq := object.get(pc, "StringEquals", null)
	is_array(eq)
	count(eq) == 2
	eq[0] == "platformType"
	v := eq[1]
	not v in ["Linux", "Windows", "MacOS"]
}

# Session documents
_pf_ssmdc_session_types := ["Standard_Stream", "InteractiveCommands", "NonInteractiveCommands", "Port"]

violation contains make_diag_full("pf-ssm-document-content", "ERROR", name,
	"Properties.Content.sessionType",
	sprintf("sessionType '%v' is missing or not one of %s; CreateDocument fails with \"Missing SessionType in the document.\" / \"Invalid sessionType\"", [st, concat("/", _pf_ssmdc_session_types)]),
	_pf_ssmdc_fix, _pf_ssmdc_url) if {
	some name in resources_of_type("AWS::SSM::Document")
	_pf_ssmdc_type(name) == "Session"
	c := _pf_ssmdc_content(name)
	st := object.get(c, "sessionType", "(missing)")
	not st in _pf_ssmdc_session_types
}

violation contains make_diag_full("pf-ssm-document-content", "ERROR", name,
	"Properties.Content.properties",
	sprintf("sessionType %s needs a properties object; CreateDocument fails with \"Missing Properties in session type %s document\"", [st, st]),
	_pf_ssmdc_fix, _pf_ssmdc_url) if {
	some name in resources_of_type("AWS::SSM::Document")
	_pf_ssmdc_type(name) == "Session"
	c := _pf_ssmdc_content(name)
	st := object.get(c, "sessionType", null)
	st in ["InteractiveCommands", "NonInteractiveCommands", "Port"]
	not is_object(object.get(c, "properties", null))
}
