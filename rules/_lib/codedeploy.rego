package cdk_preflight

import rego.v1

# Shared helpers for the CodeDeploy rules: traversal of the raw document
# (resolve() cannot prove a key absent), literal/number guards, and the compute
# platform that decides which half of a deployment configuration is legal.
# Loaded ahead of every rule (BUNDLED_LIBS); never emits diagnostics.

# A user-written literal, not a Ref/GetAtt that resolve() turned into a logical id.
_pf_codedeploylib_lit(v) if {
	is_string(v)
	not input.resources[v]
}

# Raw properties of a resource. The preprocessed document is the only place
# where "the key is absent" can be told apart from "the value is a token".
_pf_codedeploylib_props(name) := p if {
	p := input.resources[name].properties
	is_object(p)
}

_pf_codedeploylib_has(o, k) if {
	is_object(o)
	object.get(o, k, "__pf_absent") != "__pf_absent"
}

_pf_codedeploylib_obj(o, k) := v if {
	is_object(o)
	v := object.get(o, k, null)
	is_object(v)
}

# A number written as a literal - a JSON number, or the string CloudFormation
# also accepts for a numeric property. A Ref and an absent key both yield
# nothing, so a caller checking a lower bound is not fooled by to_number(null),
# which is 0.
_pf_codedeploylib_num(v) := v if is_number(v)

_pf_codedeploylib_num(v) := n if {
	is_string(v)
	regex.match(`^-?[0-9]+$`, v)
	n := to_number(v)
}

# ComputePlatform of a resource that carries its own - AWS::CodeDeploy::Application
# and AWS::CodeDeploy::DeploymentConfig. An absent property is Server: the
# service applies that default and then enforces the Server rules against it
# (measured 2026-09-14 us-east-1: CreateDeploymentConfig with no computePlatform
# and a trafficRoutingConfig fails with "should be null for Server deployment
# configuration"). A Ref or token yields nothing, so a rule built on this helper
# stays silent rather than guessing.
#
# A deployment group does NOT carry one: its platform comes from the application
# it names, which is a cross-resource hop this helper deliberately does not make.
_pf_codedeploylib_platform(name) := p if {
	p := resolve(name, "Properties.ComputePlatform")
	_pf_codedeploylib_lit(p)
}

_pf_codedeploylib_platform(name) := "Server" if {
	not _pf_codedeploylib_has(_pf_codedeploylib_props(name), "ComputePlatform")
}


# Compute platform of a deployment group. It carries none of its own: the platform
# is the one on the AWS::CodeDeploy::Application that ApplicationName points at.
# Only a Ref to an application in the same template can answer - a literal name
# refers to an application created elsewhere, whose platform the template does not
# know, so the helper yields nothing and every rule built on it stays silent
# rather than assuming Server.
_pf_codedeploylib_dg_platform(name) := p if {
	a := resolve(name, "Properties.ApplicationName")
	input.resources[a].resourceType == "AWS::CodeDeploy::Application"
	p := _pf_codedeploylib_platform(a)
}
