package cdk_preflight

import rego.v1

# Shared helpers for the CodePipeline rules: traversal of the raw document
# (resolve() cannot prove a key absent, and the stage/action nesting is deeper
# than a dotted path can iterate) plus the two provider tables the action rules
# read. Loaded ahead of every rule (BUNDLED_LIBS); never emits diagnostics.

# A user-written literal, not a Ref/GetAtt that resolve() turned into a logical id.
_pf_cplib_lit(v) if {
	is_string(v)
	not input.resources[v]
}

# A plain object, not an intrinsic that the preprocessor turned into a marker.
_pf_cplib_plain(o) if {
	is_object(o)
	object.get(o, "__kind", "_") == "_"
	object.get(o, "__ref", "_") == "_"
	object.get(o, "__dynamic", "_") == "_"
}

_pf_cplib_props(name) := p if {
	p := input.resources[name].properties
	is_object(p)
}

_pf_cplib_absent(o, k) if {
	is_object(o)
	object.get(o, k, "__pf_absent") == "__pf_absent"
}

# object.get() with a default cannot tell "absent" from "written as that value",
# and an absent key defaulting to "" reads as a user literal. Every rule that
# judges a value the user wrote reads it through here instead.
_pf_cplib_get(o, k) := v if {
	is_object(o)
	not _pf_cplib_absent(o, k)
	v := object.get(o, k, null)
}

# Stages / Actions read from the preprocessed document. An absent list reads as
# empty so the callers only have to guard the shapes they actually compare.
_pf_cplib_stages(name) := s if {
	s := object.get(_pf_cplib_props(name), "Stages", [])
	is_array(s)
}

_pf_cplib_actions(stage) := a if {
	_pf_cplib_plain(stage)
	a := object.get(stage, "Actions", [])
	is_array(a)
}

_pf_cplib_tid(action) := t if {
	_pf_cplib_plain(action)
	t := object.get(action, "ActionTypeId", {})
	_pf_cplib_plain(t)
}

_pf_cplib_category(action) := c if {
	c := _pf_cplib_get(_pf_cplib_tid(action), "Category")
	_pf_cplib_lit(c)
}

# The action categories each AWS-owned provider is published under.
# Source: "Valid action providers in CodePipeline" (userguide/actions-valid-providers.html).
# A provider missing from this table is never judged, so a newly published
# provider costs a miss rather than a false positive.
_pf_cplib_aws_providers := {
	"S3": {"Source", "Deploy"},
	"ECR": {"Source"},
	"CodeCommit": {"Source"},
	"CodeStarSourceConnection": {"Source"},
	"CodeBuild": {"Build", "Test"},
	"ECRBuildAndPublish": {"Build"},
	"Commands": {"Compute", "Build"},
	"DeviceFarm": {"Test"},
	"CloudFormation": {"Deploy"},
	"CloudFormationStackSet": {"Deploy"},
	"CloudFormationStackInstances": {"Deploy"},
	"CodeDeploy": {"Deploy"},
	"CodeDeployToECS": {"Deploy"},
	"EC2": {"Deploy"},
	"ECS": {"Deploy"},
	"EKS": {"Deploy"},
	"ElasticBeanstalk": {"Deploy"},
	"AppConfig": {"Deploy"},
	"OpsWorks": {"Deploy"},
	"ServiceCatalog": {"Deploy"},
	"Manual": {"Approval"},
	"CodePipeline": {"Invoke"},
	"Lambda": {"Invoke", "Deploy"},
	"StepFunctions": {"Invoke"},
	"InspectorScan": {"Invoke"},
}

# Configuration keys each AWS-owned action provider requires, keyed
# "<Category>/<Provider>". Every entry was confirmed against CreatePipeline
# (api-probe 2026-09-14 us-east-1: dropping the key returns "Action
# configuration for action 'X' is missing required configuration '<key>'").
_pf_cplib_required_config := {
	"Source/S3": {"S3Bucket", "S3ObjectKey"},
	"Source/ECR": {"RepositoryName"},
	"Source/CodeCommit": {"RepositoryName", "BranchName"},
	"Deploy/S3": {"BucketName", "Extract"},
	"Deploy/CodeDeploy": {"ApplicationName", "DeploymentGroupName"},
	"Deploy/CloudFormation": {"ActionMode", "StackName"},
	"Deploy/ECS": {"ClusterName", "ServiceName"},
	"Deploy/ElasticBeanstalk": {"ApplicationName", "EnvironmentName"},
	"Build/CodeBuild": {"ProjectName"},
	"Test/CodeBuild": {"ProjectName"},
	"Invoke/Lambda": {"FunctionName"},
	"Invoke/StepFunctions": {"StateMachineArn"},
	"Invoke/CodePipeline": {"PipelineName"},
}

# The two artifact-store enums. The singular ArtifactStore and one entry of the
# cross-region ArtifactStores list nest the store under the same key, so both
# rules take the parent object and read through it.
_pf_cplib_storetype(parent) := v if {
	s := _pf_cplib_get(parent, "ArtifactStore")
	_pf_cplib_plain(s)
	v := _pf_cplib_get(s, "Type")
	_pf_cplib_lit(v)
}

_pf_cplib_storekeytype(parent) := v if {
	s := _pf_cplib_get(parent, "ArtifactStore")
	_pf_cplib_plain(s)
	k := _pf_cplib_get(s, "EncryptionKey")
	_pf_cplib_plain(k)
	v := _pf_cplib_get(k, "Type")
	_pf_cplib_lit(v)
}

# A queryable configuration property must be required and non-secret; the
# service reports both halves as one check.
_pf_cplib_queryable_ok(secret, required) if {
	secret == false
	required == true
}
