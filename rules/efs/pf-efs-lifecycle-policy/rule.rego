package cdk_preflight

import rego.v1

_pf_efslc_url := "https://docs.aws.amazon.com/efs/latest/APIReference/API_PutLifecycleConfiguration.html"

_pf_efslc_fix := "Write one object per transition — [{\"TransitionToIA\":\"AFTER_30_DAYS\"},{\"TransitionToArchive\":\"AFTER_90_DAYS\"}] — keep Archive later than IA, and use ThroughputMode elastic or provisioned when you archive"

_pf_efslc_keys := {"TransitionToIA", "TransitionToArchive", "TransitionToPrimaryStorageClass"}

_pf_efslc_days := {
	"AFTER_1_DAY": 1,
	"AFTER_7_DAYS": 7,
	"AFTER_14_DAYS": 14,
	"AFTER_30_DAYS": 30,
	"AFTER_60_DAYS": 60,
	"AFTER_90_DAYS": 90,
	"AFTER_180_DAYS": 180,
	"AFTER_270_DAYS": 270,
	"AFTER_365_DAYS": 365,
}

_pf_efslc_policies(name) := p if {
	p := resolve(name, "Properties.LifecyclePolicies")
	is_array(p)
}

# [file system, index, transition key, value] of every policy entry.
_pf_efslc_entries contains [name, i, key, v] if {
	some name in resources_of_type("AWS::EFS::FileSystem")
	some i, p in _pf_efslc_policies(name)
	is_object(p)
	some key, v in p
	key in _pf_efslc_keys
}

violation contains make_diag_full("pf-efs-lifecycle-policy", "ERROR", name,
	sprintf("Properties.LifecyclePolicies[%d]", [i]),
	sprintf("this LifecyclePolicy object holds %d transitions; PutLifecycleConfiguration wants one object per transition and fails with \"One or more LifecyclePolicy objects specified are malformed.\"", [count(p)]),
	_pf_efslc_fix, _pf_efslc_url) if {
	some name in resources_of_type("AWS::EFS::FileSystem")
	some i, p in _pf_efslc_policies(name)
	is_object(p)
	count(p) > 1
}

violation contains make_diag_full("pf-efs-lifecycle-policy", "ERROR", name,
	sprintf("Properties.LifecyclePolicies[%d].%s", [i, key]),
	sprintf("%s is set by more than one LifecyclePolicy object; PutLifecycleConfiguration fails with \"Duplicate LifecyclePolicy transition types are not allowed.\"", [key]),
	_pf_efslc_fix, _pf_efslc_url) if {
	some [name, i, key, _] in _pf_efslc_entries
	some [n2, j, k2, _] in _pf_efslc_entries
	n2 == name
	k2 == key
	j != i
}

violation contains make_diag_full("pf-efs-lifecycle-policy", "ERROR", name,
	sprintf("Properties.LifecyclePolicies[%d].TransitionToArchive", [i]),
	sprintf("TransitionToArchive (%s) is not later than TransitionToIA (%s); PutLifecycleConfiguration fails with \"The value for TransitionToArchive is the same as or less than the value for TransitionToIA.\"", [av, iv]),
	_pf_efslc_fix, _pf_efslc_url) if {
	some [name, i, "TransitionToArchive", av] in _pf_efslc_entries
	some [n2, _, "TransitionToIA", iv] in _pf_efslc_entries
	n2 == name
	_pf_efslc_days[av] <= _pf_efslc_days[iv]
}

# Archive storage needs Elastic or Provisioned throughput; Bursting is the
# CloudFormation default, so an archive policy on a plain file system fails.
violation contains make_diag_full("pf-efs-lifecycle-policy", "ERROR", name,
	sprintf("Properties.LifecyclePolicies[%d].TransitionToArchive", [i]),
	sprintf("TransitionToArchive is set but ThroughputMode is %s; PutLifecycleConfiguration fails with \"The ThroughputMode value for the file system does not support TransitionToArchive. Either change the ThroughputMode value to Elastic or Provisioned\"", [mode]),
	_pf_efslc_fix, _pf_efslc_url) if {
	some [name, i, "TransitionToArchive", _] in _pf_efslc_entries
	mode := _pf_efslc_mode(name)
	not mode in {"elastic", "provisioned"}
}

_pf_efslc_mode(name) := m if {
	m := resolve(name, "Properties.ThroughputMode")
	is_string(m)
}

_pf_efslc_mode(name) := "bursting" if _pf_efslib_absent(name, "ThroughputMode")
