package cdk_preflight

import rego.v1

# Judged only when DeferMaintenance is literally true (the branch where the handler
# calls ModifyClusterMaintenance after CreateCluster).
violation contains make_diag_full("pf-redshift-defer-maintenance-duration-max", "ERROR", name,
	"Properties.DeferMaintenanceDuration",
	sprintf("DeferMaintenanceDuration %v exceeds 60 days; ModifyClusterMaintenance rejects it after the cluster is created (\"The duration must be 60 days or less.\")", [n]),
	"Defer maintenance for 60 days or less, or set DeferMaintenanceEndTime instead",
	"https://docs.aws.amazon.com/redshift/latest/APIReference/API_ModifyClusterMaintenance.html") if {
	some name in resources_of_type("AWS::Redshift::Cluster")
	_pf_redshiftlib_true(name, "DeferMaintenance")
	n := _pf_redshiftlib_num(name, "DeferMaintenanceDuration")
	n > 60
}
