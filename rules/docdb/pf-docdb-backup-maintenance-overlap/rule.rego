package cdk_preflight

import rego.v1

# The backup window recurs daily, so a same-day maintenance window overlaps whenever the
# time-of-day intervals intersect. Claim scope: both windows well-formed, neither wrapping
# midnight, maintenance window on a single day (other shapes stay silent, under-claim).
violation contains make_diag_full("pf-docdb-backup-maintenance-overlap", "ERROR", name,
	"Properties.PreferredBackupWindow",
	sprintf("Backup window %s overlaps maintenance window %s; DocumentDB rejects the pair (\"The backup window and maintenance window must not overlap.\")", [bw, mw]),
	"Separate the two windows in time",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbcluster.html") if {
	some name in _pf_docdb_clusters
	bw := _pf_docdb_lit(name, "Properties.PreferredBackupWindow")
	bp := split(bw, "-")
	count(bp) == 2
	bs := _pf_docdb_hm(bp[0])
	be := _pf_docdb_hm(bp[1])
	bs < be
	mw := _pf_docdb_lit(name, "Properties.PreferredMaintenanceWindow")
	mp := split(lower(mw), "-")
	count(mp) == 2
	m1 := split(mp[0], ":")
	m2 := split(mp[1], ":")
	count(m1) == 3
	count(m2) == 3
	m1[0] == m2[0]
	ms := _pf_docdb_hm(sprintf("%s:%s", [m1[1], m1[2]]))
	me := _pf_docdb_hm(sprintf("%s:%s", [m2[1], m2[2]]))
	ms < me
	bs < me
	ms < be
}
