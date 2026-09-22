package cdk_preflight

import rego.v1

# 日次のバックアップ窓と週次のメンテナンス窓は、時刻の区間が交われば重なる。見るのは
# 両窓が整形式で日付をまたがず、メンテナンス窓が同じ曜日で閉じる形だけ（under-claim）。
violation contains make_diag_full("pf-neptune-backup-maintenance-overlap", "ERROR", name,
	"Properties.PreferredBackupWindow",
	sprintf("PreferredBackupWindow %s overlaps PreferredMaintenanceWindow %s; Neptune rejects the pair (\"The backup window and maintenance window must not overlap.\")", [bw, mw]),
	"Separate the two windows in time",
	"https://docs.aws.amazon.com/neptune/latest/userguide/api-clusters.html") if {
	some name in resources_of_type("AWS::Neptune::DBCluster")
	bw := resolve(name, "Properties.PreferredBackupWindow")
	bs := _pf_neptunelib_wstart(bw)
	be := _pf_neptunelib_wend(bw)
	bs < be
	mw := resolve(name, "Properties.PreferredMaintenanceWindow")
	is_string(mw)
	mp := split(lower(mw), "-")
	count(mp) == 2
	m1 := split(mp[0], ":")
	m2 := split(mp[1], ":")
	count(m1) == 3
	count(m2) == 3
	m1[0] == m2[0]
	ms := _pf_neptunelib_hhmm(sprintf("%s:%s", [m1[1], m1[2]]))
	me := _pf_neptunelib_hhmm(sprintf("%s:%s", [m2[1], m2[2]]))
	ms < me
	bs < me
	ms < be
}
