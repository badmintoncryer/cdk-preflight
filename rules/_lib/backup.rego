package cdk_preflight

import rego.v1

# AWS Backup (AWS::Backup::*) のルールで共有するヘルパー。診断は出さない。
# しきい値はここに置かない — 境界チェッカ (scripts/bundle-rules.ts#boundaryProblem) は
# rule.rego しか読まないので、_lib に書いた定数はフィクスチャと突き合わされない。
# 節: (1) 生プロパティ (2) BackupPlan の走査 (3) BackupSelection (4) 名前の文字種 (5) ARN

# --- (1) 生プロパティ -------------------------------------------------------
# 生の properties を読むので Ref / Fn::GetAtt はマーカー（{"__kind","__ref"}）のまま残り、
# is_string / is_number ガードがユーザーの書いたリテラルだけを通す。
_pf_bklib_props(name) := p if {
	p := object.get(input.resources[name], "properties", {})
	is_object(p)
}

_pf_bklib_get(o, k) := v if {
	is_object(o)
	v := object.get(o, k, "__pf_absent")
	v != "__pf_absent"
}

_pf_bklib_str(o, k) := v if {
	v := _pf_bklib_get(o, k)
	is_string(v)
}

# to_number はマーカー（オブジェクト）に対して undefined なので、これがリテラル数値の
# ガードを兼ねる。数値文字列（"59"）も拾う。
_pf_bklib_num(o, k) := n if {
	n := to_number(_pf_bklib_get(o, k))
}

# --- (2) BackupPlan の走査 --------------------------------------------------
# BackupPlanRule[] を flatten_list と同じ {index, value} の形で返す。
_pf_bklib_plan_rules(name) := flatten_list(name, "Properties.BackupPlan.BackupPlanRule")

# ルール i の CopyActions[]（同上）。
_pf_bklib_copy_actions(name, i) := flatten_list(name, sprintf("Properties.BackupPlan.BackupPlanRule.%d.CopyActions", [i]))

# BackupRule / CopyAction の Lifecycle（オブジェクトのときだけ）。
_pf_bklib_lifecycle(o) := lc if {
	lc := _pf_bklib_get(o, "Lifecycle")
	is_object(lc)
}

# --- (3) BackupSelection ----------------------------------------------------
_pf_bklib_selection(name) := s if {
	s := _pf_bklib_get(_pf_bklib_props(name), "BackupSelection")
	is_object(s)
}

# --- (4) 名前の文字種 -------------------------------------------------------
# BackupPlanName / RuleName: 英数字と - _ . （BackupVaultName はピリオド不可だが
# エンジンが F3031 で持っているのでルールにしない）。
_pf_bklib_dot_dash_name(s) if regex.match(`^[A-Za-z0-9._-]+$`, s)

# FrameworkName / ReportPlanName / RestoreTestingPlanName / RestoreTestingSelectionName:
# 英数字とアンダースコアだけでハイフン不可。スライス C3-2 のための置き場（未使用）。
_pf_bklib_underscore_name(s) if regex.match(`^[A-Za-z0-9_]+$`, s)

# --- (5) ARN ----------------------------------------------------------------
# arn:<partition>:backup:<region>:<account>:<type>:<name> を分解する。
# parts[3] = リージョン / parts[4] = アカウント / parts[5] = リソース種別。
_pf_bklib_backup_arn(s) := parts if {
	parts := split(s, ":")
	count(parts) >= 6
	parts[0] == "arn"
	parts[2] == "backup"
}
