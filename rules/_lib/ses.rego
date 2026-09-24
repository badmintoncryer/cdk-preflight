package cdk_preflight

import rego.v1

# Amazon SES v2 (AWS::SES::*) のルールで共有するヘルパー。診断は出さない。

# ユーザーが書いたリテラル文字列だけを通す。Ref / Fn::GetAtt はマーカー（resolve() が
# 論理 ID を返す）、`{{resolve:secretsmanager:...}}` は CloudFormation が実行時に解く
# 動的参照で、どちらも中身を検査できない。後者を通すと DKIM の秘密鍵を Secrets Manager
# 経由で渡す正しい書き方にルールが鳴る。
_pf_ses_lit(s) if {
	is_string(s)
	not input.resources[s]
	not startswith(s, "{{resolve:")
}

_pf_ses_arn_part(arn, i) := v if {
	is_string(arn)
	p := split(arn, ":")
	count(p) >= 6
	p[0] == "arn"
	v := p[i]
	v != ""
}

_pf_ses_arn_region(arn) := _pf_ses_arn_part(arn, 3)

# DkimSigningAttributes は Easy DKIM（NextSigningKeyLength）と BYODKIM
# （DomainSigningSelector + DomainSigningPrivateKey）の 2 系統が 1 つのオブジェクトに
# 同居している。どちらを書いたかは「キーが在るか」で決まるので、値ではなく存在を見る。
_pf_ses_dkim(name) := o if {
	o := resolve(name, "Properties.DkimSigningAttributes")
	is_object(o)
}

_pf_ses_dkim_set(name, k) if object.get(_pf_ses_dkim(name), k, "__pf_absent") != "__pf_absent"

_pf_ses_byodkim_keys := ["DomainSigningSelector", "DomainSigningPrivateKey"]

_pf_ses_byodkim(name) if {
	some k in _pf_ses_byodkim_keys
	_pf_ses_dkim_set(name, k)
}

# イベント宛先は 4 つの名前つきプロパティのうちどれか 1 つ。
_pf_ses_dest_keys := ["CloudWatchDestination", "EventBridgeDestination", "KinesisFirehoseDestination", "SnsDestination"]

_pf_ses_ed(name) := o if {
	o := resolve(name, "Properties.EventDestination")
	is_object(o)
}

_pf_ses_ed_has(name, k) if object.get(_pf_ses_ed(name), k, "__pf_absent") != "__pf_absent"

_pf_ses_ed_any(name) if {
	some k in _pf_ses_dest_keys
	_pf_ses_ed_has(name, k)
}

_pf_ses_ed_has_other(name, k) if {
	some o in _pf_ses_dest_keys
	o != k
	_pf_ses_ed_has(name, o)
}

_pf_ses_event_types := {
	"SEND", "REJECT", "BOUNCE", "COMPLAINT", "DELIVERY", "OPEN", "CLICK",
	"RENDERING_FAILURE", "DELIVERY_DELAY", "SUBSCRIPTION",
}

# --- #70 C2: SES 受信系（ReceiptRule / ReceiptRuleSet）--------------------------
# ReceiptRule.Rule.Actions の 1 要素が名乗れるアクションの種類。
_pf_sesrx_action_keys := {
	"AddHeaderAction", "BounceAction", "ConnectAction", "LambdaAction",
	"S3Action", "SNSAction", "StopAction", "WorkmailAction",
}

# intrinsic はマーカーオブジェクトで届く: Ref / Fn::GetAtt は `__kind`、解けない参照や
# 動的参照は `__dynamic`、Fn::If は `__conditional` + `__if_true` / `__if_false`
# （実測 2026-09-24）。接頭辞で見るので、将来マーカーが増えても取りこぼさない。
_pf_sesrx_marker(v) if {
	some k in object.keys(v)
	startswith(k, "__")
}

# Actions は前処理済みドキュメントの生の配列で読む。flatten_list() は Fn::If を真の枝に
# 潰して返すので（実測 2026-09-24）、デプロイ時に AWS::NoValue へ落ちて消える要素まで
# 「在る」ように見え、個数を数えるとそのぶん誤検出する。
_pf_sesrx_actions(name) := a if {
	props := object.get(input.resources[name], "properties", {})
	a := object.get(object.get(props, "Rule", {}), "Actions", [])
	is_array(a)
}

# 要素が実際に持っているアクション種別。条件付きで消えうるものは数に入れない。
_pf_sesrx_named(o) := {k |
	some k in _pf_sesrx_action_keys
	v := object.get(o, k, null)
	is_object(v)
	not _pf_sesrx_marker(v)
}

# Actions の中の BounceAction を、要素の添字つきで返す（診断のパスに添字を出すため）。
_pf_sesrx_bounce(name) := [[i, b] |
	some i, e in _pf_sesrx_actions(name)
	is_object(e)
	b := object.get(e, "BounceAction", null)
	is_object(b)
	not _pf_sesrx_marker(b)
]
