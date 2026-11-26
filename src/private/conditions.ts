/**
 * Which resources a template switches off with a `Condition` that is false
 * under the same values the engine resolves properties with (parameter
 * defaults and the stack's pseudo parameters).
 *
 * The engine resolves a property through a parameter default, but hands every
 * resource to the rules whatever its `Condition` says (issue #408), and walks both
 * branches of every `Fn::If`. A resource whose condition is false under those
 * defaults is never created, and a branch that is never taken is never deployed, so
 * a finding on either is a false positive by construction. Rules cannot see the raw
 * condition expressions (`input.conditions` only carries a lossy summary such as
 * `Not(Equals(?, ""))`), so the plugins evaluate them here, on the raw template, and
 * hand the engine the template specialized to what is proven (`specializeTemplate`).
 *
 * The evaluation is three-valued. Anything it cannot evaluate (a parameter
 * without a default, an unknown pseudo parameter, an intrinsic it does not
 * model) is `undefined`, and an undefined condition keeps the resource and the whole
 * `Fn::If` — the behaviour before this module existed. Only a proven condition
 * changes anything.
 */

/** What the stack's own environment says about the pseudo parameters. */
export interface PseudoValues {
  readonly region?: string;
  readonly accountId?: string;
}

type Value = string | number | boolean | Value[] | { [k: string]: unknown };

const UNKNOWN = Symbol('unknown');
type Maybe<T> = T | typeof UNKNOWN;

function partitionOf(region: string): { partition: string; urlSuffix: string } {
  if (region.startsWith('cn-')) return { partition: 'aws-cn', urlSuffix: 'amazonaws.com.cn' };
  if (region.startsWith('us-gov-')) return { partition: 'aws-us-gov', urlSuffix: 'amazonaws.com' };
  if (region.startsWith('us-iso-')) return { partition: 'aws-iso', urlSuffix: 'c2s.ic.gov' };
  if (region.startsWith('us-isob-')) return { partition: 'aws-iso-b', urlSuffix: 'sc2s.sgov.gov' };
  return { partition: 'aws', urlSuffix: 'amazonaws.com' };
}

const CONCRETE_REGION = /^[a-z]{2}(-[a-z]+)+-\d+$/;
const CONCRETE_ACCOUNT = /^\d{12}$/;

/** Parameter types whose value is a list (the `Ref` returns the split list). */
function isListParameter(type: unknown): boolean {
  return typeof type === 'string' && (type === 'CommaDelimitedList' || /^List</.test(type));
}

class Evaluator {
  private readonly conditionCache = new Map<string, Maybe<boolean>>();
  private readonly inProgress = new Set<string>();

  constructor(private readonly template: any, private readonly pseudo: PseudoValues) {}

  /** The value of a condition by name, or UNKNOWN. */
  public condition(name: string): Maybe<boolean> {
    if (this.conditionCache.has(name)) return this.conditionCache.get(name)!;
    const conditions = this.template?.Conditions;
    if (!conditions || typeof conditions !== 'object' || !(name in conditions)) return UNKNOWN;
    if (this.inProgress.has(name)) return UNKNOWN; // a cycle is the engine's problem, not ours
    this.inProgress.add(name);
    const out = this.bool(conditions[name]);
    this.inProgress.delete(name);
    this.conditionCache.set(name, out);
    return out;
  }

  private bool(expr: any): Maybe<boolean> {
    if (typeof expr === 'boolean') return expr;
    if (typeof expr === 'string') {
      if (expr === 'true') return true;
      if (expr === 'false') return false;
      return UNKNOWN;
    }
    if (!expr || typeof expr !== 'object' || Array.isArray(expr)) return UNKNOWN;
    const keys = Object.keys(expr);
    if (keys.length !== 1) return UNKNOWN;
    const [fn] = keys;
    const arg = expr[fn];
    switch (fn) {
      case 'Condition':
        return typeof arg === 'string' ? this.condition(arg) : UNKNOWN;
      case 'Fn::Not': {
        if (!Array.isArray(arg) || arg.length !== 1) return UNKNOWN;
        const v = this.bool(arg[0]);
        return v === UNKNOWN ? UNKNOWN : !v;
      }
      case 'Fn::And': {
        if (!Array.isArray(arg) || arg.length < 2) return UNKNOWN;
        const vs = arg.map((a) => this.bool(a));
        if (vs.some((v) => v === false)) return false;
        return vs.every((v) => v === true) ? true : UNKNOWN;
      }
      case 'Fn::Or': {
        if (!Array.isArray(arg) || arg.length < 2) return UNKNOWN;
        const vs = arg.map((a) => this.bool(a));
        if (vs.some((v) => v === true)) return true;
        return vs.every((v) => v === false) ? false : UNKNOWN;
      }
      case 'Fn::Equals': {
        if (!Array.isArray(arg) || arg.length !== 2) return UNKNOWN;
        const a = this.value(arg[0]);
        const b = this.value(arg[1]);
        if (a === UNKNOWN || b === UNKNOWN) return UNKNOWN;
        return scalarText(a) !== undefined && scalarText(b) !== undefined
          ? scalarText(a) === scalarText(b)
          : JSON.stringify(a) === JSON.stringify(b);
      }
      default:
        return UNKNOWN;
    }
  }

  /** The value an expression has under the defaults, or UNKNOWN. */
  private value(expr: any): Maybe<Value> {
    if (typeof expr === 'string' || typeof expr === 'number' || typeof expr === 'boolean') return expr;
    if (Array.isArray(expr)) {
      const out: Value[] = [];
      for (const e of expr) {
        const v = this.value(e);
        if (v === UNKNOWN) return UNKNOWN;
        out.push(v);
      }
      return out;
    }
    if (!expr || typeof expr !== 'object') return UNKNOWN;
    const keys = Object.keys(expr);
    if (keys.length !== 1) return UNKNOWN;
    const [fn] = keys;
    const arg = expr[fn];
    switch (fn) {
      case 'Ref':
        return typeof arg === 'string' ? this.ref(arg) : UNKNOWN;
      case 'Condition': {
        const v = this.condition(arg);
        return v === UNKNOWN ? UNKNOWN : v;
      }
      case 'Fn::Select': {
        if (!Array.isArray(arg) || arg.length !== 2) return UNKNOWN;
        const idx = this.value(arg[0]);
        const list = this.value(arg[1]);
        const i = typeof idx === 'number' ? idx : typeof idx === 'string' && /^\d+$/.test(idx) ? Number(idx) : NaN;
        if (!Array.isArray(list) || !Number.isInteger(i) || i < 0 || i >= list.length) return UNKNOWN;
        return list[i];
      }
      case 'Fn::Split': {
        if (!Array.isArray(arg) || arg.length !== 2 || typeof arg[0] !== 'string' || arg[0] === '') return UNKNOWN;
        const s = this.value(arg[1]);
        return typeof s === 'string' ? s.split(arg[0]) : UNKNOWN;
      }
      case 'Fn::Join': {
        if (!Array.isArray(arg) || arg.length !== 2 || typeof arg[0] !== 'string') return UNKNOWN;
        const parts = this.value(arg[1]);
        if (!Array.isArray(parts)) return UNKNOWN;
        const texts = parts.map(scalarText);
        return texts.every((t) => t !== undefined) ? texts.join(arg[0]) : UNKNOWN;
      }
      case 'Fn::FindInMap': {
        if (!Array.isArray(arg) || arg.length !== 3) return UNKNOWN;
        const [m, k1, k2] = arg.map((a) => this.value(a));
        if (typeof m !== 'string' || typeof k1 !== 'string' || typeof k2 !== 'string') return UNKNOWN;
        const v = this.template?.Mappings?.[m]?.[k1]?.[k2];
        return v === undefined ? UNKNOWN : (v as Value);
      }
      default:
        return UNKNOWN;
    }
  }

  private ref(name: string): Maybe<Value> {
    const { region, accountId } = this.pseudo;
    switch (name) {
      case 'AWS::Region':
        return region && CONCRETE_REGION.test(region) ? region : UNKNOWN;
      case 'AWS::AccountId':
        return accountId && CONCRETE_ACCOUNT.test(accountId) ? accountId : UNKNOWN;
      case 'AWS::Partition':
        return region && CONCRETE_REGION.test(region) ? partitionOf(region).partition : UNKNOWN;
      case 'AWS::URLSuffix':
        return region && CONCRETE_REGION.test(region) ? partitionOf(region).urlSuffix : UNKNOWN;
      default:
        break;
    }
    const p = this.template?.Parameters?.[name];
    if (!p || typeof p !== 'object' || !('Default' in p)) return UNKNOWN;
    // An SSM parameter type resolves to the stored value, not to the default (which is the parameter name).
    if (typeof p.Type === 'string' && p.Type.startsWith('AWS::SSM::Parameter::Value<')) return UNKNOWN;
    const d = p.Default;
    if (isListParameter(p.Type)) {
      if (Array.isArray(d)) return d.map(String);
      return typeof d === 'string' ? d.split(',') : UNKNOWN;
    }
    if (typeof d === 'string' || typeof d === 'number' || typeof d === 'boolean') return String(d);
    return UNKNOWN;
  }
}

function scalarText(v: Value): string | undefined {
  if (typeof v === 'string') return v;
  if (typeof v === 'number' || typeof v === 'boolean') return String(v);
  return undefined;
}

/**
 * Logical IDs of the resources whose `Condition` is proven false.
 * A template that is not an object, or has no conditional resources, gives an empty set.
 */
export function inactiveResources(template: unknown, pseudo: PseudoValues = {}): Set<string> {
  const out = new Set<string>();
  const t = template as any;
  const resources = t?.Resources;
  if (!resources || typeof resources !== 'object') return out;
  const ev = new Evaluator(t, pseudo);
  for (const [id, r] of Object.entries<any>(resources)) {
    const name = r?.Condition;
    if (typeof name === 'string' && ev.condition(name) === false) out.add(id);
  }
  return out;
}

const NO_VALUE = Symbol('no-value');

/**
 * The template as it is deployed under the defaults, as far as that is proven:
 *
 *   - resources (and outputs) whose `Condition` is proven false are removed, and so are
 *     `DependsOn` entries that point at a removed resource;
 *   - an `Fn::If` whose condition is proven is replaced by the branch that is taken, and a taken
 *     `{"Ref": "AWS::NoValue"}` removes the property (or list element) altogether;
 *   - a parameter of an SSM type loses its `Default` (the parameter name, not its value).
 *
 * The engine walks both branches of an `Fn::If` (a value in the branch that is never taken still
 * fires a rule), and it hands every resource to the rules whatever its `Condition` says (#408). A
 * reference from a live resource to a removed one can only sit in a branch that is not taken
 * (CloudFormation rejects it anywhere else), so it goes away with the branch.
 *
 * Anything undecided is left exactly as it was. Returns undefined when nothing changes.
 */
export function specializeTemplate(template: unknown, pseudo: PseudoValues = {}): unknown | undefined {
  const t = template as any;
  if (!t || typeof t !== 'object' || !t.Resources || typeof t.Resources !== 'object') return undefined;
  const ev = new Evaluator(t, pseudo);
  let changed = false;
  const walk = (node: any): any => {
    if (Array.isArray(node)) {
      const out: any[] = [];
      for (const e of node) {
        const v = walk(e);
        if (v !== NO_VALUE) out.push(v);
      }
      return out;
    }
    if (!node || typeof node !== 'object') return node;
    const keys = Object.keys(node);
    if (keys.length === 1 && keys[0] === 'Fn::If' && Array.isArray(node['Fn::If']) && node['Fn::If'].length === 3
      && typeof node['Fn::If'][0] === 'string') {
      const c = ev.condition(node['Fn::If'][0]);
      if (c !== UNKNOWN) {
        changed = true;
        const taken = node['Fn::If'][c ? 1 : 2];
        if (taken && typeof taken === 'object' && !Array.isArray(taken) && Object.keys(taken).length === 1 && taken.Ref === 'AWS::NoValue') return NO_VALUE;
        return walk(taken);
      }
    }
    const out: Record<string, unknown> = {};
    for (const k of keys) {
      const v = walk(node[k]);
      if (v !== NO_VALUE) out[k] = v;
    }
    return out;
  };
  const off = (x: any) => typeof x?.Condition === 'string' && ev.condition(x.Condition) === false;
  const resources: Record<string, unknown> = {};
  const removed = new Set<string>();
  for (const [id, r] of Object.entries<any>(t.Resources)) {
    if (off(r)) removed.add(id);
  }
  if (removed.size) changed = true;
  for (const [id, r] of Object.entries<any>(t.Resources)) {
    if (removed.has(id)) continue;
    let res = r && typeof r === 'object' ? { ...r } : r;
    if (res && typeof res === 'object') {
      for (const k of ['Properties', 'Metadata', 'UpdatePolicy', 'CreationPolicy']) {
        if (k in res) {
          const v = walk(res[k]);
          if (v === NO_VALUE) delete res[k];
          else res[k] = v;
        }
      }
      const dep = res.DependsOn;
      if (typeof dep === 'string' && removed.has(dep)) delete res.DependsOn;
      else if (Array.isArray(dep) && dep.some((d) => removed.has(d))) res.DependsOn = dep.filter((d) => !removed.has(d));
    }
    resources[id] = res;
  }
  const out: any = { ...t, Resources: resources };
  // A parameter of an SSM type resolves to the value stored under that name, but the engine
  // resolves its Default, which is the parameter *name* ("/aws/service/ami-..."): rules then judge
  // a path as if it were the value. Without the Default the reference stays unresolved.
  if (t.Parameters && typeof t.Parameters === 'object') {
    const params: Record<string, unknown> = {};
    for (const [id, p] of Object.entries<any>(t.Parameters)) {
      if (p && typeof p === 'object' && typeof p.Type === 'string' && p.Type.startsWith('AWS::SSM::Parameter::Value<') && 'Default' in p) {
        const { Default: _drop, ...rest } = p;
        params[id] = rest;
        changed = true;
      } else {
        params[id] = p;
      }
    }
    out.Parameters = params;
  }
  if (t.Outputs && typeof t.Outputs === 'object') {
    const outputs: Record<string, unknown> = {};
    for (const [id, o] of Object.entries<any>(t.Outputs)) {
      if (off(o)) {
        changed = true;
        continue;
      }
      const v = walk(o);
      if (v !== NO_VALUE) outputs[id] = v;
    }
    out.Outputs = outputs;
  }
  return changed ? out : undefined;
}

/**
 * specializeTemplate on a file. Writes the specialized template next to a temp dir and returns its
 * path, or undefined when the template is unreadable or nothing changes (then validate the original).
 */
export function specializeTemplateFile(templatePath: string, pseudo: PseudoValues, tmpDir: string): string | undefined {
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const fs = require('fs') as typeof import('fs');
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const path = require('path') as typeof import('path');
    const out = specializeTemplate(JSON.parse(fs.readFileSync(templatePath, 'utf8')), pseudo);
    if (out === undefined) return undefined;
    const file = path.join(tmpDir, `${fs.readdirSync(tmpDir).length}-${path.basename(templatePath)}`);
    fs.writeFileSync(file, JSON.stringify(out));
    return file;
  } catch {
    return undefined;
  }
}
