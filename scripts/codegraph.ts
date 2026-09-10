/**
 * =====================================================================
 *   CODEGRAPH - Générateur du graphe de dépendances d'OCTUPUS
 * =====================================================================
 *   Parcourt le code source (app/ · components/ · lib/ · scripts/ · racine),
 *   extrait les imports/exports (alias "@/" et relatifs, import() dynamique,
 *   require(), re-exports) et émet public/codegraph.json — le contrat est
 *   défini dans lib/codegraph-types.ts.
 *
 *   Usage :  bun run codegraph          (depuis next-app/)
 *
 *   Le graphe sert à comprendre le projet SANS lire chaque fichier :
 *   chaque nœud = fichier, chaque arête = dépendance d'import.
 * =====================================================================
 */
import ts from "typescript";
import { existsSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { basename, dirname, join, relative, posix } from "node:path";
import type {
  CodeGraphData,
  CodeGraphEdge,
  CodeGraphFile,
  CodeGraphGroup,
  CodeGraphKind,
} from "../lib/codegraph-types";

const ROOT = process.cwd();
const OUT = join(ROOT, "public", "codegraph.json");

const SOURCE_EXTS = [".ts", ".tsx", ".js", ".jsx", ".mts", ".cts"];
const SKIP_DIRS = new Set(["node_modules", ".next", "public", ".git", ".vscode", ".vercel"]);
const SKIP_FILES = new Set(["next-env.d.ts"]);

// --------------------------------------------------------------- parcours
function walk(dir: string, acc: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    if (SKIP_DIRS.has(entry)) continue;
    const full = join(dir, entry);
    const st = statSync(full);
    if (st.isDirectory()) walk(full, acc);
    else if (SOURCE_EXTS.some((e) => entry.endsWith(e)) && !SKIP_FILES.has(entry)) acc.push(full);
  }
  return acc;
}

function toId(abs: string): string {
  return posix.normalize(relative(ROOT, abs).split("\\").join("/"));
}

function kindOf(id: string): CodeGraphKind {
  if (id.startsWith("app/api/")) return "api";
  if (id.startsWith("app/")) {
    const b = basename(id).toLowerCase();
    if (b.startsWith("page")) return "page";
    if (b.startsWith("layout")) return "layout";
    if (b.startsWith("route")) return "api";
    return "other";
  }
  if (id.startsWith("components/ui/")) return "ui";
  if (id.startsWith("components/")) return "component";
  if (id.startsWith("lib/")) return "lib";
  if (id.startsWith("scripts/")) return "script";
  return "config";
}

function groupOf(id: string): CodeGraphGroup {
  if (id.startsWith("app/")) return "app";
  if (id.startsWith("components/")) return "components";
  if (id.startsWith("lib/")) return "lib";
  if (id.startsWith("scripts/")) return "scripts";
  return "root";
}

// ------------------------------------------------------ résolution d'import
/** Résout un specifier vers un id de fichier interne, ou null (externe / non-résolu). */
function resolveSpec(spec: string, fromAbs: string): string | null {
  let target: string;
  if (spec.startsWith("@/")) target = join(ROOT, spec.slice(2));
  else if (spec.startsWith("./") || spec.startsWith("../")) target = join(dirname(fromAbs), spec);
  else return null; // paquet externe

  if (relative(ROOT, target).startsWith("..")) return null; // hors projet

  const candidates = [
    target,
    ...SOURCE_EXTS.map((e) => target + e),
    ...SOURCE_EXTS.map((e) => join(target, "index" + e)),
  ];
  for (const c of candidates) {
    if (existsSync(c) && statSync(c).isFile()) {
      const id = toId(c);
      if (SOURCE_EXTS.some((e) => id.endsWith(e))) return id;
    }
  }
  return null; // css / json / dangling → ignoré
}

interface ScanResult {
  loc: number;
  /** cible interne → occurrences (pour la pondération des arêtes). */
  internal: Map<string, number>;
  externals: Set<string>;
}

function scanFile(abs: string): ScanResult {
  const text = readFileSync(abs, "utf8");
  const id = toId(abs);
  const sf = ts.createSourceFile(
    id,
    text,
    ts.ScriptTarget.Latest,
    true,
    id.endsWith(".tsx") ? ts.ScriptKind.TSX : ts.ScriptKind.TS,
  );

  const internal = new Map<string, number>();
  const externals = new Set<string>();
  const bump = (target: string | null, spec: string) => {
    if (target) internal.set(target, (internal.get(target) ?? 0) + 1);
    else if (spec.startsWith(".") || spec.startsWith("@/")) return; // non-résolu interne → ignoré
    else externals.add(spec);
  };

  const visit = (node: ts.Node) => {
    if (ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) {
      const spec = node.moduleSpecifier;
      if (spec && ts.isStringLiteral(spec)) bump(resolveSpec(spec.text, abs), spec.text);
    } else if (ts.isCallExpression(node)) {
      if (node.expression.kind === ts.SyntaxKind.ImportKeyword && node.arguments.length === 1 && ts.isStringLiteral(node.arguments[0])) {
        bump(resolveSpec(node.arguments[0].text, abs), node.arguments[0].text); // import() dynamique
      } else if (
        ts.isIdentifier(node.expression) &&
        node.expression.text === "require" &&
        node.arguments.length === 1 &&
        ts.isStringLiteral(node.arguments[0])
      ) {
        bump(resolveSpec(node.arguments[0].text, abs), node.arguments[0].text);
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);

  return { loc: text.split("\n").length, internal, externals };
}

// ------------------------------------------------------------- assemblage
function build(): CodeGraphData {
  const files: CodeGraphFile[] = [];
  const byGroup: Record<CodeGraphGroup, number> = { app: 0, components: 0, lib: 0, scripts: 0, root: 0 };
  const byKind: Record<string, number> = {};
  const edgeCounts = new Map<string, number>(); // "source→target" → occurrences
  const externalCounts = new Map<string, number>();

  for (const abs of walk(ROOT)) {
    const id = toId(abs);
    const { loc, internal, externals } = scanFile(abs);

    files.push({
      id,
      label: basename(id),
      group: groupOf(id),
      kind: kindOf(id),
      loc,
      imports: [...internal.keys()].filter((d) => d !== id),
      externals: [...externals],
    });
    byGroup[groupOf(id)]++;
    byKind[kindOf(id)] = (byKind[kindOf(id)] ?? 0) + 1;
    for (const [dep, n] of internal) {
      if (dep === id) continue;
      edgeCounts.set(`${id}\u2192${dep}`, (edgeCounts.get(`${id}\u2192${dep}`) ?? 0) + n);
    }
    for (const ext of externals) externalCounts.set(ext, (externalCounts.get(ext) ?? 0) + 1);
  }

  const edges: CodeGraphEdge[] = [...edgeCounts.entries()]
    .map(([key, weight]) => {
      const [source, target] = key.split("\u2192");
      return { source, target, weight };
    })
    .sort((a, b) => (a.source + a.target).localeCompare(b.source + b.target));

  const topExternals = [...externalCounts.entries()]
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 15);

  files.sort((a, b) => a.id.localeCompare(b.id));

  return {
    version: 1,
    generatedAt: new Date().toISOString(),
    files,
    edges,
    summary: { files: files.length, edges: edges.length, byGroup, byKind, topExternals },
  };
}

// ------------------------------------------------------------------ main
const graph = build();
writeFileSync(OUT, JSON.stringify(graph, null, 2) + "\n", "utf8");

const s = graph.summary;
console.log(`\u2705 CodeGraph généré → public/codegraph.json`);
console.log(`   ${s.files} fichiers · ${s.edges} dépendances internes`);
console.log(`   groupes : ${Object.entries(s.byGroup).map(([k, v]) => `${k}=${v}`).join(" · ")}`);
console.log(`   externes : ${s.topExternals.map((e) => `${e.name}×${e.count}`).join(" · ")}`);
