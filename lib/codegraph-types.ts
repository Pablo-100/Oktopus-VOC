/**
 * Contrat JSON de CodeGraph — défini par le générateur (scripts/codegraph.ts).
 * public/codegraph.json respecte exactement cette interface.
 * Consommé par opencode pour comprendre le projet sans lire chaque fichier.
 */

export type CodeGraphGroup = "app" | "components" | "lib" | "scripts" | "root";

export type CodeGraphKind =
  | "page"
  | "layout"
  | "api"
  | "component"
  | "ui"
  | "lib"
  | "script"
  | "config"
  | "other";

export interface CodeGraphFile {
  /** Chemin relatif POSIX depuis la racine du projet (ex. "lib/data.ts"). */
  id: string;
  /** Nom de fichier (ex. "data.ts"). */
  label: string;
  /** Groupe racine (dossier de premier niveau) — sert de nœud parent. */
  group: CodeGraphGroup;
  /** Type fonctionnel du fichier (page, api, ui…). */
  kind: CodeGraphKind;
  /** Lignes de code (indication de taille). */
  loc: number;
  /** Ids des fichiers internes importés (résolus, uniques). */
  imports: string[];
  /** Paquets externes importés (react, cytoscape…), uniques. */
  externals: string[];
}

export interface CodeGraphEdge {
  source: string;
  target: string;
  /** Nombre d'occurrences d'import source → target (≥ 1). */
  weight: number;
}

export interface CodeGraphSummary {
  files: number;
  edges: number;
  byGroup: Record<CodeGraphGroup, number>;
  byKind: Record<string, number>;
  /** Paquets externes les plus importés (nom → occurrences). */
  topExternals: { name: string; count: number }[];
}

export interface CodeGraphData {
  version: number;
  generatedAt: string;
  files: CodeGraphFile[];
  edges: CodeGraphEdge[];
  summary: CodeGraphSummary;
}
