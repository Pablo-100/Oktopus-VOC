# OCTUPUS-VOC — Vulnerability Operations Center

## Rapport de projet ING-4

**Auteur :** Tbini Mustapha Amin
**Dépôt :** `github.com/Pablo-100/Oktopus-VOC`
**Période :** juillet – septembre 2026

---

## Table des matières

1. [Introduction](#1-introduction)
2. [État de l'art](#2-état-de-lart)
3. [Analyse et spécification des besoins](#3-analyse-et-spécification-des-besoins)
4. [Architecture](#4-architecture)
5. [Conception détaillée](#5-conception-détaillée)
6. [Implémentation](#6-implémentation)
7. [Sécurité](#7-sécurité)
8. [Tests et validation](#8-tests-et-validation)
9. [Déploiement et exploitation](#9-déploiement-et-exploitation)
10. [Résultats](#10-résultats)
11. [Limites et perspectives](#11-limites-et-perspectives)
12. [Conclusion](#12-conclusion)

---

## 1. Introduction

### 1.1 Contexte

Une équipe sécurité reçoit aujourd'hui plus de vulnérabilités qu'elle ne peut en
traiter. Le NVD publie plusieurs dizaines de milliers de CVE par an, et la base
de ce projet en contient **91 480** à la date de rédaction. Aucune organisation
ne corrige 91 480 failles. La question opérationnelle n'est donc pas *quelles
vulnérabilités existent*, mais **lesquelles comptent pour moi, maintenant**.

Le réflexe habituel — trier par score CVSS — répond mal à cette question. Le
CVSS mesure la gravité **théorique** d'une faille, indépendamment de son
exploitation réelle et indépendamment de l'exposition de l'organisation. Une
CVE 9.8 sur un composant que l'entreprise n'utilise pas est moins urgente qu'une
CVE 7.5 activement exploitée sur un serveur exposé sur Internet.

### 1.2 Problématique

Trois informations manquent à un tri par CVSS seul :

1. **La probabilité d'exploitation** — une faille grave mais jamais exploitée
   n'a pas la même urgence qu'une faille moyenne exploitée en masse.
2. **La réalité de l'exploitation** — certaines failles sont *confirmées*
   exploitées dans la nature.
3. **L'exposition propre de l'organisation** — la vulnérabilité touche-t-elle
   une machine réellement joignable depuis Internet ?

Les deux premières sont adressables par des sources publiques (EPSS, CISA KEV).
La troisième suppose de connaître sa propre surface d'attaque externe, ce qui
relève de l'**EASM** (*External Attack Surface Management*).

### 1.3 Objectifs

Construire une plateforme hébergée, multi-utilisateur, qui :

- agrège CVE, EPSS, KEV et renseignement 0-day depuis des sources publiques ;
- calcule un score de risque **contextualisé** (RBVM) plutôt qu'un CVSS brut ;
- découvre la surface exposée de l'utilisateur via des fournisseurs EASM ;
- corrèle cette surface aux CVE avec un **niveau de preuve explicite** ;
- déclenche un workflow SOC (alerte, triage, escalade, audit) ;
- ne présente **jamais** une information dont elle ne peut pas répondre.

Ce dernier point est le fil conducteur du projet et sera justifié tout au long
du rapport : une plateforme de sécurité qui affiche une donnée fausse est pire
qu'une plateforme qui n'affiche rien.

---

## 2. État de l'art

### 2.1 Les métriques de vulnérabilité

| Métrique | Ce qu'elle mesure | Ce qu'elle ne mesure pas |
| --- | --- | --- |
| **CVSS** (FIRST) | Gravité technique intrinsèque, 0–10 | Probabilité d'exploitation, exposition |
| **EPSS** (FIRST) | Probabilité d'exploitation à 30 jours, 0–1 | Gravité, impact métier |
| **CISA KEV** | Exploitation **confirmée** dans la nature | Gravité, portée |

Ces trois signaux sont **orthogonaux**. Une erreur fréquente des tableaux de
bord commerciaux est de les fusionner en un indicateur unique qui perd
l'information : EPSS élevé et KEV ne signifient pas la même chose, et un
analyste a besoin de distinguer « probablement exploitable » de « exploité, on
en a la preuve ».

### 2.2 RBVM

Le *Risk-Based Vulnerability Management* consiste à prioriser selon le risque
réel plutôt que selon la gravité brute. Le modèle retenu ici :

```
risque = CVSS×0.4 + EPSS×0.4 + KEV×0.2      (normalisé sur 0–100)
```

La pondération donne un poids égal à la gravité et à la probabilité, le KEV
agissant comme un facteur de certitude. Ce calcul est implémenté **une seule
fois** dans `lib/risk-engine.ts` et constitue la source de vérité unique —
aucun second moteur de score n'existe dans le projet.

### 2.3 EASM

L'EASM consiste à découvrir, depuis l'extérieur, ce qu'une organisation expose.
Deux familles d'outils existent : les scanners **actifs** (qui sondent les
hôtes) et les sources **passives** (qui interrogent des bases constituées par
des crawlers tiers).

Ce projet retient exclusivement l'approche **passive**. Ce choix est structurant
et sera justifié en [§7.4](#74-autorisation-de-surveillance).

---

## 3. Analyse et spécification des besoins

### 3.1 Besoins fonctionnels

| Réf | Besoin |
| --- | --- |
| BF1 | Synchroniser les CVE depuis NVD, enrichies EPSS et KEV |
| BF2 | Suivre les 0-day et pré-publications depuis plusieurs sources |
| BF3 | Calculer un score de risque contextualisé |
| BF4 | Déclarer un inventaire logiciel et filtrer les CVE qui le concernent |
| BF5 | Découvrir la surface exposée (IP, domaines, services, certificats) |
| BF6 | Corréler surface et CVE avec un niveau de preuve |
| BF7 | Surveiller périodiquement les actifs et détecter les changements |
| BF8 | Émettre des alertes SOC avec cycle de vie complet et piste d'audit |
| BF9 | Notifier (Telegram) et créer des tickets |
| BF10 | Visualiser les relations sous forme de graphe |

### 3.2 Besoins non fonctionnels

| Réf | Besoin | Traduction technique |
| --- | --- | --- |
| BNF1 | **Honnêteté** de l'information | Aucune donnée affichée sans provenance vérifiable |
| BNF2 | **Isolation** entre utilisateurs | Chaque donnée porte un `user_id`, testé de façon adverse |
| BNF3 | **Confidentialité** des secrets | Aucune clé en clair, ni en base, ni en logs, ni en réponse |
| BNF4 | **Résistance aux pannes** partielles | L'échec d'un fournisseur ne casse pas la requête |
| BNF5 | **Traçabilité** des décisions | Chaque transition d'alerte est auditée |
| BNF6 | Fonctionnement **serverless** | Aucun état en mémoire entre invocations |

### 3.3 Contraintes

- **Budget nul** : uniquement des offres gratuites (Vercel Hobby, Neon,
  GitHub Actions, quotas gratuits des fournisseurs EASM).
- **Serverless** : pas de worker permanent, pas de cache mémoire partagé.
- **Sources tierces non fiables** : quotas épuisables, APIs changeantes,
  réponses partielles.

---

## 4. Architecture

### 4.1 Vue d'ensemble

```
┌──────────────┐   ┌──────────────┐   ┌──────────────┐
│  Navigateur  │──▶│ Next.js App  │──▶│ Neon Postgres│
│  (React 19)  │◀──│  (Vercel)    │◀──│              │
└──────────────┘   └──────┬───────┘   └──────────────┘
                          │
             ┌────────────┼────────────┐
             ▼            ▼            ▼
        ┌────────┐  ┌──────────┐  ┌──────────┐
        │  NVD   │  │   EASM   │  │ Telegram │
        │ EPSS   │  │ 8 fourn. │  │          │
        │ KEV    │  │          │  │          │
        └────────┘  └──────────┘  └──────────┘
                          ▲
                    ┌─────┴──────┐
                    │   GitHub   │
                    │  Actions   │  (ordonnanceur)
                    └────────────┘
```

### 4.2 Décision d'architecture : le navigateur n'appelle jamais un tiers

Toutes les requêtes vers les APIs externes partent du **serveur**. Le
navigateur ne parle qu'à l'application. Trois raisons :

1. **Confidentialité des clés** — une clé API utilisée côté client est
   publique par construction.
2. **CORS** — la plupart de ces APIs ne l'autorisent pas.
3. **Mutualisation** — une réponse tierce peut être mise en cache et servir
   plusieurs utilisateurs, ce qui est indispensable avec des quotas gratuits.

### 4.3 Décision : l'état vit en base, jamais en mémoire

Vercel exécute des fonctions sans état : deux requêtes consécutives peuvent
s'exécuter sur deux instances différentes. Tout ce qui doit persister — cache,
quotas, files de notification, verrous d'ordonnancement — est donc en
PostgreSQL. Le projet compte **25 tables**.

Une conséquence concrète : la limitation de débit par IP reste en mémoire et
n'est donc valable que par instance. C'est une limite assumée et documentée,
pas un oubli ([§11.1](#111-limites-connues)).

### 4.4 Volumétrie

| Élément | Quantité |
| --- | --- |
| Fichiers source TS/TSX | 159 |
| Lignes de code source | 24 732 |
| Fichiers de test | 25 |
| Lignes de test | 7 597 |
| Routes API | 36 |
| Pages | 13 |
| Tables PostgreSQL | 25 |
| Fournisseurs EASM | 8 |

Le ratio test/source (≈ 31 %) reflète un choix : les invariants de sécurité de
ce projet ne sont pas vérifiables à l'œil.

---

## 5. Conception détaillée

### 5.1 Le modèle de preuve — contribution centrale

Le problème : un fournisseur EASM annonce « le port 443 de cette machine
exécute Apache ». Une base CVE annonce « telle CVE affecte Apache ». Peut-on en
conclure que la machine est vulnérable ?

**Non.** Selon la précision de l'observation, la conclusion va de la certitude à
la spéculation. Confondre ces cas produit des faux positifs à grande échelle.

Le système classe donc chaque corrélation dans un **niveau de preuve** :

| Niveau | Signification | Peut déclencher une alerte |
| --- | --- | --- |
| `confirmed` | Le fournisseur a été interrogé *sur cette CVE* et a répondu que cet hôte est concerné | **Oui** |
| `strong` | Version précise observée (ex. `OpenSSH 6.6.1p1`) correspondant à la CVE | **Oui** |
| `product` | Produit observé sans version | Non |
| `weak` | Correspondance par bannière ou heuristique | Non |
| `pivot` | Rapprochement indirect | Non |

Deux propriétés sont imposées par le code :

- **`confirmed` n'est pas assignable.** Il est *dérivé* dans
  `makeVulnerability()` à partir du mode d'interrogation. Aucun appelant ne
  peut le déclarer.
- **Seuls `confirmed` et `strong` alertent.** Un `product` ne réveille
  personne, quel que soit son CVSS.

**Illustration.** Log4Shell (CVE-2021-44228, CVSS 9.8, KEV, EPSS ≈ 0.97) est
détectée sur une IP appartenant à Cloudflare, sur la seule base du produit. Un
tableau de bord classique afficherait 100/Critique. Ce système affiche **38 /
Medium** et n'émet aucune alerte, parce que la preuve est de niveau `product` :
on sait qu'un produit vulnérable *existe quelque part derrière cette adresse*,
pas que cet hôte est vulnérable.

Un test dédié (`exposure-risk-matrix.test.ts`, 16 tests) vérifie cet invariant :
en neutralisant la pondération par le niveau de preuve, **9 tests sur 26
échouent**. L'invariant est donc réellement porté par le code, pas par
convention.

### 5.2 Fraîcheur : deux dates, jamais confondues

Une observation possède deux horodatages distincts :

- `observedAt` — quand **le fournisseur** a vu l'hôte ;
- `fetchedAt` — quand **nous** avons récupéré cette information.

Les confondre reviendrait à présenter une donnée vieille de trois semaines comme
étant d'il y a deux minutes. Le type prévoit une valeur `LIVE`, et un test
vérifie qu'elle n'est **jamais émise** — aucun fournisseur du projet n'observe
en temps réel.

### 5.3 Cycle de vie d'une alerte

```
          ┌──────────┐
          │   open   │
          └────┬─────┘
     ┌─────────┼──────────┬───────────┐
     ▼         ▼          ▼           ▼
acknowledged  suppressed  resolved   closed
     │
     ▼
in_progress ──▶ resolved ──▶ closed
```

- Toute transition est validée côté serveur (`canTransition`).
- La suppression **exige un motif** parmi une liste fermée.
- Chaque transition, note d'analyste et affectation produit un événement dans
  une piste d'audit unique.

### 5.4 Multi-tenance

Chaque donnée porte un `user_id`. L'identité d'un actif est
`(user_id, asset_key)`, la déduplication d'alerte `(user_id, fingerprint)`.

Deux utilisateurs surveillant **le même hôte** est le cas normal, pas un cas
limite : une adresse de CDN ou un hébergeur mutualisé sera surveillé par
plusieurs clients.

Une décision moins évidente : un accès inter-locataire renvoie **`not_found`**
et non `forbidden`. Un message distinct confirmerait l'existence de la
ressource, ce qui est en soi une divulgation.

---

## 6. Implémentation

### 6.1 Pile technique

| Couche | Technologie | Justification |
| --- | --- | --- |
| Framework | Next.js 16 (App Router) | Rendu serveur et routes API dans un seul déploiement |
| Langage | TypeScript strict | Les erreurs de type ont réellement attrapé des bugs (§8.3) |
| Runtime | Bun | Exécution et tests rapides |
| Base | Neon PostgreSQL (driver HTTP) | Serverless, offre gratuite |
| Auth | Better Auth | OTP e-mail, OAuth, liaison de comptes |
| Hébergement | Vercel | Intégration Git, fonctions serverless |
| Ordonnanceur | GitHub Actions | Pas de worker permanent à financer |

### 6.2 Les rôles de fournisseurs

Les 8 fournisseurs ne sont pas interchangeables. Chacun a été **testé en
conditions réelles** pour déterminer ce qu'il sait réellement faire :

| Rôle | Fournisseurs | Apport |
| --- | --- | --- |
| **Discovery** | LeakIX, FOFA, ZoomEye | Trouver des hôtes par produit |
| **Enrichment** | Censys, Netlas, Shodan | Ports, produits, **versions**, certificats |
| **Threat** | GreyNoise, AbuseIPDB | Réputation et activité de balayage |

Shodan occupe une place particulière : c'est le seul fournisseur configuré qui
rapporte une **version** de service, donc le seul qui rende le niveau `strong`
— et donc l'alerte — atteignable.

### 6.3 Robustesse face aux tiers

- `Promise.allSettled` : l'échec d'un fournisseur n'annule pas les autres.
- Quotas horaires par fournisseur, comptabilisés en base de façon atomique.
- Distinction explicite entre `quota_exhausted` (report) et
  `query_unsupported` (échec définitif) : confondre les deux provoque un
  backoff sur une situation qui se résoudra d'elle-même.
- `exposure_provider_health` enregistre le **dernier résultat observé**.
  L'indicateur « configuré » ne suffit pas : un compte sans crédit possède une
  clé valide et ne renvoie rien.

### 6.4 Ordonnancement

Un ordonnanceur serverless ne peut pas supposer d'exécution unique. La
réclamation d'un actif dû utilise :

```sql
WITH due AS MATERIALIZED (
  SELECT ... LIMIT n FOR UPDATE SKIP LOCKED
) ...
```

`MATERIALIZED` n'est pas cosmétique : sans lui, `FOR UPDATE` rend la
sous-requête non-hachable et le planificateur peut la ré-exécuter par ligne,
réclamant plus d'actifs que la limite. Le bug a été reproduit (2 actifs
réclamés avec `LIMIT 1`) avant correction, et un test de non-régression le
couvre.

Pour la file de notifications, **la transition d'état *est* la réclamation** :
le passage à `sending` s'effectue dans la même instruction que la sélection.
Sans cela, deux instances peuvent envoyer la même notification — comportement
également reproduit puis corrigé.

---

## 7. Sécurité

### 7.1 Modèle de menace

| Menace | Contre-mesure |
| --- | --- |
| Fuite de clé API | Aucun appel tiers côté client ; `redactSecrets()` sur tout texte persisté |
| Accès inter-locataire | Prédicat `user_id` sur chaque requête ; tests adverses |
| Vol de la base | Secrets utilisateurs chiffrés AES-256-GCM, clé hors base |
| SSRF | Adresses privées, loopback, link-local, ULA, multicast bloquées |
| XSS | CSP stricte à nonce ; échappement des chaînes fournisseur |
| Usage abusif de la surveillance | Preuve de contrôle du domaine par enregistrement DNS TXT |

### 7.2 BYOK — chiffrement des secrets utilisateurs

Les fournisseurs EASM sont payants. Chaque utilisateur fournit donc ses propres
clés, ce qui transforme la plateforme en dépositaire de **secrets appartenant à
des tiers**. Le traitement est plus strict que pour les secrets du projet :

- **AES-256-GCM**, IV aléatoire par enregistrement.
- Clé maîtresse dans l'environnement, **jamais en base** : une exfiltration de
  la base seule ne donne rien d'exploitable.
- Le propriétaire et le fournisseur sont liés dans les **données authentifiées
  additionnelles** (AAD) : un chiffré recopié dans la ligne d'un autre
  utilisateur échoue à l'authentification.
- Un secret stocké **n'est jamais renvoyé** — seuls les quatre derniers
  caractères sont affichés.

Les clés résidant désormais en base et non dans l'environnement, la redaction
par comparaison aux variables d'environnement devenait aveugle. Les secrets de
la requête courante sont donc portés par un contexte `AsyncLocalStorage` que la
fonction de redaction consulte — `process.env` étant global au processus, il ne
pouvait pas servir à cela sans faire fuiter la clé d'un utilisateur dans la
requête d'un autre.

### 7.3 Cloisonnement du cache et des quotas

Un résultat obtenu avec la clé d'un utilisateur lui appartient : un autre ne
doit pas le lire depuis le cache, à la fois parce qu'il ne l'a pas payé et
parce que les offres diffèrent dans ce qu'elles renvoient. Cinq tables portent
donc une colonne `scope`.

Le même raisonnement s'applique aux quotas : un compteur global unique
permettait à un utilisateur d'épuiser le budget de tous les autres.

### 7.4 Autorisation de surveillance

Tous les fournisseurs du projet sont **passifs** : la plateforme ne sonde
jamais un hôte, elle relit des observations déjà collectées. Une consultation
ponctuelle reste donc ouverte — elle n'est pas différente d'une visite du site
de Shodan.

La **surveillance continue** est de nature différente : elle interroge un hôte
de façon répétée, accumule son historique et réveille un humain. Elle exige
donc une preuve de contrôle :

| Cible | Autorisation |
| --- | --- |
| `example.com` | Enregistrement DNS TXT contenant un jeton propre à l'utilisateur |
| `app.example.com` | Hérité d'un parent vérifié (seul le propriétaire de la zone délègue) |
| Adresse IP | Uniquement tant qu'un domaine vérifié y résout (A ou AAAA) |

Trois propriétés :

- **Échec fermé** : toute erreur de résolution vaut refus.
- **Revérifié à chaque cycle**, pas seulement à l'activation : une autorisation
  fondée sur un enregistrement DNS cesse quand celui-ci disparaît.
- **Mise en pause, jamais suppression** : l'utilisateur conserve sa
  configuration et reprend automatiquement après re-vérification.

La correspondance par suffixe est un test de **délégation**, pas de chaîne :
`evil-example.com` est rejeté face à un `example.com` vérifié.

---

## 8. Tests et validation

### 8.1 Stratégie

**639 tests, 1 699 assertions, 25 fichiers.** Les suites adossées à la base
refusent de s'exécuter sans `TEST_DATABASE_URL` : elles écrivent de vraies
lignes, et se rabattre sur `DATABASE_URL` viserait la base de production.

| Suite | Tests | Objet |
| --- | --- | --- |
| `soc-workflow` | 63 | Machine à états des alertes |
| `exposure-intel` | 62 | Normalisation et corrélation |
| `exposure-graph` | 54 | Projection du graphe |
| `notify-delivery` | 42 | File de notification, reprise |
| `zero-days` | 41 | Collecte 0-day |
| `soc-workflow-db` | 33 | Persistance et audit |
| `exposure-cve-correlation` | 32 | Appariement CVE |
| `exposure-soc-alerts` | 32 | Éligibilité des alertes |
| `exposure-freshness` | 30 | Modèle de fraîcheur |
| `byok-credentials` | 28 | Chiffrement, isolation, redaction |
| `ownership` | 20 | Preuve de contrôle |
| `tenancy-isolation` | 19 | Isolation inter-locataires |
| *(13 autres suites)* | 183 | — |

### 8.2 Tests adverses

`tenancy-isolation.test.ts` donne **le même actif, la même CVE, le même port**
à deux locataires, puis interroge chacun. Un prédicat `user_id` manquant est
invisible autrement : la requête s'exécute, renvoie des lignes, l'interface
s'affiche — elle montre simplement les données de quelqu'un d'autre.

### 8.3 Bugs trouvés par la validation

Cette section est volontairement détaillée : elle constitue le résultat
expérimental du projet.

| Bug | Symptôme | Cause |
| --- | --- | --- |
| Réclamation excessive | 2 actifs pour `LIMIT 1` | Sous-requête non matérialisée |
| Double notification | 2 envois Telegram | État `pending` pendant l'appel HTTP |
| Famine du sync 0-day | Données figées 12 jours, santé « OK » | Budget 60 s consommé par le sync CVE |
| Identifiants `BIGSERIAL` | **Toutes** les actions SOC en HTTP 400 | `BIGINT` renvoyé en *string*, validé par `typeof === "number"` |
| Éviction de cache | Suppression des lignes des autres locataires | Clé primaire devenue composite |
| `<Toaster/>` non monté | Tous les messages de succès/erreur invisibles | Composant jamais inséré dans le layout |
| Filtres 0-day inertes | Deux listes déroulantes sans effet | État écrit mais jamais lu |
| Hydratation bloquée | Page figée, compteurs à zéro | **CSP `script-src 'self'`** bloquant les scripts inline de Next |

Le dernier mérite un développement, car il illustre une limite méthodologique.

### 8.4 Étude de cas : le bug invisible aux tests

**Symptôme.** En production, l'application s'affichait correctement et restait
totalement inerte : compteurs figés à zéro, horloge à `--:--:--`, formulaire de
connexion bloqué sur « Loading… ».

**Ce qui rendait le diagnostic difficile.** Toutes les vérifications
disponibles passaient :

- 639 tests au vert ;
- `typecheck`, `lint`, `build` propres ;
- les 12 pages et 36 routes API renvoyaient les mêmes codes en local et en
  production, connecté comme déconnecté ;
- le HTML de production était **identique octet pour octet** entre les deux.

**Cause.** Une `Content-Security-Policy` déclarée dans `next.config.ts`,
appliquée **uniquement** lorsque `NODE_ENV === "production"` :

```
script-src 'self'
```

Next.js transmet la charge utile RSC et l'amorçage de React dans **onze
balises `<script>` inline**. `'self'` n'autorise pas le script inline : les
onze étaient bloquées, React ne recevait jamais sa charge utile, et
l'hydratation ne démarrait pas.

**Pourquoi rien ne l'a détecté.** Seul un navigateur applique une CSP. `curl`
l'ignore, les tests unitaires ne l'exécutent pas, et le serveur ne produit
aucune erreur. Le développement fonctionnait pour une seule raison : l'en-tête
n'y était jamais appliqué.

**Correction.** La politique a été déplacée dans `proxy.ts` avec un **nonce par
requête**. `'unsafe-inline'` aurait débloqué les mêmes scripts en autorisant
*n'importe quel* script inline — y compris injecté — c'est-à-dire en abandonnant
exactement la protection visée. Un nonce n'existant qu'à partir d'une requête,
le layout racine bascule en rendu dynamique : une page pré-générée n'a aucune
requête d'où tirer un nonce.

**Leçon.** Une suite de tests verte prouve l'absence des défauts qu'elle sait
observer. Aucune couche du projet ne pouvait observer une politique appliquée
par le navigateur.

---

## 9. Déploiement et exploitation

### 9.1 Chaîne

```
git push ──▶ GitHub ──▶ Vercel (build + déploiement)
                │
                └──▶ GitHub Actions ──▶ /api/cron/*  (Bearer CRON_SECRET)
```

### 9.2 Séparation des tâches planifiées

Les synchronisations CVE et 0-day sont **deux appels HTTP distincts**. Quand
elles partageaient une invocation, la passe CVE consommait le budget de 60 s et
la passe 0-day n'était jamais atteinte : la fonction était tuée plutôt que de
lever une exception, donc rien n'était journalisé et les données ont gelé
douze jours pendant que tous les indicateurs restaient au vert.

### 9.3 Observabilité

Deux surfaces ont été ajoutées après des pannes réelles :

- **`/api/health`** — âge des données par pipeline. `last_status` indique si le
  dernier appel a **échoué**, pas s'il a **produit** quelque chose : un flux
  peut réussir indéfiniment et ne rien stocker.
- **`/api/config-check`** — ce que le déploiement **en cours d'exécution**
  possède réellement comme configuration : présence, longueur et empreinte
  SHA-256 tronquée, jamais la valeur. Les variables d'environnement sont liées
  à un déploiement ; « j'ai défini la variable » et « le code en cours la voit »
  sont deux affirmations distinctes, indiscernables de l'extérieur sans cela.

---

## 10. Résultats

### 10.1 Fonctionnalités livrées

Les dix besoins fonctionnels de [§3.1](#31-besoins-fonctionnels) sont
implémentés, testés et déployables. La chaîne complète fonctionne de bout en
bout : synchronisation → corrélation → score → alerte → notification → triage →
audit.

### 10.2 Mesures

| Indicateur | Valeur |
| --- | --- |
| CVE en base | 91 480 |
| Enregistrements 0-day | 161 |
| Tests / assertions | 639 / 1 699 |
| Erreurs `typecheck` | 0 |
| Erreurs `lint` | 0 (16 avertissements documentés) |
| Requête d'impact (index GIN) | ≈ 100 ms sur 91 k lignes |
| Enrichissement d'un actif | ≈ 1,4 s, 5 services, 149 vulnérabilités |

### 10.3 Validation du modèle de preuve

Sur un actif réel enrichi via Shodan :

```
Enregistrements de vulnérabilité conservés : 149
Alertes émises                             :   5
Retenues par le plafond anti-saturation    : 115
Supprimées par le filtre de preuve         :  29
```

Les 149 constats restent **consultables** ; seule l'alerte est bornée. Un
plafond de 5 alertes par actif et par cycle évite qu'un seul hôte ne noie la
file, sans jamais masquer une donnée.

---

## 11. Limites et perspectives

### 11.1 Limites connues

| Limite | Nature | Atténuation |
| --- | --- | --- |
| Limitation de débit par instance | Mémoire non partagée en serverless | Déplaçable en base, motif déjà en place pour les quotas |
| Pas d'outil de migration | DDL idempotent au démarrage | Acceptable à cette échelle ; Drizzle/Prisma au-delà |
| Pas de gestion d'équipes | Affectation limitée à soi-même | Nécessite un annuaire d'utilisateurs et des rôles |
| Comptes fournisseurs épuisés | Censys, FOFA, ZoomEye sans crédit | Résolu par le BYOK |
| Ticketing « interne » | Implémentation de référence | L'interface d'adaptation existe |
| Pas d'export SIEM | Hors périmètre | Export CSV/JSON comme point d'intégration |

### 11.2 Perspectives

1. **Équipes et RBAC** — affectation à un collègue, rôles, vues partagées.
2. **Export CEF/STIX** — intégration SIEM.
3. **Adaptateurs Jira / ServiceNow** — l'interface est déjà en place.
4. **Métriques SLA** — délai de prise en charge, délai de remédiation.
5. **Limitation de débit distribuée** — en base, sur le modèle des quotas.

---

## 12. Conclusion

Le projet livre une plateforme VOC complète et fonctionnelle : agrégation
multi-sources, scoring RBVM contextualisé, découverte de surface d'attaque
externe, corrélation à niveau de preuve explicite, workflow SOC audité et
notification.

La contribution technique la plus significative n'est pas une fonctionnalité
mais un **refus** : le système refuse de présenter comme certain ce qu'il ne
peut pas prouver. Le modèle de preuve à cinq niveaux, l'invariant qu'une preuve
faible ne peut jamais devenir une alerte critique, la séparation stricte de
`observedAt` et `fetchedAt`, et le rejet de `LIVE` comme fraîcheur sont
l'expression d'une même exigence.

Le travail de validation le confirme : la majorité des défauts corrigés
n'étaient pas des plantages mais des **mensonges silencieux** — une interface
affirmant un succès qui n'avait pas eu lieu, un filtre visible sans effet, un
indicateur de santé au vert sur un flux gelé, une politique de sécurité
supposée protectrice qui rendait l'application inerte. Aucun ne levait
d'exception. Tous auraient été invisibles sans une recherche délibérée.

---

## Annexes

### A. Variables d'environnement

| Variable | Rôle |
| --- | --- |
| `DATABASE_URL` | Connexion PostgreSQL |
| `BETTER_AUTH_SECRET` | Signature des sessions |
| `CREDENTIAL_ENCRYPTION_KEY` | Clé maîtresse AES-256-GCM (BYOK) |
| `CRON_SECRET` | Authentification des tâches planifiées |
| `TEST_DATABASE_URL` | Base de test dédiée (jamais la production) |
| *(clés fournisseurs)* | Niveau plateforme, complétées par le BYOK |

`BETTER_AUTH_URL` et `APP_URL` sont volontairement **non définies** en
production : `getAppUrl()` se rabat sur `VERCEL_PROJECT_PRODUCTION_URL`, fournie
automatiquement et toujours correcte.

### B. Principales tables

`cves`, `zero_days`, `assets`, `exposure_asset_state`, `exposure_history`,
`exposure_vulnerability`, `exposure_monitoring`, `exposure_alerts`,
`exposure_alert_events`, `exposure_tickets`, `user_provider_credentials`,
`target_ownership`, `exposure_provider_quota`, `exposure_provider_health`.

### C. Reproduire l'environnement

```bash
bun install
cp .env.example .env.local     # renseigner les variables
bun run doctor                 # vérifier la configuration
bun run dev                    # développement
bun run build && bun run start # production (applique la CSP)
bun run test                   # 639 tests
```

> Une vérification en développement ne vaut pas une vérification en production :
> la CSP n'est appliquée que par `bun run build && bun run start`.
