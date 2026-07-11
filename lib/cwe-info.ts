/*
=====================================================================
  CWE-INFO.JS - Dictionnaire des faiblesses CWE (nom + description FR)
=====================================================================
  Clé = numéro CWE (chaîne). Couvre le CWE Top 25 + les faiblesses web
  les plus fréquentes. Sert à afficher une explication lisible au survol,
  car les numéros CWE ne parlent pas à la plupart des utilisateurs.
=====================================================================
*/
export const CWE_INFO: Record<string, { name: string; desc: string }> = {
    "79":  { name: "Cross-Site Scripting (XSS)", desc: "L'application insère des données non filtrées dans une page web : un attaquant peut exécuter du JavaScript dans le navigateur des victimes (vol de session, redirection, défiguration)." },
    "787": { name: "Écriture hors limites mémoire", desc: "Le programme écrit au-delà de la zone mémoire allouée, ce qui peut corrompre des données, faire planter l'application ou permettre l'exécution de code." },
    "89":  { name: "Injection SQL", desc: "Des entrées non échappées sont concaténées dans une requête SQL : un attaquant peut lire, modifier ou supprimer la base de données." },
    "416": { name: "Use After Free", desc: "Le programme utilise une zone mémoire déjà libérée, provoquant plantage ou exécution de code arbitraire." },
    "78":  { name: "Injection de commandes système (OS)", desc: "Des entrées non filtrées sont passées au shell du système : l'attaquant peut exécuter des commandes arbitraires sur le serveur." },
    "20":  { name: "Validation d'entrée incorrecte", desc: "L'application ne vérifie pas correctement les données reçues, ouvrant la porte à de nombreuses attaques (injections, débordements, etc.)." },
    "125": { name: "Lecture hors limites mémoire", desc: "Le programme lit au-delà de la zone allouée, pouvant divulguer des informations sensibles ou faire planter l'application." },
    "22":  { name: "Traversée de répertoires (Path Traversal)", desc: "Des chemins non filtrés (../) permettent d'accéder à des fichiers hors du dossier prévu (config, mots de passe...)." },
    "352": { name: "Falsification de requête (CSRF)", desc: "Un site malveillant force le navigateur d'une victime authentifiée à exécuter une action non désirée sur une application de confiance." },
    "434": { name: "Upload de fichier non restreint", desc: "L'application accepte l'envoi de fichiers dangereux (ex. script) qui peuvent ensuite être exécutés sur le serveur." },
    "862": { name: "Autorisation manquante", desc: "Une fonctionnalité n'effectue aucun contrôle d'autorisation : n'importe quel utilisateur peut y accéder." },
    "476": { name: "Déréférencement de pointeur NULL", desc: "Le programme utilise un pointeur nul, ce qui provoque généralement un plantage (déni de service)." },
    "287": { name: "Authentification incorrecte", desc: "Le mécanisme d'authentification est défaillant : un attaquant peut se faire passer pour un autre utilisateur." },
    "190": { name: "Dépassement d'entier (Integer Overflow)", desc: "Un calcul dépasse la capacité du type entier, entraînant des comportements inattendus (souvent des débordements mémoire)." },
    "502": { name: "Désérialisation de données non fiables", desc: "L'application désérialise des données contrôlées par l'attaquant, pouvant mener à l'exécution de code." },
    "77":  { name: "Injection de commandes", desc: "Des entrées non filtrées modifient une commande exécutée par l'application." },
    "119": { name: "Débordement de tampon mémoire", desc: "Opérations mémoire hors des limites d'un tampon : corruption mémoire, plantage ou exécution de code." },
    "798": { name: "Identifiants codés en dur", desc: "Des mots de passe ou clés sont écrits directement dans le code, faciles à extraire et impossibles à changer sans patch." },
    "918": { name: "Server-Side Request Forgery (SSRF)", desc: "L'attaquant force le serveur à effectuer des requêtes vers des cibles internes (métadonnées cloud, services privés)." },
    "306": { name: "Authentification manquante (fonction critique)", desc: "Une fonction sensible est accessible sans aucune authentification." },
    "362": { name: "Condition de concurrence (Race Condition)", desc: "Deux opérations concurrentes mal synchronisées créent un état incohérent exploitable." },
    "269": { name: "Gestion incorrecte des privilèges", desc: "L'application accorde ou conserve des privilèges de façon incorrecte, permettant une élévation de privilèges." },
    "94":  { name: "Injection de code", desc: "L'attaquant injecte du code interprété/exécuté par l'application." },
    "863": { name: "Autorisation incorrecte", desc: "Le contrôle d'autorisation existe mais est mal implémenté : accès à des ressources non permises." },
    "276": { name: "Permissions par défaut incorrectes", desc: "Des ressources sont créées avec des permissions trop permissives par défaut." },
    "200": { name: "Exposition d'informations sensibles", desc: "L'application divulgue des informations (chemins, versions, données personnelles) utiles à un attaquant." },
    "522": { name: "Identifiants insuffisamment protégés", desc: "Des identifiants sont stockés ou transmis sans protection adéquate (clair, hachage faible)." },
    "732": { name: "Attribution de permissions incorrecte", desc: "Une ressource critique reçoit des permissions permettant à des acteurs non autorisés d'y accéder." },
    "611": { name: "Entité externe XML (XXE)", desc: "Un parseur XML traite des entités externes, permettant lecture de fichiers locaux ou SSRF." },
    "400": { name: "Consommation de ressources incontrôlée", desc: "L'application ne limite pas l'usage des ressources (CPU, mémoire, disque) : déni de service." },
    "285": { name: "Autorisation incorrecte", desc: "Contrôle d'accès insuffisant sur une ressource : un utilisateur accède à ce qu'il ne devrait pas." },
    "601": { name: "Redirection ouverte (Open Redirect)", desc: "L'application redirige vers une URL contrôlée par l'attaquant (phishing, vol de jeton)." },
    "617": { name: "Assertion atteignable", desc: "Une assertion peut être déclenchée par l'attaquant, provoquant un arrêt de l'application (déni de service)." },
    "770": { name: "Allocation sans limite", desc: "Des ressources sont allouées sans quota, permettant un épuisement (déni de service)." },
    "404": { name: "Fermeture de ressource incorrecte", desc: "Des ressources ne sont pas libérées correctement (fuites, état incohérent)." },
    "312": { name: "Stockage en clair de données sensibles", desc: "Des données sensibles sont stockées sans chiffrement." },
    "319": { name: "Transmission en clair de données sensibles", desc: "Des données sensibles transitent sans chiffrement (interception possible)." },
    "639": { name: "Contournement d'autorisation par clé (IDOR)", desc: "L'accès à un objet dépend d'un identifiant manipulable : accès aux données d'autres utilisateurs." },
    "1321":{ name: "Pollution de prototype", desc: "Modification du prototype d'objets JavaScript, altérant le comportement de l'application." },
    "917": { name: "Injection de langage d'expression (EL)", desc: "Injection dans un moteur d'expression (ex. Spring EL), pouvant mener à l'exécution de code." },
    "384": { name: "Fixation de session", desc: "L'attaquant impose un identifiant de session connu pour détourner la session de la victime." },
    "121": { name: "Débordement de tampon sur la pile", desc: "Écriture au-delà d'un tampon sur la pile : corruption, souvent exécution de code." },
    "122": { name: "Débordement de tampon sur le tas", desc: "Écriture au-delà d'un tampon alloué dynamiquement (tas)." },
    "415": { name: "Double libération (Double Free)", desc: "La même zone mémoire est libérée deux fois : corruption du tas exploitable." },
    "532": { name: "Fuite d'informations dans les logs", desc: "Des données sensibles sont écrites dans les journaux." },
    "116": { name: "Encodage/échappement incorrect", desc: "Sortie non correctement encodée, à l'origine de nombreuses injections (dont XSS)." },
    "74":  { name: "Injection (générique)", desc: "Des données non neutralisées modifient la structure d'une commande ou d'une requête." }
};

