/*
=====================================================================
  THREAT-MAP.JS - Corrélation CWE -> CAPEC + MITRE ATT&CK
=====================================================================
  Mapping curé pour les faiblesses les plus fréquentes.
    - CAPEC : patterns d'attaque (mapping officiel MITRE CWE->CAPEC)
    - ATT&CK : techniques associées (indicatif, via CAPEC->ATT&CK)
  Permet d'enrichir chaque CVE avec un contexte "comment on l'attaque".
=====================================================================
*/
export const THREAT_MAP: Record<string, { capec: { id: string; name: string }[]; attack: { id: string; name: string }[] }> = {
    "79":  { capec: [{ id: "CAPEC-63", name: "Cross-Site Scripting" }, { id: "CAPEC-592", name: "Stored XSS" }], attack: [{ id: "T1059.007", name: "Command & Scripting: JavaScript" }, { id: "T1189", name: "Drive-by Compromise" }] },
    "89":  { capec: [{ id: "CAPEC-66", name: "SQL Injection" }, { id: "CAPEC-7", name: "Blind SQL Injection" }], attack: [{ id: "T1190", name: "Exploit Public-Facing Application" }] },
    "78":  { capec: [{ id: "CAPEC-88", name: "OS Command Injection" }], attack: [{ id: "T1059", name: "Command & Scripting Interpreter" }] },
    "77":  { capec: [{ id: "CAPEC-248", name: "Command Injection" }], attack: [{ id: "T1059", name: "Command & Scripting Interpreter" }] },
    "94":  { capec: [{ id: "CAPEC-242", name: "Code Injection" }], attack: [{ id: "T1059", name: "Command & Scripting Interpreter" }] },
    "22":  { capec: [{ id: "CAPEC-126", name: "Path Traversal" }], attack: [{ id: "T1083", name: "File & Directory Discovery" }] },
    "352": { capec: [{ id: "CAPEC-62", name: "Cross-Site Request Forgery" }], attack: [{ id: "T1189", name: "Drive-by Compromise" }] },
    "434": { capec: [{ id: "CAPEC-650", name: "Upload a Web Shell" }], attack: [{ id: "T1505.003", name: "Server Software Component: Web Shell" }] },
    "502": { capec: [{ id: "CAPEC-586", name: "Object Injection" }], attack: [{ id: "T1059", name: "Command & Scripting Interpreter" }] },
    "918": { capec: [{ id: "CAPEC-664", name: "Server-Side Request Forgery" }], attack: [{ id: "T1090", name: "Proxy / Pivot interne" }] },
    "611": { capec: [{ id: "CAPEC-201", name: "XML External Entities (XXE)" }], attack: [{ id: "T1190", name: "Exploit Public-Facing Application" }] },
    "862": { capec: [{ id: "CAPEC-122", name: "Privilege Abuse" }], attack: [{ id: "T1078", name: "Valid Accounts" }] },
    "863": { capec: [{ id: "CAPEC-122", name: "Privilege Abuse" }], attack: [{ id: "T1078", name: "Valid Accounts" }] },
    "287": { capec: [{ id: "CAPEC-115", name: "Authentication Bypass" }], attack: [{ id: "T1078", name: "Valid Accounts" }] },
    "306": { capec: [{ id: "CAPEC-12", name: "Choosing Message Identifier" }], attack: [{ id: "T1190", name: "Exploit Public-Facing Application" }] },
    "798": { capec: [{ id: "CAPEC-70", name: "Try Common/Default Credentials" }], attack: [{ id: "T1552.001", name: "Unsecured Credentials: In Files" }] },
    "259": { capec: [{ id: "CAPEC-70", name: "Try Common/Default Credentials" }], attack: [{ id: "T1552.001", name: "Unsecured Credentials: In Files" }] },
    "522": { capec: [{ id: "CAPEC-560", name: "Use of Known Credentials" }], attack: [{ id: "T1552", name: "Unsecured Credentials" }] },
    "200": { capec: [{ id: "CAPEC-116", name: "Information Discovery" }], attack: [{ id: "T1213", name: "Data from Information Repositories" }] },
    "269": { capec: [{ id: "CAPEC-122", name: "Privilege Abuse" }], attack: [{ id: "T1068", name: "Exploitation for Privilege Escalation" }] },
    "416": { capec: [{ id: "CAPEC-100", name: "Overflow Buffers" }], attack: [{ id: "T1203", name: "Exploitation for Client Execution" }] },
    "787": { capec: [{ id: "CAPEC-100", name: "Overflow Buffers" }], attack: [{ id: "T1203", name: "Exploitation for Client Execution" }] },
    "125": { capec: [{ id: "CAPEC-540", name: "Overread Buffers" }], attack: [{ id: "T1203", name: "Exploitation for Client Execution" }] },
    "119": { capec: [{ id: "CAPEC-100", name: "Overflow Buffers" }], attack: [{ id: "T1203", name: "Exploitation for Client Execution" }] },
    "190": { capec: [{ id: "CAPEC-92", name: "Forced Integer Overflow" }], attack: [{ id: "T1203", name: "Exploitation for Client Execution" }] },
    "476": { capec: [], attack: [{ id: "T1499", name: "Endpoint Denial of Service" }] },
    "20":  { capec: [{ id: "CAPEC-153", name: "Input Data Manipulation" }], attack: [{ id: "T1190", name: "Exploit Public-Facing Application" }] },
    "601": { capec: [{ id: "CAPEC-194", name: "Fake the Source of Data" }], attack: [{ id: "T1204", name: "User Execution" }] },
    "400": { capec: [{ id: "CAPEC-125", name: "Flooding" }], attack: [{ id: "T1499", name: "Endpoint Denial of Service" }] },
    "74":  { capec: [{ id: "CAPEC-152", name: "Injection" }], attack: [{ id: "T1190", name: "Exploit Public-Facing Application" }] },
    "639": { capec: [{ id: "CAPEC-122", name: "Privilege Abuse (IDOR)" }], attack: [{ id: "T1078", name: "Valid Accounts" }] },
    "384": { capec: [{ id: "CAPEC-61", name: "Session Fixation" }], attack: [{ id: "T1539", name: "Steal Web Session Cookie" }] },
    "917": { capec: [{ id: "CAPEC-242", name: "Code Injection (EL)" }], attack: [{ id: "T1059", name: "Command & Scripting Interpreter" }] },
    "1321":{ capec: [{ id: "CAPEC-242", name: "Prototype Pollution" }], attack: [{ id: "T1059.007", name: "Command & Scripting: JavaScript" }] }
};

