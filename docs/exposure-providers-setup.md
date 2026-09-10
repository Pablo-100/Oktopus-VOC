# Exposure Providers — Account Setup

Companion doc to the roadmap's Phase 1 "exposure signal" (`Shodan/Censys instance counts for the affected product`). This is the account-creation checklist for the 10 EASM/OSINT platforms from your encadrant's list — **do this once, then tell me which keys you've added and I'll build the `ExposureProvider` adapters.**

## Security rule — read this first

**Never paste an actual API key/secret into the chat with me.** Put every value directly into `next-app/.env.local` (already gitignored). When you tell me a key is ready, just say the variable name (e.g. "`GREYNOISE_API_KEY` is set") — I never need to see the value to write code that reads `process.env.GREYNOISE_API_KEY`.

Free-tier limits below are from memory and vendors change them often — **verify the current quota on each pricing page before relying on it**, especially once the feed is public.

---

## Tier A — build first (best free tier, least overlap, highest relevance)

### 1. GreyNoise
The standout of the ten for this project — not an exposure counter, but a live "is this CVE being mass-scanned/exploited right now" signal, tagged per CVE. Worth feeding into `computeZeroDayRisk` directly, not just a display badge.

1. Go to <https://viz.greynoise.io/> (or the GreyNoise developer portal) and create a free account.
2. Verify your email.
3. Account settings → API → copy the **Community API Key**.
4. Set `GREYNOISE_API_KEY` in `.env.local`.

Free tier: Community API, per-IP lookups, daily rate limit — no credit card required.

### 2. LeakIX
Free, community-run, and it already correlates exposed hosts to CVEs/misconfigurations — closest philosophical match to Octupus-VOC.

1. Register at <https://leakix.net/>.
2. Go to your account/profile page → API section.
3. Generate an API key.
4. Set `LEAKIX_API_KEY` in `.env.local`.

Free tier: open, rate-limited (no paid tier needed for a baseline integration).

### 3. Censys
Authoritative internet-wide host/cert/service index — use as the baseline exposure count.

1. Register at <https://search.censys.io/>.
2. Go to your account page → **API** / Personal Access Tokens.
3. Copy the token — it looks like `censys_XXXXXXXX_XXXXXXXXXXXXXXXXXXXX` and is used as a single Bearer token (Censys's newer Platform API replaced the old API-ID/API-Secret pair with one token).
4. Set `CENSYS_API_TOKEN` in `.env.local`.

Free tier: registered account gets a limited number of queries/month.

---

## Tier B — add once Tier A is working

### 4. Netlas
1. Register at <https://netlas.io/>.
2. Profile → API key.
3. Set `NETLAS_API_KEY`.

### 5. Onyphe
French/EU-based — useful data-residency argument for the "international" positioning (EU users, GDPR).
1. Register at <https://www.onyphe.io/>.
2. Account → API key.
3. Set `ONYPHE_API_KEY`.

Free tier: public tier with a daily request cap.

### 6. Criminal IP
Bonus: it returns a per-IP risk/vulnerability score alongside exposure data — useful as a sanity check against your own RBVM score.
1. Register at <https://www.criminalip.io/>.
2. My Page → API → generate key.
3. Set `CRIMINALIP_API_KEY`.

---

## Tier C — regional coverage, only if Censys/GreyNoise undercounts a product

### 7. FOFA
1. Register at <https://fofa.info/>.
2. Personal Center → API. FOFA auth needs **both** your account email and the key.
3. Set `FOFA_EMAIL` and `FOFA_API_KEY`.

### 8. ZoomEye
1. Register at <https://www.zoomeye.org/>.
2. Personal profile → API key.
3. Set `ZOOMEYE_API_KEY`.

Both FOFA and ZoomEye free tiers are small (points/credits system) — fine for occasional lookups, not for scanning every CVE automatically.

---

## Tier D — defer (paid, not worth building against on a student budget)

### 9. BinaryEdge
1. Register at <https://www.binaryedge.io/> if you want to explore it, but it's enterprise-priced with only small trial credits.
2. Set `BINARYEDGE_API_KEY` only when there's an actual need/budget for it.

---

## Unverified — confirm before creating an account

### 10. "Hunter's Howls"
I don't have reliable knowledge of this exact product — it may be a smaller/regional tool or a rebrand I'm not aware of. Before signing up, confirm with your encadrant: the exact name, the URL, and what "domain/subdomain and infrastructure discovery" specifically means for this one (e.g. is it closer to a subdomain-enum tool like SecurityTrails/Chaos, or a Shodan-style search engine). I'd rather you double-check than have me guess at signup steps for a product I can't verify.

---

## Status

Configured and wired into the app: **GreyNoise, LeakIX, Censys, Netlas, ZoomEye**. **FOFA has a key but is still inactive** — `FOFA_EMAIL` is empty in `.env.local` and FOFA's API rejects requests without both; add your FOFA account email to activate it.

Where to see them running: open any CVE (`/dashboard`) or 0-day (`/zero-days`) detail view —
- **"Internet exposure — `<product>`"** panel → Censys/LeakIX/Netlas/FOFA/ZoomEye counts (`lib/exposure-providers.ts`).
- **"Live exploitation activity — GreyNoise"** panel → shows only when GreyNoise has data for that CVE (`lib/greynoise.ts`).

Not yet configured: Onyphe, Criminal IP, BinaryEdge, "Hunter's Howls" (see Tier B/C/D and the unverified entry above).
