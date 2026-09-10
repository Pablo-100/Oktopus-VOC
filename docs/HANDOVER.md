# Handover checklist

For transferring this project to a new owner or client. Work through it in order — step 0 decides whether the buyer receives a working project at all, and step 1 decides whether you accidentally hand over your own credentials.

---

## 0. Commit everything first — STOP IF THIS IS NOT DONE

A large amount of source has historically sat **untracked**, including entire features (`/exposure`, `/zero-days`) and shared modules like `lib/errors.ts` that **tracked** files import.

This matters because `git archive`, `git clone`, and any Git-based transfer ship **only committed files**. If untracked source remains, the buyer receives a project that **fails to build on first run** — imports resolve to files that do not exist.

Check before packaging:

```bash
# Anything listed here (other than build output) will NOT reach the buyer
git status --porcelain --untracked-files=all | grep '^??' \
  | grep -vE 'node_modules|\.next/|tsbuildinfo|\.log$'
```

If that prints anything, commit it. Then prove the packaged result is complete:

```bash
git archive --format=zip --output=/tmp/check.zip HEAD
mkdir -p /tmp/verify && unzip -q /tmp/check.zip -d /tmp/verify
cd /tmp/verify && bun install && bun run build   # must succeed
```

**Do not skip that build check.** It is the only thing that proves the buyer's copy actually works, rather than just looking complete.

---

## 1. Do NOT hand over these files

| File | Why |
|---|---|
| `.env.local` | Contains **live production credentials** — database password, session secret, OAuth secrets, email password, API keys |
| `.env.*.local` | Same |
| `apis.txt` (repo root, if present) | Plaintext API keys |
| `.next/` | Build cache; may embed baked-in values |
| `node_modules/` | Rebuilt by `bun install` |

`.env.local` is gitignored, so a `git clone` or `git archive` will **not** include it. But a **ZIP of the folder will.**

**Safe way to package the source:**

```bash
# From the repository root — produces a clean archive with no ignored files
git archive --format=zip --output=octupus-voc.zip HEAD
```

Verify before sending:

```bash
unzip -l octupus-voc.zip | grep -iE "env|apis\.txt"
# Expect: only .env.example — nothing else
```

---

## 2. Rotate every credential

Anything that ever lived in your `.env.local` should be treated as compromised the moment the project changes hands — even if you never sent the file. The buyer must run on **their own** credentials, and your old ones must stop working.

| Credential | Action |
|---|---|
| `BETTER_AUTH_SECRET` | Buyer generates a fresh one (`bun run doctor:secret`). Never reuse yours — it signs sessions. |
| `DATABASE_URL` | Buyer creates their own database, **or** you transfer the Neon project and rotate the password. |
| `GMAIL_APP_PASSWORD` | **Revoke yours** at [myaccount.google.com/apppasswords](https://myaccount.google.com/apppasswords). Buyer creates their own. |
| `RESEND_API_KEY` | Revoke in the Resend dashboard. |
| `GOOGLE_CLIENT_SECRET` / `GITHUB_CLIENT_SECRET` | Buyer registers their **own** OAuth apps — these are tied to your accounts. |
| `TELEGRAM_BOT_TOKEN` | Buyer creates their own bot via @BotFather. Yours points at your chat. |
| `OPENROUTER_API_KEY` | Revoke — this one bills you per request. |
| `NVD_API_KEY`, `GITHUB_TOKEN` | Buyer requests their own (both free). |
| Exposure provider keys | Buyer signs up themselves — see [`exposure-providers-setup.md`](exposure-providers-setup.md). |
| `CRON_SECRET` | Buyer generates a fresh random string. |

> **Billing risk:** `OPENROUTER_API_KEY` and any paid EASM provider charge **your** account for **their** usage until revoked. Revoke these first.

---

## 3. What the buyer creates

Nothing here requires anything from you — all self-serve:

1. **Database** — [neon.tech](https://neon.tech), free tier is enough to start
2. **Email sending** — a Gmail App Password (free, ~500/day, no domain required)
3. **Hosting** — a Vercel account (free tier works)
4. *(optional)* OAuth apps, Telegram bot, NVD key, exposure provider keys

---

## 4. Transferring live infrastructure (optional)

Only if you're selling the **running deployment**, not just the source:

| Asset | How |
|---|---|
| **Vercel project** | Project Settings → Transfer, or the buyer re-imports the repo (cleaner) |
| **Neon database** | Transfer the project, or `pg_dump` → buyer restores into their own |
| **Domain** | Standard registrar transfer (auth code); update `BETTER_AUTH_URL` afterwards |
| **GitHub repository** | Settings → Transfer ownership |

After **any** transfer, the buyer must set `BETTER_AUTH_URL` to their domain and update the OAuth callback URLs — otherwise sign-in breaks and emails link to the wrong place.

---

## 5. Buyer's first run

Hand them this; it should be all they need:

```bash
bun install
cp .env.example .env.local
# fill in the REQUIRED section
bun run doctor      # must pass with no blocking issues
bun dev
```

`bun run doctor` verifies the database connection and every required value, and reports each optional feature as on or off. **If it reports blocking issues, the app will not work correctly** — resolve those before anything else.

Then, to enable automatic CVE syncing, add `APP_URL` and `CRON_SECRET` under the repository's **Settings → Secrets and variables → Actions**.

---

## 6. Pre-handover verification

Run these before you consider the transfer complete:

```bash
bun run typecheck   # 0 errors
bun test            # all passing
bun run build       # clean production build
bun run doctor      # your own environment still healthy
```

And confirm the packaged archive is clean:

```bash
unzip -l octupus-voc.zip | grep -iE "env|apis\.txt"   # only .env.example
```

---

## 7. Scope of what's included

Worth stating explicitly in writing, so expectations match:

**Included:** full source, database schema (auto-created), setup validation, documentation, the CVE/0-day collection pipeline, risk engine, and all UI.

**Not included and buyer-dependent:**

- **Third-party accounts and their quotas.** Free tiers vary and can change.
- **FOFA and ZoomEye** need paid credits to return data — code is complete, but the accounts must be funded.
- **Censys** — the search endpoint is unresolved against their current Platform API; the adapter is wired and auth works, but the query path needs confirming from the Censys API Explorer. Documented in `lib/exposure-providers.ts`.
- **Data licensing.** NVD, CISA KEV, and MITRE data are public, but each EASM provider's terms govern redistribution. Publishing aggregate counts is generally fine; republishing raw scan results generally is not. The buyer should review the terms for their intended use.

---

## 8. License

The repository ships a **proprietary, all-rights-reserved** license naming the original author. Before transfer, agree in writing which applies:

- **Full transfer of ownership** — update `LICENSE` and the copyright line to the buyer.
- **A license to use** — keep the current license and attach the grant terms.
- **Non-exclusive resale** — state explicitly whether the buyer may resell or redistribute.

The current `LICENSE` grants the buyer nothing by default, so leaving it unchanged after a full sale will not reflect the deal.
