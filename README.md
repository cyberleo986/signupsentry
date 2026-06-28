# SignupSentry

> Drop-in fraud detection for SaaS free tiers. Stop fake signups, bot networks, and brand impersonation in 5 lines of JS.

**Status:** Building in public. Day 0 of 7.
**Tagline:** *The signup form your free tier deserves.*

---

## Why this exists

Every SaaS with a free tier is bleeding. Bot networks spin up dozens-to-hundreds of fake accounts. Disposable-email domains bypass static blocklists. Brand impersonation turns your signup flow into a phishing launchpad. Founders spend hours every day playing whack-a-mole — or kill the free tier and lose their #1 acquisition channel.

**Nobody owns "drop-in fraud detection for indie SaaS under $50/mo."** Castle / Sift / Arkose are enterprise. Stripe Radar is per-transaction. Cloudflare Turnstile is a CAPTCHA, not a scoring engine. The gap is wide and the pain is universal.

SignupSentry fills it: an API + drop-in widget that scores every signup 0-100, explains why, and lets you block, flag, or pass — in real time, at $19/mo for 100K checks.

---

## What ships at MVP (Day 7)

**Core API**
- `POST /v1/check` — `{ email, ip, user_agent, fingerprint }` → `{ score: 0-100, action: block|flag|pass, reasons: [...] }`
- Free tier: 10K checks/mo
- Paid Solo: $19/mo, 100K checks
- Paid Team: $49/mo, 1M checks + custom rules + Slack/Telegram alerts

**Open-source assets (the moat)**
- Disposable-email-domain list (5,000+ domains, daily refresh, public on GH)
- Brand-impersonation list (Levenshtein distance vs Apple/Spotify/Stripe/etc.)
- Scoring engine (rule-based, no external ML dependency)
- Drop-in JS widget (5 lines, no jQuery, async)

**Dashboard (minimal v1)**
- API key + usage graph + recent blocks list
- Webhook URL for high-risk events

**Distribution**
- dev.to post: "How to spot a fake signup in 2026" (publishes day 5)
- Show HN draft (submits day 6)
- README with 5-minute quickstart

---

## Pricing rationale

| Tier | Price | Checks/mo | Per-check cost |
|---|---|---|---|
| Free | $0 | 10,000 | free |
| Solo | $19 | 100,000 | $0.00019 |
| Team | $49 | 1,000,000 | $0.000049 |

Per-check cost is intentionally below what abuse would burn — so the buyer is *always* ahead even if they get a few false positives.

---

## Open source license

- **List + scoring rules + widget:** MIT (free, public)
- **Hosted API:** proprietary
- **Self-host instructions:** included in README

This is the Sentry/Supabase playbook: open-source the engine, charge for hosted convenience.

---

## Day-by-day build plan

- **Day 0 (today):** repo, README, MIT license, package.json, scoring engine skeleton
- **Day 1-2:** /v1/check API, SQLite store, disposable-email lookup, brand-impersonation rule
- **Day 3:** drop-in JS widget (5 lines)
- **Day 4:** dev.to post draft + landing page
- **Day 5:** Stripe checkout, free tier meter, simple dashboard
- **Day 6:** Show HN draft, documentation, demo gif
- **Day 7:** DM 2 r/SaaS posters, free integration, ship to npm + GitHub

---

## Repo structure

```
signupsentry/
├── README.md          # you are here
├── LICENSE            # MIT
├── package.json
├── src/
│   ├── index.js       # express app
│   ├── scoring.js     # the moat
│   ├── disposable.js  # email-domain check
│   ├── brand.js       # impersonation check
│   ├── fingerprint.js # UA + IP heuristics
│   └── db.js          # SQLite layer
├── data/
│   ├── disposable-domains.txt
│   └── brand-list.txt
├── public/
│   └── widget.js      # 5-line drop-in
├── test/
│   └── *.test.js
└── scripts/
    └── refresh-domains.sh
```

---

## Why "SignupSentry"

Owns the niche ("signup fraud" → "SignupSentry"), plays as a verb ("sentry your signups"), and parallels the Sentry brand association (devs already trust the name pattern). Available on npm as `signupsentry`.

---

*Built by BizClaw. Pivoted from HYRVΞ on 2026-06-28. Pain verified via r/SaaS scanner.*
*Public repo: github.com/cyberleo986/signupsentry (pending — repo goes live day 1)*