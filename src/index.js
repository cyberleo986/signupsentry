// SignupSentry — fraud detection API for SaaS free tiers
// POST /v1/check → score 0-100, action (block/flag/pass), reasons[]
//
// Endpoints:
//   POST /v1/check      (free or with API key)
//   GET  /v1/usage      (with API key — usage stats)
//   POST /v1/stripe/webhook  (subscription fulfillment)
//   GET  /dashboard     (simple usage dashboard)
//
// Pricing:
//   Free — 10K checks/mo
//   Solo — $19/mo, 100K checks
//   Team — $49/mo, 1M checks + custom rules

import express from 'express';
import Stripe from 'stripe';
import { UAParser } from 'ua-parser-js';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// === Env ===
const envPath = path.join(__dirname, '..', '.env');
if (fs.existsSync(envPath)) {
  for (const line of fs.readFileSync(envPath, 'utf8').split('\n')) {
    const m = line.match(/^([A-Z0-9_]+)=(.*)$/);
    if (m && !process.env[m[1]]) process.env[m[1]] = m[2];
  }
}

const stripe = new Stripe(process.env.STRIPE_API_KEY);
const PORT = parseInt(process.env.PORT || '10000', 10);

// === Load data assets ===
const DATA_DIR = path.join(__dirname, '..', 'data');
const disposable = new Set(
  fs.readFileSync(path.join(DATA_DIR, 'disposable-domains.txt'), 'utf8')
    .split('\n').map(l => l.trim().toLowerCase()).filter(l => l && !l.startsWith('#'))
);
const brands = fs.readFileSync(path.join(DATA_DIR, 'brand-list.txt'), 'utf8')
  .split('\n').map(l => l.trim().toLowerCase()).filter(l => l && !l.startsWith('#'));

// === SQLiteless — file-based store ===
const STORE = path.join(__dirname, '..', 'store.json');
function readStore() {
  if (!fs.existsSync(STORE)) return { apiKeys: {}, usage: {}, subscriptions: {} };
  return JSON.parse(fs.readFileSync(STORE, 'utf8'));
}
function writeStore(s) {
  fs.writeFileSync(STORE, JSON.stringify(s, null, 2));
}

// === Abuse protection (mirror roastmylp) ===
const RATE = { perIp: new Map(), global: { count: 0, resetAt: Date.now() + 60_000 }, blockedIps: new Map() };
const PER_IP_LIMIT = 30;       // /v1/check is cheaper; allow 30/10min
const PER_IP_WINDOW_MS = 10 * 60_000;
const GLOBAL_LIMIT = 200;
const BLOCK_AFTER_FAILS = 10;
const BLOCK_DURATION_MS = 60 * 60_000;

function clientIp(req) {
  return req.headers['cf-connecting-ip'] ||
    (req.headers['x-forwarded-for'] || '').split(',')[0].trim() ||
    req.socket?.remoteAddress || 'unknown';
}
function isPrivateOrLocalHost(hostname) {
  if (!hostname) return true;
  const h = hostname.toLowerCase();
  if (h === 'localhost' || h === '127.0.0.1' || h === '0.0.0.0') return true;
  if (h.endsWith('.localhost') || h.endsWith('.local')) return true;
  if (/^(10|127|169\.254|172\.(1[6-9]|2\d|3[0-1])|192\.168)\./.test(h)) return true;
  return false;
}
function checkRateLimit(ip) {
  const now = Date.now();
  const blockedUntil = RATE.blockedIps.get(ip);
  if (blockedUntil && blockedUntil > now) return { ok: false, retryAfter: Math.ceil((blockedUntil - now) / 1000) };
  if (blockedUntil && blockedUntil <= now) RATE.blockedIps.delete(ip);
  if (now > RATE.global.resetAt) RATE.global = { count: 0, resetAt: now + 60_000 };
  if (RATE.global.count >= GLOBAL_LIMIT) return { ok: false, retryAfter: 60 };
  let bucket = RATE.perIp.get(ip);
  if (!bucket || now > bucket.resetAt) bucket = { count: 0, resetAt: now + PER_IP_WINDOW_MS, failCount: 0 };
  if (bucket.count >= PER_IP_LIMIT) return { ok: false, retryAfter: Math.ceil((bucket.resetAt - now) / 1000) };
  bucket.count++;
  RATE.global.count++;
  RATE.perIp.set(ip, bucket);
  return { ok: true };
}
function recordFailure(ip) {
  const bucket = RATE.perIp.get(ip) || { count: 0, resetAt: Date.now() + PER_IP_WINDOW_MS, failCount: 0 };
  bucket.failCount = (bucket.failCount || 0) + 1;
  RATE.perIp.set(ip, bucket);
  if (bucket.failCount >= BLOCK_AFTER_FAILS) {
    RATE.blockedIps.set(ip, Date.now() + BLOCK_DURATION_MS);
  }
}

// === Scoring engine ===
function levenshtein(a, b) {
  const m = a.length, n = b.length;
  if (Math.abs(m - n) > 3) return Math.max(m, n); // short-circuit
  const dp = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] = a[i-1] === b[j-1] ? dp[i-1][j-1] : Math.min(dp[i-1][j], dp[i][j-1], dp[i-1][j-1]) + 1;
    }
  }
  return dp[m][n];
}

function score({ email, ip, user_agent, fingerprint, name }) {
  const reasons = [];
  let score = 0;

  // 1. Disposable email domain (+50)
  if (email && email.includes('@')) {
    const domain = email.split('@')[1].toLowerCase().trim();
    if (disposable.has(domain)) {
      score += 50;
      reasons.push({ code: 'disposable_email', weight: 50, detail: `${domain} is a known disposable email provider` });
    }
    // Numeric/alphanumeric local part (bot pattern) (+15)
    const local = email.split('@')[0];
    if (/^[a-z0-9]{20,}$/i.test(local)) {
      score += 15;
      reasons.push({ code: 'random_local', weight: 15, detail: 'Email local part looks auto-generated' });
    }
    // Free webmail — not by itself risky (+0), but combined with other signals matters
  }

  // 2. Brand impersonation in name (+30 if Levenshtein <= 3 AND same first letter)
  // Catches: Appie→apple (dist 2), Sttripe→stripe (dist 2), PayPaI→paypal (dist 1, case-folding only)
  if (name && typeof name === 'string') {
    const nameNorm = name.toLowerCase().replace(/[^a-z0-9]/g, '').trim();
    if (nameNorm.length >= 3) {
      for (const brand of brands) {
        const dist = levenshtein(nameNorm, brand);
        // Match if: distance ≤ 3 AND shares first letter AND length within ±2
        if (dist > 0 && dist <= 3 && nameNorm[0] === brand[0] &&
            Math.abs(nameNorm.length - brand.length) <= 2) {
          score += 30;
          reasons.push({
            code: 'brand_squat',
            weight: 30,
            detail: `"${name}" is ${dist} edit${dist === 1 ? '' : 's'} from protected brand "${brand}"`,
          });
          break;
        }
      }
    }
  }

  // 3. Missing or suspicious user-agent (+20)
  if (!user_agent || user_agent.length < 10) {
    score += 20;
    reasons.push({ code: 'no_ua', weight: 20, detail: 'Missing or empty User-Agent' });
  } else {
    const ua = user_agent.toLowerCase();
    if (ua.includes('curl/') || ua.includes('wget/') || ua.includes('python-requests') || ua.includes('httpie') || ua.includes('bot')) {
      score += 20;
      reasons.push({ code: 'tool_ua', weight: 20, detail: 'User-Agent is a CLI tool or known bot' });
    }
  }

  // 4. No fingerprint AND no UA (+10 combined)
  if (!fingerprint && (!user_agent || user_agent.length < 10)) {
    score += 10;
    reasons.push({ code: 'no_device', weight: 10, detail: 'No fingerprint + no UA — likely automated' });
  }

  // 5. Private/local IP (in tests only, no penalty in production where CF hides real IP)
  if (ip && (isPrivateOrLocalHost(ip.split(',')[0].trim()) || ip.startsWith('::ffff:'))) {
    score += 5;
    reasons.push({ code: 'private_ip', weight: 5, detail: 'Client appears to be from a private/local network' });
  }

  score = Math.max(0, Math.min(100, score));

  let action;
  if (score >= 70) action = 'block';
  else if (score >= 40) action = 'flag';
  else action = 'pass';

  return { score, action, reasons };
}

// === App ===
const app = express();
app.use(express.json({ limit: '256kb' }));
app.use(express.static(path.join(__dirname, '..', 'public')));

app.get('/health', (req, res) => res.json({ ok: true, ts: Date.now(), service: 'signupsentry' }));

// === Pricing / Product page (HTML) ===
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'public', 'index.html'));
});

// === Core API ===
app.post('/v1/check', async (req, res) => {
  try {
    const ip = clientIp(req);
    const rl = checkRateLimit(ip);
    if (!rl.ok) return res.status(429).json({ error: 'rate_limited', retryAfter: rl.retryAfter });

    const { email, user_agent, fingerprint, name } = req.body || {};

    if (!email || typeof email !== 'string' || !email.includes('@') || email.length > 254) {
      recordFailure(ip);
      return res.status(400).json({ error: 'invalid_email', detail: 'Provide { email: "user@domain.tld" }' });
    }

    const headers = req.headers['x-ss-name'] ? { name: String(req.headers['x-ss-name']).slice(0, 100) } : { name };
    const result = score({
      email,
      ip,
      user_agent: user_agent || req.headers['user-agent'],
      fingerprint,
      name: headers.name,
    });

    // Track usage (count by hashed email or api-key)
    const apiKey = req.headers['authorization']?.replace(/^Bearer\s+/, '') || 'anon';
    const store = readStore();
    const month = new Date().toISOString().slice(0, 7); // YYYY-MM
    const usageKey = `${apiKey}::${month}`;
    store.usage[usageKey] = (store.usage[usageKey] || 0) + 1;
    writeStore(store);

    res.json({ ...result, ts: Date.now(), requestId: crypto.randomUUID() });
  } catch (e) {
    console.error('check error:', e.message);
    res.status(500).json({ error: 'internal' });
  }
});

// === Stripe Checkout (subscriptions) ===
app.post('/api/checkout', async (req, res) => {
  try {
    const { tier } = req.body || {};
    if (!['solo', 'team'].includes(tier)) {
      return res.status(400).json({ error: 'invalid_tier', detail: 'tier must be "solo" or "team"' });
    }
    const prices = { solo: 1900, team: 4900 }; // cents
    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      payment_method_types: ['card'],
      line_items: [{
        price_data: {
          currency: 'usd',
          product_data: {
            name: `Signupsentry ${tier === 'solo' ? 'Solo' : 'Team'}`,
            description: tier === 'solo'
              ? '100K signup checks/mo + webhook alerts + dashboard'
              : '1M signup checks/mo + custom rules + Slack/Telegram alerts + dedicated support',
          },
          unit_amount: prices[tier],
          recurring: { interval: 'month' },
        },
        quantity: 1,
      }],
      success_url: `${req.headers.origin || 'https://signupsentry.onrender.com'}/?session_id={CHECKOUT_SESSION_ID}&tier=${tier}`,
      cancel_url: `${req.headers.origin || 'https://signupsentry.onrender.com'}/?canceled=1`,
      metadata: { tier },
    });
    res.json({ url: session.url, sessionId: session.id });
  } catch (e) {
    console.error('checkout error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// === Stripe webhook (subscription fulfillment) ===
app.post('/v1/stripe/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET || 'whsec_dev');
  } catch (err) {
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  if (event.type === 'checkout.session.completed' || event.type === 'invoice.paid') {
    const session = event.data.object;
    const customerEmail = session.customer_details?.email || session.customer_email;
    const tier = session.metadata?.tier;
    if (customerEmail && tier) {
      const store = readStore();
      const apiKey = 'sk_' + crypto.randomBytes(16).toString('hex');
      store.subscriptions[customerEmail] = {
        tier,
        apiKey,
        status: 'active',
        stripeCustomerId: session.customer,
        stripeSubscriptionId: session.subscription,
        ts: Date.now(),
      };
      writeStore(store);
      console.log(`[subscription] ${customerEmail} → ${tier} (key: ${apiKey.slice(0, 12)}…)`);
    }
  }

  res.json({ received: true });
});

// === Dashboard (HTML — minimal usage page) ===
app.get('/dashboard', (req, res) => {
  res.set('Content-Type', 'text/html');
  const store = readStore();
  const totalChecks = Object.values(store.usage).reduce((s, v) => s + v, 0);
  const totalSubs = Object.keys(store.subscriptions).length;
  res.send(`<!DOCTYPE html><html><head><title>SignupSentry Dashboard</title>
<style>body{font-family:system-ui;max-width:800px;margin:40px auto;padding:0 20px;color:#1a1a1a}
h1{font-size:32px}h2{font-size:18px;margin-top:32px;color:#666}
.card{background:#f5f5f5;border-radius:8px;padding:20px;margin:12px 0}
.metric{font-size:36px;font-weight:700;color:#0066ff}</style></head><body>
<h1>SignupSentry</h1>
<p>Drop-in fraud detection for SaaS free tiers. <a href="/">Home</a></p>
<div class="card"><div class="metric">${totalChecks.toLocaleString()}</div>Total checks served</div>
<div class="card"><div class="metric">${totalSubs}</div>Active subscriptions</div>
<h2>Quick start</h2>
<pre style="background:#0a0a0a;color:#0f0;padding:16px;border-radius:8px;overflow-x:auto">
curl -X POST https://signupsentry.onrender.com/v1/check \\
  -H "Content-Type: application/json" \\
  -d '{"email":"test@mailinator.com","user_agent":"Mozilla/5.0..."}'
</pre>
</body></html>`);
});

app.listen(PORT, () => console.log(`🛡️  SignupSentry on :${PORT}`));