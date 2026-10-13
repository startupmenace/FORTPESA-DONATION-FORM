const net = require('net');
const dns = require('dns');
dns.setDefaultResultOrder('ipv4first');
net.setDefaultAutoSelectFamilyAttemptTimeout(5000);
require('dotenv').config();
const express = require('express');
const crypto = require('crypto');

const API = 'https://fortpesa.co.ke/api/v1';
const { FORTPESA_API_KEY, FORTPESA_CHANNEL_ID, FORTPESA_WEBHOOK_SECRET, PORT = 3000 } = process.env;
const MIN_AMOUNT = 1;

if (!FORTPESA_API_KEY || !FORTPESA_CHANNEL_ID) {
  console.error('Set FORTPESA_API_KEY and FORTPESA_CHANNEL_ID in .env (see .env.example)');
  process.exit(1);
}

async function fortpesa(path, options = {}) {
  const res = await fetch(API + path, {
    ...options,
    headers: {
      Authorization: `Bearer ${FORTPESA_API_KEY}`,
      'Content-Type': 'application/json',
      Accept: 'application/json',
      ...options.headers,
    },
  });
  const body = await res.json().catch(() => ({}));
  return { status: res.status, body };
}

// 0712…, 712…, +254712… -> 254712345678
function normalizePhone(input) {
  let p = String(input || '').replace(/[\s\-+]/g, '');
  if (/^0[17]\d{8}$/.test(p)) p = '254' + p.slice(1);
  else if (/^[17]\d{8}$/.test(p)) p = '254' + p;
  return /^254[17]\d{8}$/.test(p) ? p : null;
}

const FRIENDLY = {
  INSUFFICIENT_BALANCE: 'Donations are temporarily unavailable. Please try again later.',
  CHANNEL_NOT_APPROVED: 'Donations are temporarily unavailable. Please try again later.',
  CHANNEL_NOT_FOUND: 'Donations are temporarily unavailable. Please try again later.',
  UNAUTHENTICATED: 'Donations are temporarily unavailable. Please try again later.',
  RATE_LIMITED: 'Too many attempts. Wait a moment and try again.',
  VALIDATION_ERROR: 'Check the amount and phone number, then try again.',
};

const app = express();

// Webhook needs the RAW body for HMAC verification, so register it before express.json()
app.post('/api/webhook', express.raw({ type: '*/*' }), (req, res) => {
  const ts = req.get('X-Fortpesa-Timestamp');
  const sig = req.get('X-Fortpesa-Signature') || '';
  if (!FORTPESA_WEBHOOK_SECRET || !ts || Math.abs(Date.now() / 1000 - Number(ts)) > 300) {
    return res.sendStatus(400);
  }
  const expected =
    'sha256=' +
    crypto.createHmac('sha256', FORTPESA_WEBHOOK_SECRET).update(`${ts}.`).update(req.body).digest('hex');
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return res.sendStatus(401);

  res.sendStatus(200); // acknowledge fast, then verify state with the API
  (async () => {
    try {
      const uuid = JSON.parse(req.body.toString())?.data?.uuid;
      const { body } = await fortpesa(`/transactions/${encodeURIComponent(uuid)}`);
      const tx = body.data;
      if (tx?.status === 'success') {
        // Trusted result: record the donation, send a receipt, etc.
        console.log(`Donation received: KES ${tx.amount} (${tx.uuid})`);
      }
    } catch (err) {
      console.error('Webhook handling failed:', err.message);
    }
  })();
});

app.use(express.json());
app.use(express.static('public'));

app.post('/api/donate', async (req, res) => {
  const amount = Number(req.body.amount);
  const phone = normalizePhone(req.body.phone);
  const intentId = String(req.body.intentId || '');

  if (!Number.isInteger(amount) || amount < MIN_AMOUNT || amount > 150000) {
    return res.status(422).json({ error: { message: `Enter a whole amount from KES ${MIN_AMOUNT} to 150,000.` } });
  }
  if (!phone) {
    return res.status(422).json({ error: { message: 'Enter a valid Safaricom number, like 0712 345 678.' } });
  }
  if (!/^[A-Za-z0-9._:-]{8,64}$/.test(intentId)) {
    return res.status(422).json({ error: { message: 'Invalid request. Refresh the page and try again.' } });
  }

  try {
    const { status, body } = await fortpesa('/payments/stk', {
      method: 'POST',
      headers: { 'Idempotency-Key': `don-${intentId}` },
      body: JSON.stringify({
        amount, // whole KES integer
        phone,
        channel_id: Number(FORTPESA_CHANNEL_ID),
        account_reference: 'DONATION', // max 12 chars
        description: 'Donation', // max 13 chars
      }),
    });

    if (status === 200 || status === 201) return res.status(201).json({ uuid: body.data.uuid });

    const code = body?.error?.code;
    console.error('Fortpesa STK error:', status, code, body?.error?.message);
    res.status(status === 422 ? 422 : 502).json({
      error: { message: FRIENDLY[code] || 'We could not start the payment. Please try again.' },
    });
  } catch (err) {
    console.error('Fortpesa request failed:', err.message);
    res.status(502).json({ error: { message: 'We could not reach the payment service. Please try again.' } });
  }
});

app.get('/api/status/:uuid', async (req, res) => {
  if (!/^[0-9a-f-]{36}$/i.test(req.params.uuid)) return res.sendStatus(400);
  try {
    const { status, body } = await fortpesa(`/transactions/${req.params.uuid}`);
    if (status !== 200) return res.status(502).json({ error: { message: 'Could not check the payment.' } });
    res.json({ status: body.data.status });
  } catch {
    res.status(502).json({ error: { message: 'Could not check the payment.' } });
  }
});

app.listen(PORT, () => console.log(`Donation app running at http://localhost:${PORT}`));
