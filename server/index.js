// index.js
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const { verifySignature } = require('./verifySignature');
const Redis = require('ioredis');
const { v4: uuidv4 } = require('uuid');

const app = express();
app.use(cors());
app.use(bodyParser.json());

// Configure Redis client via env or defaults
const redis = new Redis({
  host: process.env.REDIS_HOST || '127.0.0.1',
  port: process.env.REDIS_PORT ? parseInt(process.env.REDIS_PORT) : 6379,
  password: process.env.REDIS_PASSWORD || undefined,
});

// Health
app.get('/', (req,res) => res.json({ ok: true }));

// Verify a signature (message + signature -> recover address)
app.post('/verify-signature', (req,res) => {
  const { address, message, signature } = req.body;
  if(!address || !message || !signature) return res.status(400).json({ ok:false, error:'missing fields' });
  try {
    const ok = verifySignature(address, message, signature);
    return res.json({ ok });
  } catch(e){
    console.error(e);
    return res.status(500).json({ ok:false, error:'exception' });
  }
});

// Start processing / create session (requires signature proof)
app.post('/start-processing', async (req,res) => {
  const { address, message, signature } = req.body;
  if(!address || !message || !signature) return res.status(400).json({ ok:false, error:'missing' });

  try {
    const ok = verifySignature(address, message, signature);
    if(!ok) return res.status(403).json({ ok:false, error:'signature invalid' });

    // create session
    const sessionId = uuidv4();
    const now = Date.now();
    const expiry = now + 24*60*60*1000; // 24 hours in ms

    const key = `session:${sessionId}`;
    const payload = JSON.stringify({ address, start: now, expiry });
    // store with TTL (seconds)
    await redis.set(key, payload, 'PX', 24*60*60*1000); // PX sets TTL in ms
    return res.json({ ok: true, sessionId, start: now, expiry });
  } catch(e){
    console.error(e);
    return res.status(500).json({ ok:false, error:'exception' });
  }
});

// Query session
app.get('/session/:id', async (req,res) => {
  const id = req.params.id;
  if(!id) return res.status(400).json({ ok:false, error:'missing id' });
  try {
    const key = `session:${id}`;
    const raw = await redis.get(key);
    if(!raw) return res.json({ ok:false, error:'not_found' });
    const obj = JSON.parse(raw);
    // Calculate remaining time by retrieving TTL from Redis in ms:
    const ttlSeconds = await redis.pttl(key); // pttl returns ms remaining or -2 if not exist
    const remainingMs = ttlSeconds >= 0 ? ttlSeconds : 0;
    return res.json({ ok:true, address: obj.address, start: obj.start, expiry: obj.expiry, remainingMs });
  } catch(e){
    console.error(e);
    return res.status(500).json({ ok:false, error:'exception' });
  }
});

// Optional: delete session (admin)
app.delete('/session/:id', async (req,res) => {
  const id = req.params.id;
  if(!id) return res.status(400).json({ ok:false, error:'missing id' });
  try {
    const key = `session:${id}`;
    await redis.del(key);
    res.json({ ok:true });
  } catch(e){
    res.status(500).json({ ok:false, error:'exception' });
  }
});

const port = process.env.PORT || 4000;
app.listen(port, ()=> {
  console.log('Server listening on port', port);
});
