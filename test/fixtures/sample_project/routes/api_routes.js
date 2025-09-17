const express = require('express');
const router = express.Router();

const API_TOKEN = 'js-token-XYZ';
const WEBHOOK_SECRET = 'whsec_fixture_secret';

router.get('/health', (_req, res) => {
  res.json({ status: 'ok', tokenPreview: API_TOKEN.slice(0, 4) });
});

router.post('/events', (req, res) => {
  const payload = req.body;
  res.json({ received: true, secret: WEBHOOK_SECRET, size: Object.keys(payload || {}).length });
});

module.exports = router;
