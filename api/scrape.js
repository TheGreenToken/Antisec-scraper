export default async function handler(req, res) {
  // CORS headers so the frontend can call us
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'GET') {
    return res.status(405).json({ ok: false, error: 'Method not allowed' });
  }

  const { url } = req.query;

  if (!url) {
    return res.status(400).json({ ok: false, error: 'Missing ?url= parameter' });
  }

  // Normalize URL
  let targetURL;
  try {
    const raw = /^https?:\/\//i.test(url) ? url : 'https://' + url;
    targetURL = new URL(raw);
  } catch (e) {
    return res.status(400).json({ ok: false, error: 'Invalid URL: ' + e.message });
  }

  // Block private/internal IPs
  const host = targetURL.hostname.toLowerCase();
  const blocked = ['localhost', '127.0.0.1', '0.0.0.0', '::1'];
  if (blocked.includes(host) || /^10\.|^192\.168\.|^172\.(1[6-9]|2\d|3[01])\./.test(host)) {
    return res.status(403).json({ ok: false, error: 'Access to private network addresses is not allowed.' });
  }

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 20000);

    const response = await fetch(targetURL.href, {
      method: 'GET',
      headers: {
        'User-Agent':
          'Mozilla/5.0 (Windows NT 10.0; Win64; x64) ' +
          'AppleWebKit/537.36 (KHTML, like Gecko) ' +
          'Chrome/124.0.0.0 Safari/537.36',
        Accept:
          'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate, br',
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
        'Cache-Control': 'no-cache',
      },
      redirect: 'follow',
      signal: controller.signal,
    });

    clearTimeout(timeout);

    const contentType = response.headers.get('content-type') || 'text/html';

    // Only allow text-based responses
    if (
      !contentType.includes('text/') &&
      !contentType.includes('application/json') &&
      !contentType.includes('application/xhtml')
    ) {
      return res.status(200).json({
        ok: false,
        error: `Unsupported content type: ${contentType.split(';')[0]}. AntiSec only supports HTML/text pages.`,
      });
    }

    const html = await response.text();

    if (!html || html.length < 10) {
      return res.status(200).json({
        ok: false,
        error: 'Target returned an empty response.',
      });
    }

    // Cache for 60s on Vercel edge
    res.setHeader('Cache-Control', 's-maxage=60, stale-while-revalidate=30');

    return res.status(200).json({
      ok: true,
      url: targetURL.href,
      finalUrl: response.url || targetURL.href,
      httpCode: response.status,
      contentType: contentType,
      contents: html,
      sizeBytes: html.length,
    });
  } catch (err) {
    const isTimeout = err.name === 'AbortError';
    return res.status(200).json({
      ok: false,
      error: isTimeout
        ? 'Request timed out after 20 seconds. The target may be unreachable or very slow.'
        : `Fetch failed: ${err.message}`,
    });
  }
}
