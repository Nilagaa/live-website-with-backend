// netlify/functions/login.js
// Reads user credentials stored in Netlify Blobs (persistent key-value store)

const { getStore } = require('@netlify/blobs');
const crypto = require('crypto');

function hashPassword(password) {
  return crypto.createHash('sha256').update(password).digest('hex');
}

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: JSON.stringify({ error: 'Method not allowed' }) };
  }

  try {
    const { username, password } = JSON.parse(event.body);

    if (!username || !password) {
      return { statusCode: 400, body: JSON.stringify({ error: 'Username and password required' }) };
    }

    // Connect to Netlify Blobs store named "users"
    const store = getStore('users');

    // Look up user record
    const userData = await store.get(username.toLowerCase(), { type: 'json' });

    if (!userData) {
      return {
        statusCode: 401,
        body: JSON.stringify({ success: false, error: 'Invalid username or password' })
      };
    }

    const hashedInput = hashPassword(password);
    if (hashedInput !== userData.passwordHash) {
      return {
        statusCode: 401,
        body: JSON.stringify({ success: false, error: 'Invalid username or password' })
      };
    }

    const token = Buffer.from(`${username}:${Date.now()}:${Math.random()}`).toString('base64');

    return {
      statusCode: 200,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ success: true, token })
    };

  } catch (err) {
    console.error('Login error:', err);
    return {
      statusCode: 500,
      body: JSON.stringify({ error: 'Internal server error' })
    };
  }
};
