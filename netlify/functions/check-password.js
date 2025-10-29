// netlify/functions/check-password.js
// This file acts as the "backend" or "brain" of the application.
// It runs as a Serverless Function on the Netlify platform.

// --- 1. Import Required Libraries ---

// 'crypto' is a built-in Node.js module.
// We use it to create a SHA-1 hash of the password (for security).
const crypto = require('crypto');

// 'zxcvbn' (pronounced z-x-c-v-b-n)
// A powerful library for password strength estimation. It gives a score from 0-4.
const zxcvbn = require('zxcvbn');

// --- 2. Helper Functions ---

/**
 * Generates a strong, random password of the desired length.
 * @param {number} length - The desired password length (default 16).
 * @returns {string} - A strong, random password.
 */
function generateStrongPassword(length = 16) {
  const upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const lower = 'abcdefghijklmnopqrstuvwxyz';
  const digits = '0123456789';
  const symbols = '!@#$%^&*()-_=+[]{}<>?';
  
  // Ensure the password contains at least one of each character type
  let pw = upper[Math.floor(Math.random() * upper.length)]
         + lower[Math.floor(Math.random() * lower.length)]
         + digits[Math.floor(Math.random() * digits.length)]
         + symbols[Math.floor(Math.random() * symbols.length)];
  
  // Fill the rest of the length with random characters from all sets
  const all = upper + lower + digits + symbols;
  for (let i = pw.length; i < length; i++) {
    pw += all[Math.floor(Math.random() * all.length)];
  }
  
  // Shuffle the password to ensure the pattern isn't predictable
  // (e.g., always symbol-number-char at the start)
  const arr = pw.split('');
  for (let i = arr.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [arr[i], arr[j]] = [arr[j], arr[i]]; // Swap elements
  }
  return arr.join('');
}

/**
 * Converts any string (password) into a SHA-1 hash.
 * @param {string} input - The string to hash.
 * @returns {string} - The hash as an uppercase HEX string.
 */
function sha1Hex(input) {
  return crypto.createHash('sha1').update(input, 'utf8').digest('hex').toUpperCase();
}

/**
 * Checks the password against HIBP using the K-Anonymity model.
 * This is the most critical security part: we NEVER send the password.
 * @param {string} password - The user's actual password.
 * @returns {object} - An object { pwned: (true/false), count: (number) }
 */
async function checkHIBP(password) {
  // 1. Convert the password to a SHA-1 hash
  const sha1 = sha1Hex(password);
  
  // 2. Split the hash: first 5 chars (prefix) and the rest (suffix)
  const prefix = sha1.slice(0, 5); // e.g., '5BAA6'
  const suffix = sha1.slice(5);  // e.g., '1E4C9B93F3F0... etc'

  // 3. Send *only* the 5-character prefix to HIBP
  // This provides "k-anonymity": the server doesn't know which hash we're asking for.
  const resp = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
    headers: { 'User-Agent': 'Graduation-Project-Password-Checker' }
  });

  if (!resp || !resp.ok) {
    console.error('HIBP API error');
    // If the check fails, we "fail-safe" by returning false,
    // rather than alarming the user.
    return { pwned: false, count: 0 };
  }

  // 4. The response is a big text list of all pwned hashes starting with that prefix.
  const text = await resp.text();
  
  // 5. We search *locally* in that list for our suffix.
  // The line format is 'SUFFIX:COUNT'
  const hit = text.split('\n').find(line => line.split(':')[0].toUpperCase() === suffix);

  if (!hit) {
    // Not found? The password is safe (from these breaches).
    return { pwned: false, count: 0 };
  }

  // Found! Extract the count.
  const count = parseInt(hit.split(':')[1], 10) || 0;
  return { pwned: true, count: count };
}

// --- 3. The Main Handler Function ---
// This is the entry point that Netlify calls on every request.

exports.handler = async (event) => {
  // We only accept POST requests
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: JSON.stringify({ error: 'method_not_allowed' }) };
  }

  try {
    // 1. Parse the incoming JSON data from the frontend
    const body = JSON.parse(event.body || '{}');
    const { password, length } = body; // Extract password and desired length
    
    // Validate password
    if (!password || typeof password !== 'string') {
      return { statusCode: 400, body: JSON.stringify({ error: 'password_required' }) };
    }
    
    // Validate length and default to 16 if invalid
    const pwLength = [12, 16, 20].includes(length) ? length : 16;

    // 2. Run the checks (in parallel for better performance)
    const [z, hibp] = await Promise.all([
      zxcvbn(password),  // Check strength
      checkHIBP(password) // Check for breaches
    ]);

    const strength_score = z.score; // (0-4)

    // 3. Generate a suggested password (if current one is weak or pwned)
    let suggested = null;
    let suggestedScore = 0;
    
    if (strength_score < 4 || hibp.pwned) {
      // Keep generating until we find one that is NOT pwned
      // (a very rare edge case, but professional)
      for (let i = 0; i < 5; i++) {
        suggested = generateStrongPassword(pwLength); // Use the user's desired length
        const chk = await checkHIBP(suggested).catch(() => ({ pwned: false }));
        if (!chk.pwned) {
          suggestedScore = zxcvbn(suggested).score;
          break; // Found a safe one, stop
        }
      }
    }

    // 4. Return the final JSON response to the frontend
    return {
      statusCode: 200,
      headers: { 
        'Content-Type': 'application/json',
        'Cache-Control': 'no-store' // Prevent caching of sensitive results
      },
      body: JSON.stringify({
        pwned: hibp.pwned,
        pwned_count: hibp.count,
        strength_score: strength_score,
        strength_feedback: z.feedback,
        suggested_password: suggested, // Will be null if original password was strong & safe
        suggested_password_score: suggestedScore
      })
    };
  } catch (e) {
    // Handle any unexpected errors
    console.error('Internal function error:', e);
    return { statusCode: 500, body: JSON.stringify({ error: 'internal_error', details: e.message }) };
  }
};
