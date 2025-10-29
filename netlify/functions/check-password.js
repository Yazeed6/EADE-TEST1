// netlify/functions/check-password.js
// هذا الملف يمثل "الخلفية" أو "الدماغ" للتطبيق
// إنه يعمل كـ "دالة عديمة الخادم" (Serverless Function) على منصة Netlify

// --- 1. جلب المكتبات المطلوبة ---

// مكتبة 'crypto' مدمجة في Node.js
// نستخدمها لإنشاء بصمة SHA-1 لكلمة المرور (لأغراض أمنية)
const crypto = require('crypto');

// مكتبة 'zxcvbn' (تُنطق z-x-c-v-b-n)
// هي مكتبة قوية جداً لتقييم قوة كلمة المرور، تعطيها درجة من 0 إلى 4
const zxcvbn = require('zxcvbn');

// --- 2. الدوال المساعدة ---

/**
 * دالة لإنشاء كلمة مرور قوية وعشوائية بالطول المطلوب
 * @param {number} length - طول كلمة المرور المطلوبة (الافتراضي 16)
 * @returns {string} - كلمة مرور عشوائية قوية
 */
function generateStrongPassword(length = 16) {
  const upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const lower = 'abcdefghijklmnopqrstuvwxyz';
  const digits = '0123456789';
  const symbols = '!@#$%^&*()-_=+[]{}<>?';
  
  // ضمان أن الكلمة تحتوي على الأقل على حرف واحد من كل نوع
  let pw = upper[Math.floor(Math.random() * upper.length)]
         + lower[Math.floor(Math.random() * lower.length)]
         + digits[Math.floor(Math.random() * digits.length)]
         + symbols[Math.floor(Math.random() * symbols.length)];
  
  // ملء باقي الطول بأحرف عشوائية من جميع الأنواع
  const all = upper + lower + digits + symbols;
  for (let i = pw.length; i < length; i++) {
    pw += all[Math.floor(Math.random() * all.length)];
  }
  
  // خلط الأحرف لضمان عدم وجود نمط (مثل رمز-رقم-حرف في البداية)
  const arr = pw.split('');
  for (let i = arr.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [arr[i], arr[j]] = [arr[j], arr[i]]; // تبديل أماكن الحرفين
  }
  return arr.join('');
}

/**
 * دالة لتحويل أي نص (كلمة مرور) إلى بصمة SHA-1
 * @param {string} input - النص المراد تحويله
 * @returns {string} - البصمة بصيغة Hex (أحرف كبيرة)
 */
function sha1Hex(input) {
  return crypto.createHash('sha1').update(input, 'utf8').digest('hex').toUpperCase();
}

/**
 * دالة فحص كلمة المرور في خدمة HIBP باستخدام K-Anonymity
 * هذا هو الجزء الأمني الأهم: نحن لا نرسل كلمة المرور أبداً.
 * @param {string} password - كلمة المرور الفعلية
 * @returns {object} - كائن يحتوي على { pwned: (true/false), count: (number) }
 */
async function checkHIBP(password) {
  // 1. تحويل كلمة المرور إلى بصمة SHA-1
  const sha1 = sha1Hex(password);
  
  // 2. تقسيم البصمة: أول 5 أحرف (prefix) والباقي (suffix)
  const prefix = sha1.slice(0, 5); // مثال: '5BAA6'
  const suffix = sha1.slice(5);  // مثال: '1E4C9B93F3F0... الخ'

  // 3. إرسال *فقط* أول 5 أحرف إلى خدمة HIBP
  // هذا يضمن "المجهولية-k": الخادم لا يعرف أي كلمة مرور نسأل عنها
  const resp = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
    headers: { 'User-Agent': 'Graduation-Project-Password-Checker' }
  });

  if (!resp || !resp.ok) {
    console.error('HIBP API error');
    // إذا فشل الاتصال، نفترض أنها آمنة (False Positive) بدلاً من إزعاج المستخدم
    return { pwned: false, count: 0 };
  }

  // 4. الرد عبارة عن قائمة بكل البصمات المسرّبة التي تبدأ بنفس الـ 5 أحرف
  const text = await resp.text();
  
  // 5. نبحث *محلياً* في القائمة عن باقي البصمة (suffix)
  // السطر يكون بالشكل: 'SUFFIX:COUNT'
  const hit = text.split('\n').find(line => line.split(':')[0].toUpperCase() === suffix);

  if (!hit) {
    // لم نجدها؟ إذاً كلمة المرور آمنة (بالنسبة لهذه التسريبات)
    return { pwned: false, count: 0 };
  }

  // وجدناها! نستخرج عدد مرات ظهورها
  const count = parseInt(hit.split(':')[1], 10) || 0;
  return { pwned: true, count: count };
}

// --- 3. الدالة الرئيسية (The Handler) ---
// هذه هي نقطة الدخول التي تستدعيها Netlify عند كل طلب

exports.handler = async (event) => {
  // نقبل فقط طلبات POST
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: JSON.stringify({ error: 'method_not_allowed' }) };
  }

  try {
    // 1. قراءة البيانات القادمة من الواجهة الأمامية (JSON)
    const body = JSON.parse(event.body || '{}');
    const { password, length } = body; // استخراج كلمة المرور والطول المطلوب
    
    // التحقق من وجود كلمة المرور
    if (!password || typeof password !== 'string') {
      return { statusCode: 400, body: JSON.stringify({ error: 'password_required' }) };
    }
    
    // التحقق من الطول والتأكد أنه رقم معقول (بين 12 و 20)
    const pwLength = [12, 16, 20].includes(length) ? length : 16;

    // 2. إجراء الفحوصات (بشكل متوازي لتحسين الأداء)
    const [z, hibp] = await Promise.all([
      zxcvbn(password),  // فحص القوة
      checkHIBP(password) // فحص التسريبات
    ]);

    const strength_score = z.score; // (0-4)

    // 3. إنشاء كلمة مرور مقترحة (إذا كانت الكلمة الحالية ضعيفة أو مسرّبة)
    let suggested = null;
    let suggestedScore = 0;
    
    if (strength_score < 4 || hibp.pwned) {
      // نستمر في إنشاء كلمات مرور جديدة حتى نجد واحدة "غير مسرّبة"
      // (هذا احتياط نادر جداً، لكنه احترافي)
      for (let i = 0; i < 5; i++) {
        suggested = generateStrongPassword(pwLength); // استخدام الطول المطلوب
        const chk = await checkHIBP(suggested).catch(() => ({ pwned: false }));
        if (!chk.pwned) {
          suggestedScore = zxcvbn(suggested).score;
          break; // وجدنا كلمة آمنة، توقف
        }
      }
    }

    // 4. إرجاع الرد النهائي (JSON) إلى الواجهة الأمامية
    return {
      statusCode: 200,
      headers: { 
        'Content-Type': 'application/json',
        'Cache-Control': 'no-store' // منع التخزين المؤقت للنتائج الحساسة
      },
      body: JSON.stringify({
        pwned: hibp.pwned,
        pwned_count: hibp.count,
        strength_score: strength_score,
        strength_feedback: z.feedback,
        suggested_password: suggested, // ستكون null إذا كانت الكلمة الأصلية قوية وآمنة
        suggested_password_score: suggestedScore
      })
    };
  } catch (e) {
    // معالجة أي أخطاء غير متوقعة
    console.error('Internal function error:', e);
    return { statusCode: 500, body: JSON.stringify({ error: 'internal_error', details: e.message }) };
  }
};
