# Password Checker (Netlify)

واجهة + دالة Netlify لفحص كلمات المرور عبر HIBP (k-anonymity) واقتراح كلمة أقوى.
لا يوجد تخزين لبيانات المستخدم.

## النشر على Netlify
1. ارفع هذا المجلد كمستودع إلى GitHub (أو اربطه من جهازك).
2. في Netlify: New site -> Import from Git -> اختر المستودع.
3. سيعمل البناء تلقائيًا. ستجد الواجهة على رابط الموقع، والدالة على:
   `/.netlify/functions/check-password`

## التطوير محليًا
- ثبّت Netlify CLI: `npm i -g netlify-cli`
- داخل المجلد: `netlify dev`
- افتح المتصفح على العنوان الذي يظهر في الطرفية.

## ملاحظة
- الدالة ترسل فقط أول 5 أحرف من SHA-1 لكلمة المرور إلى HIBP (k-anonymity).
- يمكن تعديل طول كلمة المرور المقترحة في `check-password.js`.