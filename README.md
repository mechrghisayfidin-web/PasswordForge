# PasswordForge (SPA)

PasswordForge هو مولّد كلمات مرور آمن يعمل بالكامل client-side (صفحة مفردة).  
تم إنشاء الـMVP بلا مكتبات خارجية وبالاعتماد على Web Crypto API فقط.

---

## الملفات

- `page.html` — واجهة المستخدم (SPA).
- `style.css` — تصميم Dark-mode.
- `script.js` — كل المنطق (generator, storage, crypto, UI).

---

## تشغيل محلي

1. افتح `page.html` في أحدث متصفح (Chrome, Firefox, Edge, Safari).
   - لأداء ميزات الحافظة API (`navigator.clipboard.writeText`) قد تحتاج تشغيل الصفحة عبر `http://localhost` (مثلاً: باستخدام `npx http-server` أو فتح ملف على بعض المتصفحات يعمل).
2. لا يحتاج المشروع لاتصال إنترنت.

---

## ملاحظات أمنية (مختصر)

- **كل شيء يعمل client-side**: لا تُرسل كلمات المرور أو الـhashes أو أي بيانات حساسة إلى أي سيرفر افتراضيًا.
- **مصدر العشوائية**: `crypto.getRandomValues` مستخدم لكل عمليات التوليد — **لا** يتم استخدام `Math.random` للأمان.
- **حساب الهاش**: `crypto.subtle.digest('SHA-256', ...)` يُستعمل لحساب SHA-256 للـ(password || salt).
- **التخزين**:
  - يتم إنشاء "مفتاح التطبيق" AES-GCM عند التشغيل الأولي وتخزينه (raw bytes) في IndexedDB (لأغراض التشفير المحلي).
  - Salt عشوائي (32 بايت) يُولَّد عند التشغيل الأول ويُشفّر بواسطة مفتاح التطبيق ثم يُخزّن في `localStorage` كـBase64.
  - قائمة الـhashes تُخزّن مشفَّرة (AES-GCM) في `localStorage` تحت المفتاح `pf_hashes_v1`.
- **لماذا نخزن hash فقط؟** لأن تخزين الـhash يمنع استرجاع كلمة المرور النصية مباشرة (hash غير قابل للعكس). في حالة الحاجة لتتبع "uniqueness" بين كلمات تم توليدها، نتحقق من تكرار نفس الـhash. ملاحظة: هذا يضمن تمييزًا محليًا فقط (المتصفح/الجهاز نفسه).
- **محدودية localStorage**: هو وسيلة تخزين محلية قد تصل إليها برامج أو مستخدمون لديهم صلاحيات الجهاز. اقرأ قسم "تحسينات" أدناه.

---

## شرح التصميم (تخزين الـsalt والـhashes)

- عند التشغيل الأول:
  - يُولَّد AES-GCM key (`appKey`) عبر Web Crypto. يتم _export_ كـraw ثم يُخزَّن في IndexedDB (كمصفوفة bytes مشفّرة base64).
  - يُولَّد salt عشوائي 32 بايت ويُشفَّر بواسطة `appKey` ثم يُخزّن في `localStorage` كمجموعة bytes مشفّرة (base64).
- عند كل توليد كلمة:
  - تُجمّع bytes: `salt || password` ثم `SHA-256` عبر `subtle.digest`.
  - الناتج (hex) يُخزن في لائحة مشفَّرة داخل `localStorage`.
- لماذا هكذا؟
  - وجود salt يحمي من هجمات القاموس المباشرة ضد التخزين المحلي.
  - تشفير salt وhash store يجعلها أقل عرضة للوصول المباشر من صفحة أخرى؛ ومع ذلك، تظل البيانات على الجهاز.

**محدودية/تحسينات مستقبلية**:

- IndexedDB وlocalStorage هما مساحات تخزين على نفس الجهاز — لا تعوّل عليهما كحماية نهائية. لتحسين الأمان:
  - استخدم backend مُشفّر يستضيف hashes (مع آلية مصادقة).
  - استخدم hardware-backed key stores أو WebAuthn-backed keys.
  - اجعل مفتاح التطبيق غير قابل للتصدير (non-extractable) إن أمكن وتخزينه في مكان محافظ (Service Worker/KeyStore).
  - أضف خيار إزالة hashes محليًا أو مزامنة مشفّرة.

---

## كيف تعمل ميزة "uniqueness"

- عند كل توليد، نحسب SHA-256(salt || password).
- نحفظ الـhash فقط (مشفرًا) في localStorage.
- إذا كان الـhash موجودًا مسبقًا نعيد التوليد تلقائيًا حتى 10 محاولات (`MAX_ATTEMPTS`) ثم نعرض تحذيرًا إذا لم ننجح.
- **ملاحظة مهمة**: هذه الـuniqueness محلية فقط (تعرف الأجهزة/المتصفح الذي يعمل عليه المستخدم). لعمل فحص عالمي (عبر المستخدمين) يلزم endpoint مركزي أو خدمة تحقق تستقبل الـhashs فقط (ولا تستقبل كلمات المرور النصية).

---

## وظائف متاحة (MVP)

- Slider للطول (8–64).
- Checkboxes: Uppercase, Lowercase, Numbers, Symbols.
- Mode: High-Security / Balanced / Memorable.
- Pattern: Random / Readable-Passphrase / Hybrid.
- ForceFirstUpper, ExcludeChars, ExcludeSimilar.
- Presets: Social, Email, Wi-Fi, Gaming (تؤثر على الطول / الرموز).
- Batch generation و Download CSV (مع تحذير أمني قبل التنزيل).
- Export Report (client-side PNG، مع تحذير).
- Copy-to-clipboard عبر `navigator.clipboard.writeText`.
- Password masked by default; Show/Hide button.

---


## Checklist نشر آمن (قبل وضعه في production)

- [ ] Serve over HTTPS (مطلوب).
- [ ] Set strict Content-Security-Policy header (no external scripts/styles).
- [ ] Set `Referrer-Policy: no-referrer`.
- [ ] Set `X-Content-Type-Options: nosniff`.
- [ ] Consider `Strict-Transport-Security`.
- [ ] Subresource Integrity for any future external assets.
- [ ] Review IndexedDB/localStorage access policies.
- [ ] Penetration test focusing on XSS (XSS ستمكّن سرقة بيانات محلية).

---


---

## Security notes (مختصر للـdev)

- `crypto.getRandomValues` و `crypto.subtle.digest` هما المصدر الوحيد للعشوائية والتجزئة.
- تجنّب استخدام JS string zeroization كالحل النهائي؛ JS لا يضمن محو الذاكرة الفعلي. حاول الحد من عمر القيم الحساسة وتقليل الاحتفاظ بها (nullify references).
- عند تنزيل CSV/PNG: اعرض تحذير واضح للمستخدم بأن الملف يحوي بيانات حساسة.

---

## Acceptance criteria — تحقق سريع

- [x] فتح `page.html` يمكّن التوليد بالكامل offline.
- [x] كل كلمة مولدة تُحسَب لها SHA-256 وتُخزّن الـhashs (إن فعلت تلك الخاصية) مشفّرة محليًا.
- [x] لا يوجد إرسال بيانات خارجي تلقائي.
- [x] Copy يعمل عبر Clipboard API عندما يتاح (HTTPS/localhost).
- [x] الرسالة الترحيبية موجودة وتشرح سياسة عدم التخزين النصي.
- [x] Responsive ويدعم الهواتف وسطح المكتب.
