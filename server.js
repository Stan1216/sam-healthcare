/**
 * SAM Healthcare — Platform Starter
 * Minimal real backend: Node.js (no external dependencies) + SQLite database.
 * Serves the website prototype and provides: patient OTP login, clinician login,
 * booking storage. Run:  node server.js   →  http://localhost:3000
 *
 * Production path (see Doc 05): Next.js/NestJS + PostgreSQL/Supabase + WhatsApp
 * Business API for real OTPs. The schema below is designed to migrate 1:1.
 */
const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const Database = require("better-sqlite3"); // portable native SQLite — runs on any Node 18+ / any host

const PORT = process.env.PORT || 3000;
const SECRET = process.env.SAM_SECRET || "dev-secret-change-me";
const SITE = process.env.SITE_FILE || path.join(__dirname, "index.html");

// ---------- database ----------
const DB_FILE = process.env.SAM_DB || path.join(__dirname, "sam.db"); // override to relocate the database (e.g. a mounted persistent disk)
const db = new Database(DB_FILE);
db.exec(`
  CREATE TABLE IF NOT EXISTS patients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    phone TEXT UNIQUE NOT NULL,
    name TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS clinicians (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    full_name TEXT, role TEXT,            -- doctor | nurse | physio | care_manager
    registration_no TEXT, verified INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS otps (
    phone TEXT PRIMARY KEY, otp TEXT NOT NULL,
    expires_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS agent_sessions (
    sid TEXT PRIMARY KEY, channel TEXT DEFAULT 'web',
    state TEXT DEFAULT '{}', handoff INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS agent_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sid TEXT NOT NULL, role TEXT, body TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_id INTEGER NOT NULL REFERENCES patients(id),
    kind TEXT DEFAULT 'note',              -- report | prescription | visit_note | vital | note
    title TEXT NOT NULL, detail TEXT,
    author TEXT DEFAULT 'self',            -- 'self' or clinician name
    created_at TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS inquiries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT, topic TEXT, message TEXT,
    channel TEXT DEFAULT 'whatsapp',
    created_at TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS bookings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_id INTEGER REFERENCES patients(id),
    name TEXT, phone TEXT, service TEXT, area TEXT,
    status TEXT DEFAULT 'new',            -- new | assigned | enroute | done
    created_at TEXT DEFAULT (datetime('now'))
  );
`);

// patient UID column (SAM-YYYY-NNNNN) — added safely for pre-existing databases
try { db.exec("ALTER TABLE patients ADD COLUMN uid TEXT"); } catch (e) {}
const ensureUid = id => {
  const p = db.prepare("SELECT id, uid, created_at FROM patients WHERE id=?").get(id);
  if (!p) return null;
  if (!p.uid) {
    const uid = `SAM-${(p.created_at || "2026").slice(0, 4)}-${String(p.id).padStart(5, "0")}`;
    db.prepare("UPDATE patients SET uid=? WHERE id=?").run(uid, p.id);
    return uid;
  }
  return p.uid;
};

// seed one demo clinician (email: dr.demo@samhealthcare.in / password: SamDemo123)
const hash = p => crypto.createHash("sha256").update(p + SECRET).digest("hex");
try {
  db.prepare("INSERT OR IGNORE INTO clinicians (email,password_hash,full_name,role,registration_no,verified) VALUES (?,?,?,?,?,1)")
    .run("dr.demo@samhealthcare.in", hash("SamDemo123"), "Dr. Demo Ananya", "doctor", "TS/2019/04312");
} catch (e) {}

// ---------- tiny token (HMAC) ----------
const sign = payload => {
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const sig = crypto.createHmac("sha256", SECRET).update(body).digest("base64url");
  return body + "." + sig;
};
const verify = token => {
  try {
    const [body, sig] = token.split(".");
    if (crypto.createHmac("sha256", SECRET).update(body).digest("base64url") !== sig) return null;
    return JSON.parse(Buffer.from(body, "base64url").toString());
  } catch { return null; }
};

// ---------- helpers ----------
const json = (res, code, obj) => { res.writeHead(code, {"Content-Type": "application/json"}); res.end(JSON.stringify(obj)); };
const readBody = req => new Promise(r => { let d = ""; req.on("data", c => d += c); req.on("end", () => { try { r(JSON.parse(d || "{}")); } catch { r({}); } }); });

// ---------- Dr. Sharen scripted rules (guardrails + offline brain) ----------
// priority:true rules are NEVER delegated to the LLM.
function sharenRules(t) {
  const A = (reply, cites, action, priority) => ({ reply, cites: cites || [], action: action || null, priority: !!priority });
  if (/(chest pain|unconscious|not breathing|breathless|severe bleeding|stroke|seizure|suicide|overdose|heart attack|electric shock|drown|choking)/.test(t))
    return A("This could be an emergency — get emergency care NOW: call 108, or if it's delayed in your area, take a private ambulance or go straight to the nearest hospital emergency room. And call SAM in parallel on +91 72074 26888 — our care desk will help coordinate the ambulance and hospital admission through our partner network, keep your family informed at every step, and arrange recovery care at home afterwards. We stay with you through all of it.", ["Emergency routing per SAM safety charter — emergency services first, SAM coordinates alongside"], "emergency", true);
  if (/(dose|dosage|prescri|which medicine|what medicine|drug for|antibiotic|painkiller|increase my|reduce my|stop taking)/.test(t))
    return A("I can't recommend medicines or doses — that requires a licensed clinician who knows the full history. What I can do: explain what a prescribed medicine is for, flag interactions to discuss, and arrange a clinician callback within the hour to review medication questions properly.", ["SAM prohibited-outputs policy: no diagnosis, no prescription, no dose changes without clinician sign-off"], "callback", true);
  if (/(platelet|dengue|malaria|typhoid|(high |viral )?fever)/.test(t))
    return A("Fever in Hyderabad's season deserves watchfulness, not panic. Same-day medical review is needed if: fever beyond 3 days, platelets below 100,000/µL and falling, bleeding gums, severe abdominal pain, drowsiness or persistent vomiting. Hydration and rest matter meanwhile. I can have our care team call you within the hour to arrange the right review — and 108 immediately if severe symptoms appear.", ["WHO Dengue Guidelines — warning-signs criteria", "NVBDCP India Dengue Management 2024"], "callback");
  if (/(stomach|abdomen|abdominal|vomit|loose motion|diarrh|constipat|urine|burning|cough|cold|throat|headache|migraine|dizzy|giddi|rash|itch|eye|ear pain|toothache|bp|blood pressure|sugar|diabet|thyroid|weight loss|fatigue|tired|sleep)/.test(t))
    return A("That deserves a proper medical look rather than guesswork — and I don't diagnose. Here's what I can do right now: our care team calls you within the hour, a clinician hears the full story and guides the right next step (our doctor-at-home division is opening soon — you'd go on the priority list). If symptoms turn severe — intense pain, high fever, confusion, breathlessness — call 108.", ["ICMR Standard Treatment Workflows — when to seek clinical review", "SAM service status — doctor division activating"], "callback");
  // --- clinical-pattern education (informs with theory; "consistent with", never a diagnosis) ---
  if (/(thumb|wrist)/.test(t) && /(pain|ache|hurt|sore)/.test(t))
    return A("Pain on the thumb side of the wrist, especially when gripping, lifting or texting, is commonly consistent with De Quervain's tenosynovitis — irritation of the two tendons that move the thumb, from repetitive strain (very common with phone/laptop use and in new mothers). Typical early care: relative rest, a thumb-spica support, ice 10–15 min, and guided tendon-glide exercises — which our live physio division can assess at home (a Finkelstein's-style provocation test is part of the assessment). See a doctor first if there's numbness/tingling (possible nerve involvement), a recent fall, or visible deformity.", ["NICE CKS — Tenosynovitis (De Quervain's)", "American Society for Surgery of the Hand — patient guidance", "WHO Rehabilitation 2030"], "book_physio");
  if (/(neck|shoulder)/.test(t) && /(stiff|pain|ache|hurt|laptop|desk|computer|work)/.test(t))
    return A("Neck stiffness with shoulder ache during desk work is most commonly a postural/mechanical strain pattern — sustained forward-head position overloading the trapezius and deep neck flexors. Evidence-backed early care: micro-breaks every 30–40 min, raising the screen to eye level, chin-tuck and scapular-setting exercises. If it persists beyond 2 weeks, radiates down the arm, or brings numbness/tingling — that needs proper assessment, which our home physio can do with a written plan. Red flags like arm weakness or night pain that wakes you deserve a doctor's review.", ["NICE CKS — Neck pain (non-specific)", "Cochrane review — exercise for mechanical neck disorders"], "book_physio");
  if (/(low(er)? back|back pain|backache)/.test(t))
    return A("Most low-back pain is mechanical — muscles, ligaments and joints, not the spine's structure — and typically improves in 2–6 weeks with staying gently active (bed rest slows recovery). Early care: keep moving within comfort, heat, graded activity; our physio assessment builds a milestone plan. Urgent doctor review instead if: numbness around the saddle area, loss of bladder/bowel control, leg weakness, fever with the pain, or a recent significant fall — those are red-flag signs.", ["NICE NG59 — Low back pain and sciatica", "WHO Rehabilitation 2030"], "book_physio");
  if (/(knee)/.test(t) && /(tkr|replacement|surgery|post.?op)/.test(t))
    return A("After a knee replacement, recovery follows well-studied milestones: regaining full straightening early, then bend (flexion) toward ~110–120° by weeks 4–6, quad strength and walking pattern after. Stiffness, swelling and night aches are common in the first weeks — controlled with ice, elevation and paced exercise. What matters is a structured, progressive programme — exactly what our home physio delivers with the same clinician each visit. Sudden calf swelling, chest symptoms or a hot, very swollen joint → doctor immediately.", ["AAOS — TKA rehabilitation guidance", "NICE — knee replacement rehabilitation pathways"], "book_physio");
  if (/(ankle)/.test(t) && /(twist|sprain|swollen|pain)/.test(t))
    return A("A twisted ankle is usually a lateral ligament sprain. Evidence-based early care follows PEACE & LOVE: Protect, Elevate, Avoid anti-inflammatories in the first days, Compress, Educate — then progressive Loading, Optimism, Vascularisation and Exercise. If you can't take four steps, there's bony tenderness at the malleoli, or numbness — get an X-ray review first (Ottawa ankle rules). Otherwise, guided rehab restores strength and balance and prevents re-sprain — our physio can start that at home.", ["British Journal of Sports Medicine — PEACE & LOVE protocol", "Ottawa Ankle Rules"], "book_physio");
  if (/(knee|spine|shoulder|hip|elbow|hand|finger|foot|heel|leg|arm|joint|muscle|sprain|strain|stiff|swelling|posture|sciatica|spondyl|arthrit|cramp|sports injury|post.?surg|thr|fracture|physio|rehab|paralysis|stroke recovery|fall|balance|walk|mobility|pain|ache|hurt)/.test(t))
    return A("Pain like that is worth assessing properly, not enduring. Musculoskeletal pain usually traces to a load-vs-capacity mismatch — a structure asked to do more than it's currently conditioned for — which is why assessment comes before exercise. Our live Physiotherapy & Rehab division starts with a structured home assessment (movement, strength, triggers), then a written, milestone-based recovery plan with the same physiotherapist every visit. If there's numbness, weakness, a recent fall or visible deformity, a doctor should look first — our care team routes that correctly.", ["WHO Rehabilitation 2030 framework", "NICE musculoskeletal care guidance — assessment before exercise"], "book_physio");
  if (/(pregnan|postpartum|delivery|pelvic|incontinence|leak)/.test(t))
    return A("Our Pelvic Floor & Women's Rehab wing is live — Hyderabad's dedicated programme for postpartum recovery, incontinence care and pre/post-surgical rehabilitation, at home, with a specialist consultation at ₹999.", ["SAM Women's Rehab programme — serving now"], "book_physio");
  if (/(price|cost|charge|fee|₹|rupee|how much)/.test(t))
    return A("Our prices are published on this page — flat and final: physiotherapy ₹799/session (12-session packages at preferential rates), pelvic-floor specialist consult ₹999, doctor home visit ₹1,299 day / ₹1,599 evening once that division opens. Consumables at MRP, shown before use. No surprise billing, ever.", ["SAM published rate card — Pricing section on this page"], "pricing");
  if (/(which service|what.*live|available|launch|when.*(doctor|nurse|nursing)|open|elder|parents care)/.test(t))
    return A("Today: Physiotherapy & Rehab (including pelvic-floor and women's rehab) is serving homes across Hyderabad, plus Elder Care memberships with a named Family Care Manager. Opening next: doctor visits, nursing and diagnostics — founding clinicians are being credentialed now. Join a priority list and we call you the day your service goes live.", ["SAM service status — updated July 2026"], "services");
  if (/^(hi|hello|hey|namaste|good (morning|afternoon|evening))\b/.test(t))
    return A("Namaste 🙏 I'm Dr. Sharen, SAM's clinical AI companion. Tell me what's worrying you — a symptom, a report, recovery after surgery, care for your parents — and I'll point you to the right care with sources. I never replace a doctor, and for emergencies it's always 108.", ["Dr. Sharen operating charter"], null);
  if (/(thank|great|super|awesome|ok bye|goodbye)/.test(t))
    return A("Always here — day or night, English or తెలుగు. Wishing your family good health. 🙏 If anything changes, our care team is one message away.", [], null);
  return null;
}

// ---------- optional LLM brain (Anthropic API; scripted rules remain the guardrail) ----------
const SHAREN_SYS = `You are Dr. Sharen, the clinical AI companion of SAM Healthcare, Hyderabad (premium home healthcare, start phase). You talk like a warm, unhurried clinician who is genuinely trying to help — not a search engine, and NEVER a salesperson.
ETHOS (why you exist — hold this above everything): You are a free, genuinely useful gift from the SAM team to anyone worried about their health. The person should leave feeling cared for and better-informed — thinking "this team really knows their stuff and actually cares." That earned trust is what makes them want to book with SAM. You never chase the booking; you earn it by being helpful. Whenever unsure, choose to be MORE helpful, not more salesy. The same warmth you show is the promise of how the SAM team will treat them.
FACTS: Live now: Physiotherapy & Rehab incl. pelvic-floor/women's rehab, ₹799/session (12-session packages), pelvic specialist consult ₹999; Elder Care membership from ₹999/mo. Opening soon (clinicians being credentialed): doctor-at-home (₹1,299 day/₹1,599 evening when live), nursing (from ₹699/procedure), diagnostics. 60-minute promise = a qualified clinician assesses and sets the care plan moving within 60 minutes of contact (8am-10pm daily); physio visits typically same-day. Care team callback within the hour for anything else. Contact +91 72074 26888.
HARD RULES: Never diagnose ("commonly consistent with...", never "you have"). Never name a specific medicine or dose. Emergencies (chest pain, breathlessness, stroke signs, heavy bleeding, unconsciousness) -> tell them to get emergency care NOW (call 108; if delayed in their area, a private ambulance or the nearest hospital ER directly) AND to call SAM's care desk +91 72074 26888 in parallel — SAM coordinates the ambulance/hospital admission through its partner network, keeps the family informed, and handles recovery at home afterwards. Never present SAM as a replacement for emergency services. Be warm, empathetic, never boastful.
HOW YOU TALK (this is the most important behaviour):
- SOUND LIKE A REAL PERSON, NOT A BOT. Write the way a warm, sharp doctor texts a worried friend or family member — human, natural, a little informal. Use contractions and everyday words, short sentences, and react first like a person would ("Ah, that sounds really uncomfortable" / "I get why that's worrying you"). NEVER sound like a medical leaflet or chatbot: do NOT use stock phrases like "commonly consistent with" / "this pattern is consistent with", labelled sections like "Red flags:", numbered or bulleted mini-reports, or a tidy analysis→care→flags→route template. Say the cautious bit the way a human does ("the one thing I'd keep an eye on is..."), not as a checklist. Vary your phrasing so you never sound templated. If you notice yourself writing a neat structured answer, stop and rewrite it as if you were speaking out loud to a scared relative.
- CONSULT, DON'T CONCLUDE. On the FIRST message about a symptom, do NOT give a full analysis, care plan, or ANY mention of booking. React warmly in one line, then ask 1-2 simple questions the way a person would ("How long's this been going on?", "Did you twist it or knock it, or did it just come on by itself?"). Keep the first reply short (2-3 sentences) and end on your question.
- BUILD OVER TURNS. The conversation so far is given to you — use it, never re-ask what's answered. Each turn: reflect back what you heard in plain words, then either ask ONE more question, or (once you genuinely have enough) explain what's likely going on in simple terms, what they can try today, and the one or two things that'd mean "get it looked at soon". Only mention a source when you make a real clinical claim, and weave it in naturally ("the WHO guidance on this basically says...") — never a citation dump.
- HELP FIRST, OFFER LAST. Mention a SAM service only when it's genuinely the best next step for THEM, gently and optionally ("if it's still bugging you in a few days, our home physio could take a proper look — no rush though"). Never on the first turn, never end every message with a booking line. Often the most trust-building reply has no offer at all.
- Keep replies short — usually 40-100 words. Warm, plain, human. English or తెలుగు as the person uses.
OUTPUT: respond ONLY with JSON: {"reply": string, "cites": [0-3 short source names — empty while still taking history], "action": one of "book_physio"|"callback"|"pricing"|"services"|"emergency"|null — keep null unless THIS reply actually made a gentle service offer}`;
async function askClaude(userText, extraContext, history) {
  try {
    const ctrl = new AbortController(); const to = setTimeout(() => ctrl.abort(), 12000);
    // Build a real multi-turn conversation so Dr. Sharen can take a history instead of answering each message blind.
    const raw = [];
    if (Array.isArray(history)) for (const h of history.slice(-8)) {
      if (!h || !h.text) continue;
      raw.push({ role: (h.role === "bot" || h.role === "assistant") ? "assistant" : "user", content: String(h.text).slice(0, 1500) });
    }
    while (raw.length && raw[0].role !== "user") raw.shift();            // Anthropic requires the first turn to be the user's
    raw.push({ role: "user", content: (extraContext ? extraContext + "\n\n" : "") + userText });
    const msgs = [];                                                     // collapse consecutive same-role turns (roles must alternate)
    for (const m of raw) { if (msgs.length && msgs[msgs.length - 1].role === m.role) msgs[msgs.length - 1].content += "\n" + m.content; else msgs.push({ ...m }); }
    const r = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST", signal: ctrl.signal,
      headers: { "x-api-key": process.env.ANTHROPIC_API_KEY, "anthropic-version": "2023-06-01", "content-type": "application/json" },
      body: JSON.stringify({ model: process.env.SHAREN_MODEL || "claude-haiku-4-5-20251001", max_tokens: 400, system: SHAREN_SYS,
        messages: msgs })
    });
    clearTimeout(to);
    if (!r.ok) return null;
    const d = await r.json();
    const txt = d?.content?.[0]?.text || "";
    const m = txt.match(/\{[\s\S]*\}/);
    if (!m) return null;
    const out = JSON.parse(m[0]);
    if (!out.reply) return null;
    return { reply: String(out.reply).slice(0, 900), cites: Array.isArray(out.cites) ? out.cites.slice(0, 3).map(String) : [], action: ["book_physio","callback","pricing","services","emergency"].includes(out.action) ? out.action : null };
  } catch (e) { return null; }
}

// ---------- CORS (front end on Hostinger/custom domain, API here) ----------
const CORS_ORIGINS = (process.env.SAM_CORS ||
  "https://www.samhealthcare.in,https://samhealthcare.in,https://www.samhealthcare.co.in,https://samhealthcare.co.in")
  .split(",").map(s => s.trim()).filter(Boolean);

// ---------- request handler ----------
const requestHandler = async (req, res) => {
  const url = new URL(req.url, "http://x");

  // CORS: allow the SAM front-end domains to call this API
  const origin = req.headers.origin;
  if (origin && CORS_ORIGINS.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
    res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
    res.setHeader("Access-Control-Max-Age", "86400");
  }
  if (req.method === "OPTIONS") { res.writeHead(204); return res.end(); }

  // --- API ---
  if (url.pathname === "/api/otp/request" && req.method === "POST") {
    const { phone } = await readBody(req);
    if (!phone || phone.replace(/\D/g, "").length < 10) return json(res, 400, { error: "Valid phone required" });
    const otp = String(crypto.randomInt(1000, 9999));
    db.prepare("INSERT INTO otps (phone,otp,expires_at) VALUES (?,?,datetime('now','+5 minutes')) ON CONFLICT(phone) DO UPDATE SET otp=excluded.otp, expires_at=excluded.expires_at").run(phone, otp);
    console.log(`[OTP] ${phone} -> ${otp}  (in production: send via WhatsApp Business API / SMS)`);
    return json(res, 200, { sent: true, devOtp: otp }); // devOtp exposed ONLY for local development
  }

  if (url.pathname === "/api/otp/verify" && req.method === "POST") {
    const { phone, otp, name } = await readBody(req);
    const row = db.prepare("SELECT otp FROM otps WHERE phone=? AND expires_at > datetime('now')").get(phone);
    if (!row || row.otp !== String(otp)) return json(res, 401, { error: "Invalid or expired OTP" });
    db.prepare("DELETE FROM otps WHERE phone=?").run(phone);
    db.prepare("INSERT OR IGNORE INTO patients (phone) VALUES (?)").run(phone);
    if (name && String(name).trim()) db.prepare("UPDATE patients SET name=? WHERE phone=? AND (name IS NULL OR name='')").run(String(name).trim().slice(0, 80), phone);
    const p = db.prepare("SELECT id, name FROM patients WHERE phone=?").get(phone);
    return json(res, 200, { token: sign({ t: "patient", id: p.id, phone }), patientId: p.id, name: p.name || "", uid: ensureUid(p.id) });
  }

  // profile of the signed-in user
  if (url.pathname === "/api/me" && req.method === "GET") {
    const auth = verify((req.headers.authorization || "").replace("Bearer ", ""));
    if (!auth) return json(res, 401, { error: "Sign in required" });
    if (auth.t === "clinician") {
      const c = db.prepare("SELECT full_name, role, email FROM clinicians WHERE id=?").get(auth.id);
      return json(res, 200, { type: "clinician", name: c?.full_name || "", role: c?.role || "" });
    }
    const p = db.prepare("SELECT name, phone, created_at FROM patients WHERE id=?").get(auth.id);
    const n = db.prepare("SELECT COUNT(*) c FROM bookings WHERE patient_id=?").get(auth.id);
    return json(res, 200, { type: "patient", uid: ensureUid(auth.id), name: p?.name || "", phone: p?.phone || "", since: p?.created_at || "", bookings: n?.c || 0 });
  }

  // ---- medical records (demo-grade; production adds encryption, consent logging & audit per Doc 05) ----
  // GET  /api/records                     → patient: own records
  // GET  /api/records?uid=SAM-...|phone=  → clinician: that patient's records
  if (url.pathname === "/api/records" && req.method === "GET") {
    const auth = verify((req.headers.authorization || "").replace("Bearer ", ""));
    if (!auth) return json(res, 401, { error: "Sign in required" });
    let pid = null, patient = null;
    if (auth.t === "clinician") {
      const uid = url.searchParams.get("uid"), phone = url.searchParams.get("phone");
      patient = uid ? db.prepare("SELECT * FROM patients WHERE uid=?").get(uid)
                    : phone ? db.prepare("SELECT * FROM patients WHERE phone=?").get(phone) : null;
      if (!patient) return json(res, 404, { error: "Patient not found — pass ?uid=SAM-… or ?phone=…" });
      pid = patient.id;
    } else { pid = auth.id; patient = db.prepare("SELECT * FROM patients WHERE id=?").get(pid); }
    const rows = db.prepare("SELECT id, kind, title, detail, author, created_at FROM records WHERE patient_id=? ORDER BY id DESC LIMIT 200").all(pid);
    return json(res, 200, { uid: ensureUid(pid), name: patient?.name || "", records: rows });
  }

  // POST /api/records — patient adds to own file; clinician adds to any patient via uid
  if (url.pathname === "/api/records" && req.method === "POST") {
    const auth = verify((req.headers.authorization || "").replace("Bearer ", ""));
    if (!auth) return json(res, 401, { error: "Sign in required" });
    const b = await readBody(req);
    if (!b.title) return json(res, 400, { error: "title required" });
    let pid, author;
    if (auth.t === "clinician") {
      const patient = db.prepare("SELECT id FROM patients WHERE uid=?").get(String(b.uid || ""));
      if (!patient) return json(res, 404, { error: "Patient not found — pass uid" });
      const c = db.prepare("SELECT full_name FROM clinicians WHERE id=?").get(auth.id);
      pid = patient.id; author = c?.full_name || "clinician";
    } else { pid = auth.id; author = "self"; }
    const kind = ["report","prescription","visit_note","vital","note"].includes(b.kind) ? b.kind : "note";
    const r = db.prepare("INSERT INTO records (patient_id,kind,title,detail,author) VALUES (?,?,?,?,?)")
      .run(pid, kind, String(b.title).slice(0, 160), String(b.detail || "").slice(0, 4000), author);
    return json(res, 200, { id: Number(r.lastInsertRowid) });
  }

  // GET /api/patients/lookup?q=SAM-…|phone — clinician/care-desk agents pull a patient file fast
  if (url.pathname === "/api/patients/lookup" && req.method === "GET") {
    const auth = verify((req.headers.authorization || "").replace("Bearer ", ""));
    if (!auth || auth.t !== "clinician") return json(res, 401, { error: "Clinician sign-in required" });
    const q = String(url.searchParams.get("q") || "").trim();
    if (!q) return json(res, 400, { error: "q required (UID or phone)" });
    const p = q.toUpperCase().startsWith("SAM-")
      ? db.prepare("SELECT * FROM patients WHERE uid=?").get(q.toUpperCase())
      : db.prepare("SELECT * FROM patients WHERE phone=?").get(q);
    if (!p) return json(res, 404, { error: "No patient matches " + q });
    const counts = {
      records: db.prepare("SELECT COUNT(*) c FROM records WHERE patient_id=?").get(p.id).c,
      bookings: db.prepare("SELECT COUNT(*) c FROM bookings WHERE patient_id=?").get(p.id).c
    };
    return json(res, 200, { uid: ensureUid(p.id), name: p.name || "", phone: p.phone, since: p.created_at, ...counts });
  }

  // Dr. Sharen — evidence-referenced assistant (informs & routes; never diagnoses/prescribes)
  // With ANTHROPIC_API_KEY set, free-text goes to Claude under a strict cite-or-refuse system prompt;
  // the scripted router below always remains as guardrail + offline fallback.
  if (url.pathname === "/api/sharen" && req.method === "POST") {
    const { q, history } = await readBody(req);
    const t = String(q || "").toLowerCase();
    const R = (reply, cites, action) => json(res, 200, { reply, cites: cites || [], action: action || null });
    if (!t.trim()) return R("Ask me about symptoms you're worried about, a report, physiotherapy, or our services — in English or తెలుగు.");
    const hard = sharenRules(t);
    if (hard && hard.priority) return R(hard.reply, hard.cites, hard.action); // emergency & medication rails are never delegated
    if (process.env.ANTHROPIC_API_KEY) {
      const ai = await askClaude(String(q), null, history);
      if (ai) return R(ai.reply, ai.cites, ai.action);
    }
    if (hard) return R(hard.reply, hard.cites, hard.action);
    return R("I can explain reports, decode prescriptions, and point you to the right care — always with sources, never replacing your doctor. Tell me what's worrying you — a symptom, a body part, a report — or ask about physiotherapy, elder care or our services. For anything urgent, call 108.", ["Dr. Sharen operating charter: informs & references; every clinical decision is clinician-confirmed"], null);
  }

  if (url.pathname === "/api/clinician/login" && req.method === "POST") {
    const { email, password } = await readBody(req);
    const c = db.prepare("SELECT * FROM clinicians WHERE email=?").get(String(email || "").toLowerCase());
    if (!c || c.password_hash !== hash(password || "")) return json(res, 401, { error: "Invalid credentials" });
    if (!c.verified) return json(res, 403, { error: "Account pending verification" });
    return json(res, 200, { token: sign({ t: "clinician", id: c.id, role: c.role }), name: c.full_name, role: c.role });
  }

  if (url.pathname === "/api/bookings" && req.method === "POST") {
    const b = await readBody(req);
    if (!b.phone || !b.service) return json(res, 400, { error: "phone and service required" });
    const auth = verify((req.headers.authorization || "").replace("Bearer ", ""));
    const r = db.prepare("INSERT INTO bookings (patient_id,name,phone,service,area) VALUES (?,?,?,?,?)")
      .run(auth && auth.t === "patient" ? auth.id : null, b.name || "", b.phone, b.service, b.area || "");
    console.log(`[BOOKING] #${r.lastInsertRowid} ${b.service} — ${b.area} (${b.phone})`);
    return json(res, 200, { id: Number(r.lastInsertRowid), status: "new" });
  }

  if (url.pathname === "/api/bookings" && req.method === "GET") {
    const auth = verify((req.headers.authorization || "").replace("Bearer ", ""));
    if (!auth) return json(res, 401, { error: "Sign in required" });
    const rows = auth.t === "clinician"
      ? db.prepare("SELECT * FROM bookings ORDER BY id DESC LIMIT 100").all()
      : db.prepare("SELECT * FROM bookings WHERE patient_id=? ORDER BY id DESC").all(auth.id);
    return json(res, 200, { bookings: rows });
  }

  // WhatsApp widget enquiries — logged so no lead is lost even if the WhatsApp send isn't completed
  if (url.pathname === "/api/inquiries" && req.method === "POST") {
    const { name, topic, message } = await readBody(req);
    if (!topic && !message) return json(res, 400, { error: "topic or message required" });
    const r = db.prepare("INSERT INTO inquiries (name,topic,message) VALUES (?,?,?)")
      .run(String(name || "").slice(0, 80), String(topic || "").slice(0, 120), String(message || "").slice(0, 1000));
    console.log(`[INQUIRY] #${r.lastInsertRowid} ${topic} — ${name || "anonymous"}`);
    return json(res, 200, { id: Number(r.lastInsertRowid) });
  }

  if (url.pathname === "/api/inquiries" && req.method === "GET") {
    const auth = verify((req.headers.authorization || "").replace("Bearer ", ""));
    if (!auth || auth.t !== "clinician") return json(res, 401, { error: "Clinician sign-in required" });
    return json(res, 200, { inquiries: db.prepare("SELECT * FROM inquiries ORDER BY id DESC LIMIT 100").all() });
  }

  // ---- SAM Care-Desk Agent — one brain, every channel (web / WhatsApp / VAPI voice later) ----
  // POST /api/agent/reply {sessionId, text, channel} → {reply, done, handoff, state}
  // Stateful intake that can CLOSE: qualify → capture area/name/time → create booking → confirm price.
  if (url.pathname === "/api/agent/reply" && req.method === "POST") {
    const { sessionId, text, channel } = await readBody(req);
    if (!sessionId) return json(res, 400, { error: "sessionId required" });
    const sid = String(sessionId).slice(0, 60);
    let s = db.prepare("SELECT * FROM agent_sessions WHERE sid=?").get(sid);
    if (!s) { db.prepare("INSERT INTO agent_sessions (sid, channel, state) VALUES (?,?,?)").run(sid, String(channel || "web"), "{}"); s = db.prepare("SELECT * FROM agent_sessions WHERE sid=?").get(sid); }
    const st = JSON.parse(s.state || "{}");
    const t = String(text || "").toLowerCase().trim();
    db.prepare("INSERT INTO agent_messages (sid, role, body) VALUES (?,?,?)").run(sid, "user", String(text || "").slice(0, 1000));
    let reply, done = false, handoff = !!s.handoff;

    const save = () => db.prepare("UPDATE agent_sessions SET state=?, handoff=? WHERE sid=?").run(JSON.stringify(st), handoff ? 1 : 0, sid);
    const phoneFromSid = sid.replace(/\D/g, "").length >= 10 ? sid.replace(/\D/g, "").slice(-10) : (st.phone || "");

    if (handoff) { reply = "You're with our human care team now — they have your full conversation and will reply here shortly. 🙏"; }
    else if (/(chest pain|unconscious|not breathing|breathless|severe bleeding|stroke|seizure|heart attack)/.test(t)) {
      reply = "⚠️ This could be an emergency — get emergency care NOW: call 108, or if it's delayed in your area, a private ambulance or the nearest hospital emergency room directly. Call us in parallel on +91 72074 26888 — our care desk is being alerted right now and will coordinate the ambulance, hospital admission through our partner network, and keep your family informed. We stay with you through it."; handoff = true;
      db.prepare("INSERT INTO inquiries (name, topic, message, channel) VALUES (?,?,?,?)").run(st.name || "", "🚨 EMERGENCY — coordinate now", String(text || "").slice(0, 500), String(channel || "web"));
    }
    else if (/(human|agent|real person|talk to someone|call me|manager)/.test(t)) {
      reply = "Of course — connecting you to our human care team now. They'll reply right here" + (phoneFromSid ? "" : " (share your number if you'd like a call back)") + ". 🙏"; handoff = true;
    }
    else if (/(dose|dosage|prescri|which medicine|what medicine|antibiotic)/.test(t)) {
      reply = "I can't advise on medicines or doses — that needs a licensed clinician. I'm arranging a clinician callback within the hour to go through it properly. Meanwhile I can explain what a prescribed medicine is for, or help you book care at home.";
      db.prepare("INSERT INTO inquiries (name, topic, message, channel) VALUES (?,?,?,?)").run(st.name || "", "Medication question — clinician callback", String(text || "").slice(0, 500), String(channel || "web"));
    }
    else if (st.stage === "area") { st.area = String(text || "").slice(0, 60); st.stage = "name";
      reply = "Got it — " + st.area + " ✅ And whose visit is this? A name helps our physiotherapist prepare (you can also tell me their age/condition)."; }
    else if (st.stage === "name") { st.name = String(text || "").slice(0, 80); st.stage = "time";
      reply = "Thank you. When works best — today, tomorrow, morning or evening? Our team confirms the exact slot on this chat."; }
    else if (st.stage === "time") { st.time = String(text || "").slice(0, 60);
      const phone = phoneFromSid || "via-" + (channel || "chat");
      const r = db.prepare("INSERT INTO bookings (name, phone, service, area, status) VALUES (?,?,?,?, 'new')")
        .run(st.name || "", phone, "Physiotherapy at home (" + (st.time || "requested") + ")", st.area || "");
      st.stage = "closed"; done = true;
      reply = "Booked ✅ Request #" + r.lastInsertRowid + " — physiotherapy at home, " + (st.area || "") + ", " + st.time + ".\n\n• Assessment first, then a written recovery plan\n• Same physiotherapist every visit\n• ₹799/session, packages available — no surprise charges\n\nOur care team confirms your slot and physiotherapist's name here shortly. Reply AGENT anytime for a human. 🙏";
    }
    else if (/(physio|knee|back|spine|shoulder|neck|hip|elbow|wrist|hand|thumb|finger|ankle|foot|heel|joint|muscle|sprain|strain|stiff|swelling|posture|sciatica|spondyl|arthrit|cramp|rehab|post.?surg|tkr|thr|replacement|fracture|walk|balance|fall|mobility|pain|ache|hurt)/.test(t)) { st.intent = "physio"; st.stage = "area";
      reply = "We can help with that at home — our Physiotherapy & Rehab division is live across Hyderabad (₹799/session, same physiotherapist every visit, written recovery plan; assessment first, and anything needing a doctor's look gets routed correctly). Which area are you in?"; }
    else if (/(doctor|nurse|nursing|injection|iv drip|drip|stomach|vomit|cough|cold|headache|dizzy|rash|bp|blood pressure|sugar|diabet)/.test(t)) {
      reply = "Honest answer: our doctor and nursing divisions are opening soon — founding clinicians are being credentialed now. I can (1) put you on the priority list — you're called the day it goes live, or (2) arrange a care-team callback within the hour so a clinician hears the full story and guides the next step today. Which would you like? (If it turns severe, call 108.)";
      db.prepare("INSERT INTO inquiries (name, topic, message, channel) VALUES (?,?,?,?)").run(st.name || "", "Doctor/Nursing priority list", String(text || "").slice(0, 500), String(channel || "web"));
    }
    else if (/(price|cost|charge|fee|₹|how much)/.test(t)) {
      reply = "Published, flat, no surprises: physiotherapy ₹799/session (12-session packages at preferential rates) · pelvic-floor specialist consult ₹999 · doctor visit ₹1,299 day / ₹1,599 evening once live. Consumables at MRP, shown before use. Want me to book a physio assessment?";
    }
    else if (/(elder|parents|amma|father|mother|old age)/.test(t)) { st.intent = "physio"; st.stage = "area";
      reply = "We understand — caring for parents from near or far is exactly why SAM exists. Live today: physiotherapy & rehab at home (great for mobility, recovery, falls prevention), with a named Family Care Manager and WhatsApp updates to the family. Which area are they in?"; }
    else {
      let ai = null;
      if (process.env.ANTHROPIC_API_KEY) ai = await askClaude(String(text || ""), "Channel: " + (channel || "web") + ". Known so far: " + JSON.stringify(st) + ". You are mid-conversation on SAM's care desk; if the right next step is a physio booking, say so and ask for their area.");
      if (ai) { reply = ai.reply + (ai.cites && ai.cites.length ? "\n(Sources: " + ai.cites.join(" · ") + ")" : "");
        if (ai.action === "book_physio") { st.intent = "physio"; st.stage = "area"; }
        if (ai.action === "emergency") handoff = true;
      } else reply = "Namaste 🙏 I'm SAM's care assistant. I can book physiotherapy at home today, put you on the priority list for doctor/nursing visits, explain our published prices, or connect you to a human — just say the word. What do you need help with?";
    }

    save();
    db.prepare("INSERT INTO agent_messages (sid, role, body) VALUES (?,?,?)").run(sid, "assistant", reply.slice(0, 1500));
    return json(res, 200, { reply, done, handoff, state: st });
  }

  // ---- WhatsApp Business Cloud API webhook (AI-first, human handoff) ----
  // Setup: set env WA_VERIFY_TOKEN, WA_TOKEN (Meta access token), WA_PHONE_ID. Point Meta webhook here.
  if (url.pathname === "/api/whatsapp/webhook" && req.method === "GET") {
    if (url.searchParams.get("hub.verify_token") === (process.env.WA_VERIFY_TOKEN || "sam-verify")) {
      res.writeHead(200); return res.end(url.searchParams.get("hub.challenge") || "");
    }
    return json(res, 403, { error: "Bad verify token" });
  }
  if (url.pathname === "/api/whatsapp/webhook" && req.method === "POST") {
    const body = await readBody(req);
    try {
      const msg = body?.entry?.[0]?.changes?.[0]?.value?.messages?.[0];
      if (msg && msg.type === "text") {
        const from = msg.from; // sender phone
        // route through the same care-desk brain (also used by web chat and, later, VAPI voice)
        const rsp = await fetch(`http://localhost:${PORT}/api/agent/reply`, { method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ sessionId: "wa-" + from, text: msg.text?.body || "", channel: "whatsapp" }) }).then(r => r.json());
        if (process.env.WA_TOKEN && process.env.WA_PHONE_ID) {
          await fetch(`https://graph.facebook.com/v20.0/${process.env.WA_PHONE_ID}/messages`, {
            method: "POST", headers: { "Authorization": "Bearer " + process.env.WA_TOKEN, "Content-Type": "application/json" },
            body: JSON.stringify({ messaging_product: "whatsapp", to: from, text: { body: rsp.reply } })
          }).catch(e => console.log("[WA SEND FAIL]", e.message));
        } else console.log(`[WA DRY-RUN] would reply to ${from}: ${rsp.reply.slice(0, 80)}…`);
      }
    } catch (e) { console.log("[WA WEBHOOK]", e.message); }
    return json(res, 200, { received: true });
  }

  // --- website ---
  if (url.pathname === "/" || url.pathname.endsWith(".html")) {
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    return fs.createReadStream(SITE).pipe(res);
  }
  json(res, 404, { error: "Not found" });
};

// ---------- server: Express when available (Hostinger-friendly), else node:http ----------
const banner = kind => console.log(`SAM Platform Starter (${kind}) → http://localhost:${PORT}\nDemo clinician: dr.demo@samhealthcare.in / SamDemo123`);
let listening = false;
try {
  const express = require("express");
  const app = express();
  app.disable("x-powered-by");
  app.use((req, res) => requestHandler(req, res)); // delegate everything to our handler (reads raw body itself)
  app.listen(PORT, () => { banner("express"); });
  listening = true;
} catch (e) {
  console.log("[express not available, falling back to node:http]", e.message);
}
if (!listening) http.createServer(requestHandler).listen(PORT, () => banner("node:http"));
