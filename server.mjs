import { createServer } from "node:http";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { extname, join, normalize } from "node:path";
import { randomBytes, randomUUID, scryptSync, timingSafeEqual } from "node:crypto";

const root = process.cwd();
const port = Number(process.env.PORT || 4173);
const dataDir = join(root, "data");
const usersFile = join(dataDir, "users.json");
const backupsDir = join(dataDir, "backups");
const SESSION_TTL = 12 * 60 * 60 * 1000;
const REMEMBER_TTL = 30 * 24 * 60 * 60 * 1000;
const LOGIN_WINDOW = 15 * 60 * 1000;
const LOGIN_LIMIT = 10;
const MAX_BODY = 16 * 1024;
const MAX_DATA_BODY = 128 * 1024;

const types = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".webp": "image/webp",
  ".json": "application/json; charset=utf-8",
  ".md": "text/markdown; charset=utf-8",
  ".txt": "text/plain; charset=utf-8"
};

const sessions = new Map();
const loginAttempts = new Map();
let usersCache = null;

function publicUser(user) {
  return {
    id: user.id,
    name: user.name,
    email: user.email || "",
    phone: user.phone || "",
    role: user.role
  };
}

function normalizeEmail(value) {
  const email = String(value || "").trim().toLowerCase();
  if (email.length > 120 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return "";
  return email;
}

function normalizePhone(value) {
  const raw = String(value || "")
    .replace(/[٠-٩]/g, (digit) => String("٠١٢٣٤٥٦٧٨٩".indexOf(digit)))
    .replace(/[۰-۹]/g, (digit) => String("۰۱۲۳۴۵۶۷۸۹".indexOf(digit)))
    .trim();
  let digits = raw.replace(/\D/g, "");
  if (digits.startsWith("00")) digits = digits.slice(2);
  if (digits.startsWith("20") && digits.length === 12) {
    // already international Egyptian
  } else if (digits.startsWith("0") && digits.length === 11) {
    digits = `20${digits.slice(1)}`;
  } else if (digits.startsWith("1") && digits.length === 10) {
    digits = `20${digits}`;
  }
  if (digits.length < 10 || digits.length > 15) return "";
  return `+${digits}`;
}

function readIdentifier(value) {
  const raw = String(value || "").trim();
  if (!raw) return { email: "", phone: "" };
  if (raw.includes("@")) return { email: normalizeEmail(raw), phone: "" };
  return { email: "", phone: normalizePhone(raw) };
}

function hashPassword(password, salt = randomBytes(16).toString("hex")) {
  return { salt, hash: scryptSync(password, salt, 64).toString("hex") };
}

function verifyPassword(password, salt, hash) {
  const candidate = scryptSync(password, salt, 64);
  const stored = Buffer.from(hash, "hex");
  return candidate.length === stored.length && timingSafeEqual(candidate, stored);
}

async function loadUsers() {
  if (usersCache) return usersCache;
  try {
    const parsed = JSON.parse(await readFile(usersFile, "utf8"));
    usersCache = Array.isArray(parsed) ? parsed : [];
  } catch {
    usersCache = [];
  }
  return usersCache;
}

async function saveUsers(users) {
  await mkdir(dataDir, { recursive: true });
  await writeFile(usersFile, JSON.stringify(users, null, 2), "utf8");
  usersCache = users;
}

function parseCookies(header = "") {
  const cookies = {};
  for (const part of header.split(";")) {
    const index = part.indexOf("=");
    if (index < 0) continue;
    const key = part.slice(0, index).trim();
    if (!key) continue;
    try {
      cookies[key] = decodeURIComponent(part.slice(index + 1).trim());
    } catch {
      cookies[key] = part.slice(index + 1).trim();
    }
  }
  return cookies;
}

function sessionCookie(request, token, maxAge = SESSION_TTL / 1000) {
  const secure = request.headers["x-forwarded-proto"] === "https" ? "; Secure" : "";
  return `baraah_session=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${maxAge}${secure}`;
}

function clearSessionCookie(request) {
  return sessionCookie(request, "", 0);
}

function getSession(request) {
  const token = parseCookies(request.headers.cookie || "").baraah_session;
  if (!token) return null;
  const session = sessions.get(token);
  if (!session) return null;
  if (session.expires < Date.now()) {
    sessions.delete(token);
    return null;
  }
  return { token, ...session };
}

function createSession(userId, remember = false) {
  const token = randomBytes(32).toString("hex");
  const ttl = remember ? REMEMBER_TTL : SESSION_TTL;
  sessions.set(token, { userId, expires: Date.now() + ttl });
  return token;
}

function json(response, status, payload, extraHeaders = {}) {
  response.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    ...extraHeaders
  });
  response.end(JSON.stringify(payload));
}

function readJsonBody(request, maxBytes = MAX_BODY) {
  return new Promise((resolve, reject) => {
    let size = 0;
    let tooLarge = false;
    const chunks = [];
    request.on("data", (chunk) => {
      size += chunk.length;
      if (size > maxBytes) {
        tooLarge = true;
        return;
      }
      chunks.push(chunk);
    });
    request.on("end", () => {
      if (tooLarge) return reject(new Error("too-large"));
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}"));
      } catch {
        reject(new Error("invalid-json"));
      }
    });
    request.on("error", reject);
  });
}

function sameOrigin(request) {
  const origin = request.headers.origin;
  if (!origin) return true;
  try {
    return new URL(origin).host === request.headers.host;
  } catch {
    return false;
  }
}

function tooManyAttempts(ip) {
  const entry = loginAttempts.get(ip);
  if (!entry) return false;
  if (Date.now() > entry.reset) {
    loginAttempts.delete(ip);
    return false;
  }
  return entry.count >= LOGIN_LIMIT;
}

function noteFailedAttempt(ip) {
  const entry = loginAttempts.get(ip);
  if (!entry || Date.now() > entry.reset) {
    loginAttempts.set(ip, { count: 1, reset: Date.now() + LOGIN_WINDOW });
    return;
  }
  entry.count += 1;
}

async function handleAuth(request, response, pathname) {
  if (pathname === "/api/auth/me" && request.method === "GET") {
    const session = getSession(request);
    const users = await loadUsers();
    const user = session ? users.find((item) => item.id === session.userId) : null;
    if (!user) {
      json(response, 200, { user: null });
      return true;
    }
    json(response, 200, { user: publicUser(user) });
    return true;
  }

  if (request.method !== "POST") {
    json(response, 405, { error: "الطريقة غير مسموحة." });
    return true;
  }

  if (!sameOrigin(request)) {
    json(response, 403, { error: "الطلب مش من نفس الموقع." });
    return true;
  }

  if (pathname === "/api/auth/logout") {
    const session = getSession(request);
    if (session) sessions.delete(session.token);
    json(response, 200, { ok: true }, { "Set-Cookie": clearSessionCookie(request) });
    return true;
  }

  if (pathname !== "/api/auth/register" && pathname !== "/api/auth/login") {
    return false;
  }

  let body;
  try {
    body = await readJsonBody(request);
  } catch (error) {
    json(response, error.message === "too-large" ? 413 : 400, { error: "بيانات الطلب غير صالحة." });
    return true;
  }

  const contact = readIdentifier(body.identifier ?? body.contact ?? body.email ?? body.phone ?? "");
  const email = contact.email;
  const phone = contact.phone;
  const password = String(body.password || "");
  const remember = body.remember === true;
  const sessionMaxAge = (remember ? REMEMBER_TTL : SESSION_TTL) / 1000;

  if (pathname === "/api/auth/register") {
    const name = String(body.name || "").replace(/[\u0000-\u001F\u007F]/g, "").trim().replace(/\s+/g, " ");
    const role = ["parent", "teacher"].includes(body.role) ? body.role : "parent";

    if (name.length < 2 || name.length > 60) {
      json(response, 400, { error: "الاسم لازم يكون من ٢ لـ ٦٠ حرف." });
      return true;
    }
    if (!email && !phone) {
      json(response, 400, { error: "اكتب بريدًا إلكترونيًا أو رقم موبايل صحيحًا." });
      return true;
    }
    if (password.length < 8 || password.length > 128) {
      json(response, 400, { error: "كلمة المرور لازم تكون ٨ أحرف على الأقل." });
      return true;
    }

    const users = await loadUsers();
    if (email && users.some((item) => item.email === email)) {
      json(response, 409, { error: "البريد الإلكتروني مسجّل بالفعل. جرّب تسجيل الدخول." });
      return true;
    }
    if (phone && users.some((item) => item.phone === phone)) {
      json(response, 409, { error: "رقم الموبايل مسجّل بالفعل. جرّب تسجيل الدخول." });
      return true;
    }

    const { salt, hash } = hashPassword(password);
    const user = {
      id: randomUUID(),
      name,
      ...(email ? { email } : {}),
      ...(phone ? { phone } : {}),
      role,
      salt,
      hash,
      createdAt: new Date().toISOString()
    };
    users.push(user);
    await saveUsers(users);

    const token = createSession(user.id, remember);
    json(response, 201, { user: publicUser(user) }, { "Set-Cookie": sessionCookie(request, token, sessionMaxAge) });
    return true;
  }

  const ip = request.socket.remoteAddress || "unknown";
  if (tooManyAttempts(ip)) {
    json(response, 429, { error: "محاولات كتير. استنى ربع ساعة وجرّب تاني." });
    return true;
  }

  if ((!email && !phone) || !password) {
    json(response, 400, { error: "اكتب البريد الإلكتروني أو رقم الموبايل وكلمة المرور." });
    return true;
  }

  const users = await loadUsers();
  const user = users.find((item) => (email && item.email === email) || (phone && item.phone === phone));
  if (!user || !verifyPassword(password, user.salt, user.hash)) {
    noteFailedAttempt(ip);
    json(response, 401, { error: "البريد/الموبايل أو كلمة المرور غير صحيحة." });
    return true;
  }

  loginAttempts.delete(ip);
  const token = createSession(user.id, remember);
  json(response, 200, { user: publicUser(user) }, { "Set-Cookie": sessionCookie(request, token, sessionMaxAge) });
  return true;
}

async function handleData(request, response) {
  const session = getSession(request);
  const users = await loadUsers();
  const user = session ? users.find((item) => item.id === session.userId) : null;
  if (!user) {
    json(response, 401, { error: "سجّل الدخول الأول عشان تحفظ البيانات." });
    return true;
  }
  if (!sameOrigin(request)) {
    json(response, 403, { error: "الطلب مش من نفس الموقع." });
    return true;
  }

  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(user.id)) {
    json(response, 400, { error: "معرّف الحساب غير صالح." });
    return true;
  }
  const backupFile = join(backupsDir, `${user.id}.json`);

  if (request.method === "GET") {
    try {
      const parsed = JSON.parse(await readFile(backupFile, "utf8"));
      json(response, 200, {
        data: parsed && parsed.data && typeof parsed.data === "object" ? parsed.data : null,
        savedAt: parsed && parsed.savedAt ? parsed.savedAt : null
      });
    } catch {
      json(response, 200, { data: null, savedAt: null });
    }
    return true;
  }

  if (request.method === "PUT" || request.method === "POST") {
    let body;
    try {
      body = await readJsonBody(request, MAX_DATA_BODY);
    } catch (error) {
      json(response, error.message === "too-large" ? 413 : 400, { error: "بيانات الحفظ غير صالحة." });
      return true;
    }
    if (!body || !body.data || typeof body.data !== "object" || Array.isArray(body.data)) {
      json(response, 400, { error: "مفيش بيانات صالحة للحفظ." });
      return true;
    }
    const savedAt = new Date().toISOString();
    try {
      await mkdir(backupsDir, { recursive: true });
      await writeFile(backupFile, JSON.stringify({ version: 1, savedAt, data: body.data }, null, 2), "utf8");
    } catch {
      json(response, 500, { error: "مش قادر أحفظ البيانات على الخادم." });
      return true;
    }
    json(response, 200, { ok: true, savedAt });
    return true;
  }

  json(response, 405, { error: "الطريقة غير مسموحة." });
  return true;
}

const server = createServer(async (request, response) => {
  let pathname;
  try {
    pathname = decodeURIComponent(new URL(request.url, `http://${request.headers.host}`).pathname);
  } catch {
    response.writeHead(400, { "Content-Type": "text/plain; charset=utf-8" }).end("Bad request");
    return;
  }

  response.setHeader("X-Content-Type-Options", "nosniff");
  response.setHeader("Referrer-Policy", "same-origin");

  if (pathname.startsWith("/api/")) {
    if (pathname.startsWith("/api/auth/") && (await handleAuth(request, response, pathname))) return;
    if (pathname === "/api/data" && (await handleData(request, response))) return;
    json(response, 404, { error: "المسار غير موجود." });
    return;
  }

  const relative = normalize(pathname === "/" ? "index.html" : pathname.replace(/^\/+/, ""));
  const parts = relative.split(/[\\/]/);
  if (
    relative.startsWith("..") ||
    /^[a-zA-Z]:/.test(relative) ||
    relative.startsWith("\\\\") ||
    parts.includes("data") ||
    parts.some((part) => part.startsWith("."))
  ) {
    response.writeHead(403, { "Content-Type": "text/plain; charset=utf-8" }).end("Forbidden");
    return;
  }

  try {
    const file = await readFile(join(root, relative));
    response.writeHead(200, {
      "Content-Type": types[extname(relative).toLowerCase()] || "application/octet-stream",
      "Cache-Control": "no-cache"
    });
    response.end(file);
  } catch {
    response.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
    response.end("Not found");
  }
});

server.on("error", (error) => {
  if (error.code === "EADDRINUSE") {
    console.error(`Port ${port} is already in use. Try: $env:PORT=4174; node server.mjs`);
  } else {
    console.error(error);
  }
  process.exitCode = 1;
});

setInterval(() => {
  const now = Date.now();
  for (const [token, session] of sessions) {
    if (session.expires < now) sessions.delete(token);
  }
}, 15 * 60 * 1000).unref();

server.listen(port, () => {
  console.log(`BARAAH is running at http://localhost:${port}`);
});
