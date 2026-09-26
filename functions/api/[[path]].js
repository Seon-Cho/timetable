// 시간표 앱 계정 API (Cloudflare Pages Functions + D1)
//   POST /api/signup  {name, password}  → 새 계정 만들기
//   POST /api/login   {name, password}  → 로그인
//   GET  /api/data                       → 저장된 일정 불러오기 (로그인 필요)
//   PUT  /api/data    (일정 JSON)        → 일정 저장 (로그인 필요)
//   POST /api/logout                     → 로그아웃
//   GET  /api/ping                       → 서버 연결 확인
// 비밀번호는 PBKDF2(SHA-256)로 해시해서 저장하고, 원래 비밀번호는 저장하지 않는다.

const enc = new TextEncoder();
const NAME_RE = /^[A-Za-z0-9가-힣_-]{2,20}$/;
const SESSION_DAYS = 30;
const MAX_DATA = 200_000; // 일정 데이터 최대 크기 (글자 수)
let ready = false;

const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
  });

const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
const fromHex = (h) => new Uint8Array(h.match(/../g).map((x) => parseInt(x, 16)));
const randomHex = (n) => hex(crypto.getRandomValues(new Uint8Array(n)));

async function hashPassword(password, saltHex) {
  const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: fromHex(saltHex), iterations: 100000 },
    key,
    256
  );
  return hex(bits);
}

function sameString(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

async function setup(db) {
  if (ready) return;
  await db.batch([
    db.prepare(
      "CREATE TABLE IF NOT EXISTS users (name TEXT PRIMARY KEY, salt TEXT NOT NULL, hash TEXT NOT NULL, data TEXT, updated INTEGER)"
    ),
    db.prepare("CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, name TEXT NOT NULL, expires INTEGER NOT NULL)"),
  ]);
  ready = true;
}

async function newSession(db, name) {
  const token = randomHex(32);
  const now = Date.now();
  await db.batch([
    db.prepare("DELETE FROM sessions WHERE expires < ?").bind(now),
    db.prepare("INSERT INTO sessions (token, name, expires) VALUES (?, ?, ?)").bind(token, name, now + SESSION_DAYS * 864e5),
  ]);
  return token;
}

async function currentUser(db, request) {
  const auth = request.headers.get("authorization") || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  if (!/^[0-9a-f]{64}$/.test(token)) return null;
  const row = await db.prepare("SELECT name, expires FROM sessions WHERE token = ?").bind(token).first();
  if (!row || row.expires < Date.now()) return null;
  return { name: row.name, token };
}

async function readCredentials(request) {
  let body;
  try {
    body = await request.json();
  } catch {
    return { error: json({ error: "요청 형식이 잘못됐어요." }, 400) };
  }
  const name = String(body.name || "").trim();
  const password = String(body.password || "");
  if (!NAME_RE.test(name))
    return { error: json({ error: "계정 이름은 2–20자의 한글, 영문, 숫자, _, - 만 쓸 수 있어요." }, 400) };
  if (password.length < 4 || password.length > 100)
    return { error: json({ error: "비밀번호는 4자 이상 100자 이하로 정해 주세요." }, 400) };
  return { name, password };
}

export async function onRequest({ request, env, params }) {
  const db = env.DB;
  if (!db) return json({ error: "서버 저장소(D1)가 연결되지 않았어요." }, 500);
  const path = (params.path || []).join("/");
  const method = request.method;

  try {
    await setup(db);

    if (path === "ping") return json({ ok: true });

    if (method === "POST" && (path === "signup" || path === "login")) {
      const cred = await readCredentials(request);
      if (cred.error) return cred.error;
      const user = await db.prepare("SELECT salt, hash, data FROM users WHERE name = ?").bind(cred.name).first();

      if (path === "signup") {
        if (user) return json({ error: "이미 있는 계정 이름이에요. 다른 이름을 쓰거나 로그인하세요." }, 409);
        const salt = randomHex(16);
        const hash = await hashPassword(cred.password, salt);
        await db
          .prepare("INSERT INTO users (name, salt, hash, data, updated) VALUES (?, ?, ?, NULL, ?)")
          .bind(cred.name, salt, hash, Date.now())
          .run();
        return json({ token: await newSession(db, cred.name), name: cred.name, data: null });
      }

      if (!user || !sameString(await hashPassword(cred.password, user.salt), user.hash))
        return json({ error: "계정 이름 또는 비밀번호가 맞지 않아요." }, 401);
      return json({
        token: await newSession(db, cred.name),
        name: cred.name,
        data: user.data ? JSON.parse(user.data) : null,
      });
    }

    const me = await currentUser(db, request);
    if (!me) return json({ error: "다시 로그인해 주세요." }, 401);

    if (path === "data" && method === "GET") {
      const row = await db.prepare("SELECT data, updated FROM users WHERE name = ?").bind(me.name).first();
      return json({ name: me.name, data: row && row.data ? JSON.parse(row.data) : null, updated: row ? row.updated : null });
    }

    if (path === "data" && method === "PUT") {
      const text = await request.text();
      if (text.length > MAX_DATA) return json({ error: "저장할 일정이 너무 커요." }, 413);
      try {
        const parsed = JSON.parse(text);
        if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error();
      } catch {
        return json({ error: "일정 데이터 형식이 잘못됐어요." }, 400);
      }
      const now = Date.now();
      await db.prepare("UPDATE users SET data = ?, updated = ? WHERE name = ?").bind(text, now, me.name).run();
      return json({ ok: true, updated: now });
    }

    if (path === "logout" && method === "POST") {
      await db.prepare("DELETE FROM sessions WHERE token = ?").bind(me.token).run();
      return json({ ok: true });
    }

    return json({ error: "없는 주소예요." }, 404);
  } catch (e) {
    return json({ error: "서버에서 오류가 났어요. 잠시 후 다시 시도해 주세요." }, 500);
  }
}
