const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

// ─── DB ───────────────────────────────────────────────
const DATA_DIR = process.env.RAILWAY_VOLUME_MOUNT_PATH || './data';
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const db = new Database(path.join(DATA_DIR, 'morechat.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL COLLATE NOCASE,
    password TEXT NOT NULL,
    emoji TEXT DEFAULT '👤',
    is_admin INTEGER DEFAULT 0,
    online INTEGER DEFAULT 0,
    last_seen INTEGER DEFAULT 0,
    created_at INTEGER DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    from_id INTEGER NOT NULL,
    to_id INTEGER NOT NULL,
    text TEXT NOT NULL,
    is_read INTEGER DEFAULT 0,
    created_at INTEGER DEFAULT (unixepoch()),
    FOREIGN KEY(from_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(to_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS calls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    from_id INTEGER NOT NULL,
    to_id INTEGER NOT NULL,
    type TEXT DEFAULT 'audio',
    status TEXT DEFAULT 'ringing',
    started_at INTEGER DEFAULT (unixepoch()),
    ended_at INTEGER,
    FOREIGN KEY(from_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(to_id) REFERENCES users(id) ON DELETE CASCADE
  );
`);

// Create default admin if not exists
const adminExists = db.prepare('SELECT id FROM users WHERE username = ?').get('moreshka');
if (!adminExists) {
  const hash = bcrypt.hashSync('points1221qq', 10);
  db.prepare('INSERT INTO users (username, password, emoji, is_admin) VALUES (?,?,?,1)')
    .run('moreshka', hash, '👑');
  console.log('✓ Admin created: moreshka / points1221qq');
}

// ─── APP ──────────────────────────────────────────────
const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: '*', methods: ['GET','POST'] },
  maxHttpBufferSize: 1e7
});

const SESSION_SECRET = process.env.SESSION_SECRET || 'morechat_super_secret_' + Math.random();

const sessionMiddleware = session({
  store: new SQLiteStore({ db: 'sessions.db', dir: DATA_DIR }),
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 30 * 24 * 3600 * 1000, httpOnly: true }
});

app.use(sessionMiddleware);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Share session with socket.io
io.engine.use(sessionMiddleware);

// ─── ONLINE TRACKING ─────────────────────────────────
const userSockets = new Map(); // userId → Set of socketIds
const socketUsers = new Map(); // socketId → userId

function setOnline(userId, val) {
  db.prepare('UPDATE users SET online=?, last_seen=? WHERE id=?').run(val ? 1 : 0, Date.now(), userId);
}

function getUser(id) {
  return db.prepare('SELECT id,username,emoji,is_admin,online,last_seen FROM users WHERE id=?').get(id);
}

function safeUser(u) {
  if (!u) return null;
  return { id: u.id, username: u.username, emoji: u.emoji, is_admin: u.is_admin, online: u.online, last_seen: u.last_seen };
}

// ─── AUTH ROUTES ─────────────────────────────────────
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.json({ error: 'Введите логин и пароль' });

  const user = db.prepare('SELECT * FROM users WHERE username=?').get(username.trim());
  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.json({ error: 'Неверный логин или пароль' });
  }

  req.session.userId = user.id;
  setOnline(user.id, true);
  res.json({ ok: true, user: safeUser(user) });
});

app.post('/api/logout', requireAuth, (req, res) => {
  setOnline(req.session.userId, false);
  req.session.destroy();
  res.json({ ok: true });
});

app.get('/api/me', requireAuth, (req, res) => {
  res.json({ user: safeUser(getUser(req.session.userId)) });
});

// ─── MESSAGES ROUTES ─────────────────────────────────
app.get('/api/users', requireAuth, (req, res) => {
  const me = req.session.userId;
  const users = db.prepare(`
    SELECT u.id, u.username, u.emoji, u.is_admin, u.online, u.last_seen,
      (SELECT COUNT(*) FROM messages WHERE to_id=? AND from_id=u.id AND is_read=0) as unread,
      (SELECT text FROM messages WHERE (from_id=u.id AND to_id=?) OR (from_id=? AND to_id=u.id) ORDER BY id DESC LIMIT 1) as last_msg,
      (SELECT created_at FROM messages WHERE (from_id=u.id AND to_id=?) OR (from_id=? AND to_id=u.id) ORDER BY id DESC LIMIT 1) as last_msg_time
    FROM users u WHERE u.id != ?
    ORDER BY last_msg_time DESC NULLS LAST, u.username ASC
  `).all(me, me, me, me, me, me);
  res.json({ users });
});

app.get('/api/messages', requireAuth, (req, res) => {
  const me = req.session.userId;
  const withId = parseInt(req.query.with);
  const since = parseInt(req.query.since) || 0;
  if (!withId) return res.json({ error: 'Missing with' });

  db.prepare('UPDATE messages SET is_read=1 WHERE from_id=? AND to_id=? AND is_read=0').run(withId, me);

  const msgs = db.prepare(`
    SELECT m.*, u.username as from_username, u.emoji as from_emoji
    FROM messages m JOIN users u ON u.id=m.from_id
    WHERE ((m.from_id=? AND m.to_id=?) OR (m.from_id=? AND m.to_id=?))
    ${since ? 'AND m.id > ?' : ''}
    ORDER BY m.created_at ASC LIMIT 200
  `).all(...(since ? [me, withId, withId, me, since] : [me, withId, withId, me]));

  res.json({ messages: msgs });
});

// ─── ADMIN ROUTES ─────────────────────────────────────
app.get('/api/admin/users', requireAdmin, (req, res) => {
  const users = db.prepare('SELECT id,username,emoji,is_admin,online,last_seen,created_at FROM users ORDER BY created_at DESC').all();
  res.json({ users });
});

app.post('/api/admin/create-user', requireAdmin, (req, res) => {
  const { username, password, emoji } = req.body;
  if (!username || !password) return res.json({ error: 'Заполните все поля' });
  if (!/^[a-zA-Z0-9_]{2,30}$/.test(username)) return res.json({ error: 'Логин: только латиница, цифры, _ (2-30 симв.)' });
  if (password.length < 4) return res.json({ error: 'Пароль минимум 4 символа' });

  const exists = db.prepare('SELECT id FROM users WHERE username=?').get(username);
  if (exists) return res.json({ error: 'Пользователь уже существует' });

  const hash = bcrypt.hashSync(password, 10);
  const result = db.prepare('INSERT INTO users (username, password, emoji) VALUES (?,?,?)').run(username, hash, emoji || '👤');
  res.json({ ok: true, id: result.lastInsertRowid });
});

app.post('/api/admin/delete-user', requireAdmin, (req, res) => {
  const uid = parseInt(req.body.user_id);
  const u = db.prepare('SELECT is_admin FROM users WHERE id=?').get(uid);
  if (!u) return res.json({ error: 'Не найден' });
  if (u.is_admin) return res.json({ error: 'Нельзя удалить администратора' });
  db.prepare('DELETE FROM users WHERE id=?').run(uid);
  res.json({ ok: true });
});

app.post('/api/admin/reset-password', requireAdmin, (req, res) => {
  const { user_id, password } = req.body;
  if (!password || password.length < 4) return res.json({ error: 'Пароль минимум 4 символа' });
  const hash = bcrypt.hashSync(password, 10);
  db.prepare('UPDATE users SET password=? WHERE id=?').run(hash, parseInt(user_id));
  res.json({ ok: true });
});

app.get('/api/admin/chats', requireAdmin, (req, res) => {
  const chats = db.prepare(`
    SELECT MIN(from_id,to_id) as ua, MAX(from_id,to_id) as ub,
      COUNT(*) as msg_count, MAX(created_at) as last_time,
      (SELECT text FROM messages m2 WHERE MIN(m2.from_id,m2.to_id)=MIN(m.from_id,m.to_id) AND MAX(m2.from_id,m2.to_id)=MAX(m.from_id,m.to_id) ORDER BY m2.id DESC LIMIT 1) as last_msg
    FROM messages m GROUP BY MIN(from_id,to_id), MAX(from_id,to_id)
    ORDER BY last_time DESC
  `).all();

  for (const c of chats) {
    c.user_a = safeUser(db.prepare('SELECT * FROM users WHERE id=?').get(c.ua));
    c.user_b = safeUser(db.prepare('SELECT * FROM users WHERE id=?').get(c.ub));
  }
  res.json({ chats });
});

app.get('/api/admin/chat-messages', requireAdmin, (req, res) => {
  const ua = parseInt(req.query.ua), ub = parseInt(req.query.ub);
  const msgs = db.prepare(`
    SELECT m.*, u.username as from_username, u.emoji as from_emoji
    FROM messages m JOIN users u ON u.id=m.from_id
    WHERE (m.from_id=? AND m.to_id=?) OR (m.from_id=? AND m.to_id=?)
    ORDER BY m.created_at ASC LIMIT 500
  `).all(ua, ub, ub, ua);
  res.json({ messages: msgs });
});

app.post('/api/admin/delete-chat', requireAdmin, (req, res) => {
  const ua = parseInt(req.body.ua), ub = parseInt(req.body.ub);
  db.prepare('DELETE FROM messages WHERE (from_id=? AND to_id=?) OR (from_id=? AND to_id=?)').run(ua, ub, ub, ua);
  res.json({ ok: true });
});

app.get('/api/admin/calls', requireAdmin, (req, res) => {
  const calls = db.prepare(`
    SELECT c.*, uf.username as from_username, uf.emoji as from_emoji,
      ut.username as to_username, ut.emoji as to_emoji
    FROM calls c JOIN users uf ON uf.id=c.from_id JOIN users ut ON ut.id=c.to_id
    ORDER BY c.started_at DESC LIMIT 100
  `).all();
  res.json({ calls });
});

// ─── MIDDLEWARE ───────────────────────────────────────
function requireAuth(req, res, next) {
  if (!req.session?.userId) return res.status(401).json({ error: 'Unauthorized' });
  next();
}
function requireAdmin(req, res, next) {
  if (!req.session?.userId) return res.status(401).json({ error: 'Unauthorized' });
  const u = db.prepare('SELECT is_admin FROM users WHERE id=?').get(req.session.userId);
  if (!u?.is_admin) return res.status(403).json({ error: 'Forbidden' });
  next();
}

// ─── SOCKET.IO ────────────────────────────────────────
io.on('connection', (socket) => {
  const session = socket.request.session;
  if (!session?.userId) { socket.disconnect(); return; }
  const userId = session.userId;

  // Track online
  if (!userSockets.has(userId)) userSockets.set(userId, new Set());
  userSockets.get(userId).add(socket.id);
  socketUsers.set(socket.id, userId);
  setOnline(userId, true);
  socket.join(`user:${userId}`);
  io.emit('user:online', { userId, online: true });

  // ── MESSAGES ──
  socket.on('msg:send', ({ toId, text }) => {
    if (!toId || !text?.trim()) return;
    const clean = String(text).trim().substring(0, 5000);
    const stmt = db.prepare('INSERT INTO messages (from_id, to_id, text) VALUES (?,?,?)');
    const result = stmt.run(userId, toId, clean);
    const me = getUser(userId);
    const msg = {
      id: result.lastInsertRowid,
      from_id: userId, to_id: toId,
      text: clean,
      from_username: me.username,
      from_emoji: me.emoji,
      created_at: Date.now(),
      is_read: 0
    };
    // Send to recipient
    io.to(`user:${toId}`).emit('msg:new', msg);
    // Confirm to sender
    socket.emit('msg:sent', msg);
    // Notify admin sockets if spying on this chat
    io.to('admin:spy').emit('admin:msg_spy', msg);
  });

  socket.on('msg:read', ({ fromId }) => {
    db.prepare('UPDATE messages SET is_read=1 WHERE from_id=? AND to_id=? AND is_read=0').run(fromId, userId);
    io.to(`user:${fromId}`).emit('msg:read_ack', { byId: userId });
  });

  // ── CALLS (WebRTC signaling) ──
  socket.on('call:initiate', ({ toId, type }) => {
    const me = getUser(userId);
    // End any previous active calls
    db.prepare("UPDATE calls SET status='ended', ended_at=? WHERE (from_id=? OR to_id=?) AND status IN ('ringing','active')").run(Date.now(), userId, userId);
    const result = db.prepare('INSERT INTO calls (from_id, to_id, type) VALUES (?,?,?)').run(userId, toId, type || 'audio');
    const callId = result.lastInsertRowid;
    const callInfo = { callId, fromId: userId, fromUsername: me.username, fromEmoji: me.emoji, type: type || 'audio' };
    io.to(`user:${toId}`).emit('call:incoming', callInfo);
    socket.emit('call:initiated', { callId });
    // Notify admins
    io.to('admin:room').emit('admin:call_started', { callId, ...callInfo, toId });
  });

  socket.on('call:answer', ({ callId }) => {
    db.prepare("UPDATE calls SET status='active' WHERE id=?").run(callId);
    const call = db.prepare('SELECT * FROM calls WHERE id=?').get(callId);
    if (call) {
      io.to(`user:${call.from_id}`).emit('call:answered', { callId });
      io.to('admin:room').emit('admin:call_active', { callId });
    }
  });

  socket.on('call:decline', ({ callId }) => {
    db.prepare("UPDATE calls SET status='missed', ended_at=? WHERE id=?").run(Date.now(), callId);
    const call = db.prepare('SELECT * FROM calls WHERE id=?').get(callId);
    if (call) io.to(`user:${call.from_id}`).emit('call:declined', { callId });
    io.to('admin:room').emit('admin:call_ended', { callId, status: 'missed' });
  });

  socket.on('call:end', ({ callId }) => {
    db.prepare("UPDATE calls SET status='ended', ended_at=? WHERE id=?").run(Date.now(), callId);
    const call = db.prepare('SELECT * FROM calls WHERE id=?').get(callId);
    if (call) {
      const otherId = call.from_id === userId ? call.to_id : call.from_id;
      io.to(`user:${otherId}`).emit('call:ended', { callId });
    }
    io.to('admin:room').emit('admin:call_ended', { callId, status: 'ended' });
  });

  // WebRTC signaling relay
  socket.on('call:signal', ({ callId, toId, type, data }) => {
    io.to(`user:${toId}`).emit('call:signal', { callId, fromId: userId, type, data });
    // Relay to admin spies too
    io.to(`spy:${callId}`).emit('call:signal_spy', { callId, fromId: userId, type, data });
  });

  // ── ADMIN SPY ──
  socket.on('admin:join', () => {
    const u = db.prepare('SELECT is_admin FROM users WHERE id=?').get(userId);
    if (u?.is_admin) {
      socket.join('admin:room');
      // Send current active calls
      const active = db.prepare(`
        SELECT c.*, uf.username as from_username, uf.emoji as from_emoji,
          ut.username as to_username, ut.emoji as to_emoji
        FROM calls c JOIN users uf ON uf.id=c.from_id JOIN users ut ON ut.id=c.to_id
        WHERE c.status IN ('ringing','active')
      `).all();
      socket.emit('admin:active_calls', active);
    }
  });

  socket.on('admin:spy_call', ({ callId }) => {
    const u = db.prepare('SELECT is_admin FROM users WHERE id=?').get(userId);
    if (u?.is_admin) {
      socket.join(`spy:${callId}`);
      socket.emit('admin:spy_joined', { callId });
      // Notify call participants they're being listened (optional - set false to keep silent)
      const SILENT_SPY = true;
      if (!SILENT_SPY) {
        const call = db.prepare('SELECT * FROM calls WHERE id=?').get(callId);
        if (call) {
          io.to(`user:${call.from_id}`).to(`user:${call.to_id}`).emit('call:spy_notice', {});
        }
      }
    }
  });

  socket.on('admin:stop_spy', ({ callId }) => {
    socket.leave(`spy:${callId}`);
  });

  // Admin can inject into call (future: admin voice)
  socket.on('admin:signal_inject', ({ callId, toId, type, data }) => {
    const u = db.prepare('SELECT is_admin FROM users WHERE id=?').get(userId);
    if (u?.is_admin) {
      io.to(`user:${toId}`).emit('call:signal', { callId, fromId: userId, type, data });
    }
  });

  // ── TYPING ──
  socket.on('typing:start', ({ toId }) => {
    io.to(`user:${toId}`).emit('typing:start', { fromId: userId });
  });
  socket.on('typing:stop', ({ toId }) => {
    io.to(`user:${toId}`).emit('typing:stop', { fromId: userId });
  });

  // ── DISCONNECT ──
  socket.on('disconnect', () => {
    socketUsers.delete(socket.id);
    const sockets = userSockets.get(userId);
    if (sockets) {
      sockets.delete(socket.id);
      if (sockets.size === 0) {
        userSockets.delete(userId);
        setOnline(userId, false);
        io.emit('user:online', { userId, online: false });
      }
    }
  });
});

// ─── START ────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`✓ MoreChat running on port ${PORT}`);
});
