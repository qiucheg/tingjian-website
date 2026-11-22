const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const fs = require('fs');

if (process.env.NODE_ENV === 'production' && !process.env.SESSION_SECRET) throw new Error('SESSION_SECRET is required in production');
const app = express();
app.set('trust proxy', 1);
const PORT = process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const UPLOAD_DIR = process.env.UPLOAD_DIR || path.join(__dirname, 'uploads');
fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(UPLOAD_DIR, { recursive: true });
const db = new Database(path.join(DATA_DIR, 'tingjian.sqlite'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT,nickname TEXT NOT NULL UNIQUE,password_hash TEXT NOT NULL,points INTEGER NOT NULL DEFAULT 0,is_admin INTEGER NOT NULL DEFAULT 0,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP); CREATE TABLE IF NOT EXISTS sounds (id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL,title TEXT NOT NULL,answer TEXT NOT NULL,options TEXT NOT NULL,story TEXT NOT NULL,audio_path TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'pending',created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,reviewed_at TEXT,FOREIGN KEY(user_id) REFERENCES users(id)); CREATE TABLE IF NOT EXISTS plays (id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL,sound_id INTEGER NOT NULL,tries INTEGER NOT NULL DEFAULT 0,solved INTEGER NOT NULL DEFAULT 0,revealed INTEGER NOT NULL DEFAULT 0,awarded INTEGER NOT NULL DEFAULT 0,UNIQUE(user_id,sound_id),FOREIGN KEY(user_id) REFERENCES users(id),FOREIGN KEY(sound_id) REFERENCES sounds(id)); CREATE TABLE IF NOT EXISTS comments (id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL,sound_id INTEGER NOT NULL,body TEXT NOT NULL,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,FOREIGN KEY(user_id) REFERENCES users(id),FOREIGN KEY(sound_id) REFERENCES sounds(id));");

if (process.env.ADMIN_PASSWORD) {
  const name = process.env.ADMIN_NICKNAME || 'admin';
  const hash = bcrypt.hashSync(process.env.ADMIN_PASSWORD, 12);
  const old = db.prepare('SELECT id FROM users WHERE nickname=?').get(name);
  if (old) db.prepare('UPDATE users SET password_hash=?,is_admin=1 WHERE id=?').run(hash, old.id);
  else db.prepare('INSERT INTO users(nickname,password_hash,is_admin) VALUES(?,?,1)').run(name, hash);
}

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false }));
app.use(session({
  store: new SQLiteStore({ db: 'sessions.sqlite', dir: DATA_DIR }),
  secret: process.env.SESSION_SECRET || 'local-development-only-secret',
  resave: false, saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', maxAge: 7 * 86400000 }
}));
app.use('/uploads', express.static(UPLOAD_DIR, { maxAge: '1d', fallthrough: false }));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/api', rateLimit({ windowMs: 60000, limit: 120, standardHeaders: true, legacyHeaders: false }));

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, UPLOAD_DIR),
  filename: (_req, file, cb) => cb(null, Date.now() + '-' + Math.random().toString(36).slice(2) + path.extname(file.originalname).toLowerCase())
});
const upload = multer({ storage, limits: { fileSize: 20 * 1024 * 1024 }, fileFilter: (_req, file, cb) => {
  const ok = ['audio/mpeg','audio/mp3','audio/wav','audio/x-wav','audio/wave','audio/ogg','audio/mp4','audio/aac','audio/webm'].includes(file.mimetype) || /\.(mp3|wav|ogg|m4a|aac|webm)$/i.test(file.originalname);
  cb(ok ? null : new Error('请上传 MP3、WAV、OGG、M4A、AAC 或 WEBM 音频文件。'), ok);
}});
const safeUser = u => u && ({ id: u.id, nickname: u.nickname, points: u.points, isAdmin: !!u.is_admin });
function currentUser(req) { return req.session.userId ? db.prepare('SELECT * FROM users WHERE id=?').get(req.session.userId) : null; }
function requireUser(req,res,next) { const u=currentUser(req); if(!u) return res.status(401).json({error:'请先登录后再操作。'}); req.user=u; next(); }
function requireAdmin(req,res,next) { const u=currentUser(req); if(!u || !u.is_admin) return res.status(403).json({error:'需要管理员权限。'}); req.user=u; next(); }
function publicSound(s, userId) {
  const p = userId ? db.prepare('SELECT tries,solved,revealed,awarded FROM plays WHERE user_id=? AND sound_id=?').get(userId,s.id) : null;
  return { id:s.id,title:s.title,audioUrl:'/uploads/'+encodeURIComponent(s.audio_path),story:s.story,creator:s.creator || '匿名声音旅人',createdAt:s.created_at,tries:p?.tries||0,solved:!!p?.solved,revealed:!!p?.revealed,awarded:p?.awarded||0,answer:(p?.solved||p?.revealed)?s.answer:null,options:JSON.parse(s.options) };
}
app.get('/api/health',(_req,res)=>res.json({ok:true}));
app.get('/api/me',(req,res)=>res.json({user:safeUser(currentUser(req))}));
app.post('/api/register',async(req,res)=>{
  const nickname=String(req.body.nickname||'').trim(), password=String(req.body.password||'');
  if(nickname.length<2||nickname.length>16) return res.status(400).json({error:'昵称请设置为 2–16 个字符。'});
  if(password.length<8) return res.status(400).json({error:'密码至少需要 8 位。'});
  try { const hash=await bcrypt.hash(password,12); const info=db.prepare('INSERT INTO users(nickname,password_hash) VALUES(?,?)').run(nickname,hash); req.session.userId=info.lastInsertRowid; res.json({user:safeUser(currentUser(req))}); }
  catch(e){res.status(409).json({error:e.code==='SQLITE_CONSTRAINT_UNIQUE'?'这个昵称已经被使用，请换一个。':'注册失败，请稍后再试。'});}
});
app.post('/api/login',async(req,res)=>{
  const nickname=String(req.body.nickname||'').trim(), password=String(req.body.password||'');
  const u=db.prepare('SELECT * FROM users WHERE nickname=?').get(nickname);
  if(!u||!(await bcrypt.compare(password,u.password_hash))) return res.status(400).json({error:'昵称或密码不正确。'});
  req.session.userId=u.id; res.json({user:safeUser(u)});
});
app.post('/api/logout',(req,res)=>req.session.destroy(()=>res.json({ok:true})));
app.get('/api/sounds',(req,res)=>{
  const u=currentUser(req);
  const rows=db.prepare("SELECT s.*,u.nickname creator FROM sounds s JOIN users u ON u.id=s.user_id WHERE s.status='approved' ORDER BY s.created_at DESC").all();
  res.json({sounds:rows.map(s=>publicSound(s,u?.id))});
});
app.get('/api/sounds/:id/comments',(req,res)=>{
  const rows=db.prepare("SELECT c.id,c.body,c.created_at,u.nickname FROM comments c JOIN users u ON u.id=c.user_id JOIN sounds s ON s.id=c.sound_id WHERE c.sound_id=? AND s.status='approved' ORDER BY c.created_at DESC").all(req.params.id);
  res.json({comments:rows});
});
app.post('/api/sounds/:id/comments',requireUser,(req,res)=>{
  const s=db.prepare("SELECT id FROM sounds WHERE id=? AND status='approved'").get(req.params.id), body=String(req.body.body||'').trim();
  if(!s) return res.status(404).json({error:'声音不存在。'});
  if(!body||body.length>300) return res.status(400).json({error:'留言请控制在 1–300 个字符。'});
  db.prepare('INSERT INTO comments(user_id,sound_id,body) VALUES(?,?,?)').run(req.user.id,s.id,body); res.json({ok:true});
});
app.post('/api/sounds/:id/guess',requireUser,(req,res)=>{
  const s=db.prepare("SELECT * FROM sounds WHERE id=? AND status='approved'").get(req.params.id);
  if(!s) return res.status(404).json({error:'没有找到这条声音。'});
  const p=db.prepare('SELECT * FROM plays WHERE user_id=? AND sound_id=?').get(req.user.id,s.id);
  if(p?.solved||p?.revealed) return res.status(400).json({error:'这条声音已经揭晓过啦。',answer:s.answer});
  const guess=String(req.body.guess||'').trim(), options=JSON.parse(s.options);
  if(!options.includes(guess)) return res.status(400).json({error:'请选择页面提供的选项。'});
  const tries=(p?.tries||0)+1, correct=guess.toLocaleLowerCase()===s.answer.trim().toLocaleLowerCase();
  const points=correct?(tries===1?3:tries===2?2:1):0;
  if(!p) db.prepare('INSERT INTO plays(user_id,sound_id,tries,solved,awarded) VALUES(?,?,?,?,?)').run(req.user.id,s.id,tries,correct?1:0,points);
  else db.prepare('UPDATE plays SET tries=?,solved=?,awarded=? WHERE id=?').run(tries,correct?1:0,points,p.id);
  if(points) db.prepare('UPDATE users SET points=points+? WHERE id=?').run(points,req.user.id);
  res.json({correct,tries,points,answer:correct?s.answer:null,story:correct?s.story:null,user:safeUser(currentUser(req)),message:correct?'猜对啦！获得 '+points+' 积分。':'还差一点，再听听看，或者换个选项试试。'});
});
app.post('/api/sounds/:id/reveal',requireUser,(req,res)=>{
  const s=db.prepare("SELECT * FROM sounds WHERE id=? AND status='approved'").get(req.params.id);
  if(!s) return res.status(404).json({error:'声音不存在。'});
  const p=db.prepare('SELECT * FROM plays WHERE user_id=? AND sound_id=?').get(req.user.id,s.id);
  if(!p) db.prepare('INSERT INTO plays(user_id,sound_id,revealed) VALUES(?,?,1)').run(req.user.id,s.id);
  else if(!p.solved) db.prepare('UPDATE plays SET revealed=1 WHERE id=?').run(p.id);
  res.json({answer:s.answer,story:s.story,points:0,message:'答案已揭晓，本次没有获得积分。'});
});
app.post('/api/sounds',requireUser,upload.single('audio'),(req,res)=>{
  if(!req.file) return res.status(400).json({error:'请先选择一段音频。'});
  const title=String(req.body.title||'').trim(), answer=String(req.body.answer||'').trim(), story=String(req.body.story||'').trim();
  const wrong=[req.body.wrong1,req.body.wrong2,req.body.wrong3].map(x=>String(x||'').trim());
  if(!title||!answer||!story||wrong.some(x=>!x)||wrong.some(x=>x.toLowerCase()===answer.toLowerCase())||new Set(wrong.map(x=>x.toLowerCase())).size!==3) {
    fs.unlinkSync(req.file.path); return res.status(400).json({error:'请填写名称、正确答案、三个互不重复的干扰选项和故事。'});
  }
  const options=[answer,...wrong].sort(()=>Math.random()-.5);
  db.prepare('INSERT INTO sounds(user_id,title,answer,options,story,audio_path) VALUES(?,?,?,?,?,?)').run(req.user.id,title,answer,JSON.stringify(options),story,req.file.filename);
  res.json({ok:true,message:'声音已提交，审核通过后就会出现在声音盲盒中。'});
});
app.get('/api/leaderboard',(req,res)=>res.json({users:db.prepare('SELECT nickname,points FROM users ORDER BY points DESC,created_at ASC LIMIT 30').all()}));
app.get('/api/mine',requireUser,(req,res)=>{
  const sounds=db.prepare('SELECT id,title,status,created_at FROM sounds WHERE user_id=? ORDER BY created_at DESC').all(req.user.id);
  const comments=db.prepare('SELECT c.body,c.created_at,s.title FROM comments c JOIN sounds s ON s.id=c.sound_id WHERE s.user_id=? ORDER BY c.created_at DESC LIMIT 30').all(req.user.id);
  res.json({sounds,comments});
});
app.get('/api/admin/pending',requireAdmin,(req,res)=>{
  const rows=db.prepare("SELECT s.*,u.nickname creator FROM sounds s JOIN users u ON u.id=s.user_id WHERE s.status='pending' ORDER BY s.created_at ASC").all();
  res.json({sounds:rows.map(s=>({...s,audioUrl:'/uploads/'+encodeURIComponent(s.audio_path),options:JSON.parse(s.options)}))});
});
app.post('/api/admin/sounds/:id/review',requireAdmin,(req,res)=>{
  const status=req.body.status;
  if(!['approved','rejected'].includes(status)) return res.status(400).json({error:'无效的审核状态。'});
  const info=db.prepare("UPDATE sounds SET status=?,reviewed_at=CURRENT_TIMESTAMP WHERE id=? AND status='pending'").run(status,req.params.id);
  if(!info.changes) return res.status(404).json({error:'记录不存在或已审核。'});
  res.json({ok:true});
});
app.get('/api/admin/stats',requireAdmin,(_req,res)=>res.json({users:db.prepare('SELECT COUNT(*) n FROM users').get().n,sounds:db.prepare('SELECT COUNT(*) n FROM sounds').get().n,pending:db.prepare("SELECT COUNT(*) n FROM sounds WHERE status='pending'").get().n}));
app.use((err,_req,res,_next)=>{
  console.error(err);
  if(err instanceof multer.MulterError) return res.status(400).json({error:err.code==='LIMIT_FILE_SIZE'?'音频不能超过 20MB。':'音频上传失败。'});
  res.status(400).json({error:err.message||'请求失败，请稍后重试。'});
});
app.listen(PORT,()=>console.log('听见另一种画面已启动，端口 '+PORT));
