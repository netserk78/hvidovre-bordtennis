#!/usr/bin/env python3
"""
Hvidovre Bordtennis Klub — server
Kræver kun Python 3.7+ (ingen pakker nødvendige)
Start: python3 server.py
"""
import http.server, sqlite3, json, hashlib, secrets, os, re
from urllib.parse import urlparse, parse_qs
from datetime import datetime, date, timedelta

DB = os.environ.get('DB_PATH', os.path.join(os.path.dirname(__file__), 'bordtennis.db'))
PUBLIC = os.path.join(os.path.dirname(__file__), 'public')
sessions = {}   # token -> user_id

# ── Database ──────────────────────────────────────────────────────────────────
def db():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    return c

def init_db():
    with db() as c:
        c.executescript('''
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                pwd_hash TEXT NOT NULL,
                is_admin INTEGER DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS bookings (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                user_name TEXT NOT NULL,
                table_num INTEGER NOT NULL,
                date TEXT NOT NULL,
                slot TEXT NOT NULL,
                UNIQUE(table_num, date, slot)
            );
        ''')
        if not c.execute("SELECT 1 FROM users WHERE email='admin@hvidovrebk.dk'").fetchone():
            c.execute("INSERT INTO users VALUES (?,?,?,?,1)",
                (secrets.token_hex(8), 'Admin', 'admin@hvidovrebk.dk',
                 hashlib.sha256(b'admin123').hexdigest()))
            c.commit()

def hash_pwd(p): return hashlib.sha256(p.encode()).hexdigest()

def session_user(handler):
    for part in handler.headers.get('Cookie','').split(';'):
        k,_,v = part.strip().partition('=')
        if k == 'session' and v in sessions:
            with db() as c:
                return c.execute("SELECT * FROM users WHERE id=?", (sessions[v],)).fetchone()
    return None

# ── Handler ───────────────────────────────────────────────────────────────────
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def json(self, data, code=200):
        body = json.dumps(data, default=str).encode()
        self.send_response(code)
        self.send_header('Content-Type','application/json')
        self.send_header('Content-Length', len(body))
        self.end_headers(); self.wfile.write(body)

    def body(self):
        n = int(self.headers.get('Content-Length',0))
        return json.loads(self.rfile.read(n)) if n else {}

    def set_cookie(self, token):
        self.send_header('Set-Cookie', f'session={token}; HttpOnly; Path=/')
    def clr_cookie(self):
        self.send_header('Set-Cookie', 'session=; Path=/; Max-Age=0')

    def user_dict(self, u):
        return {'id':u['id'],'name':u['name'],'email':u['email'],'isAdmin':bool(u['is_admin'])}

    # ── GET ───────────────────────────────────────────────────────────────────
    def do_GET(self):
        p = urlparse(self.path)
        if p.path.startswith('/api/'):
            self.api_get(p.path, parse_qs(p.query))
        else:
            self.static(p.path)

    def static(self, path):
        path = '/index.html' if path == '/' else path
        fp = os.path.join(PUBLIC, path.lstrip('/'))
        if not os.path.isfile(fp):
            fp = os.path.join(PUBLIC, 'index.html')
        with open(fp,'rb') as f: body = f.read()
        ct = 'text/html' if fp.endswith('.html') else 'text/plain'
        self.send_response(200)
        self.send_header('Content-Type', ct+'; charset=utf-8')
        self.end_headers(); self.wfile.write(body)

    def api_get(self, path, qs):
        u = session_user(self)
        if path == '/api/me':
            return self.json(self.user_dict(u) if u else None)

        if path == '/api/bookings':
            d = qs.get('date',[''])[0]
            with db() as c:
                rows = c.execute("SELECT * FROM bookings WHERE date=?", (d,)).fetchall()
            return self.json([dict(r) for r in rows])

        if path == '/api/mybookings':
            if not u: return self.json({'error':'Ikke logget ind'},401)
            with db() as c:
                rows = c.execute("SELECT * FROM bookings WHERE user_id=? ORDER BY date,slot",(u['id'],)).fetchall()
            return self.json([dict(r) for r in rows])

        if path == '/api/admin/bookings':
            if not u or not u['is_admin']: return self.json({'error':'Ingen adgang'},403)
            with db() as c:
                rows = c.execute("SELECT * FROM bookings ORDER BY date,slot").fetchall()
            return self.json([dict(r) for r in rows])

        if path == '/api/admin/users':
            if not u or not u['is_admin']: return self.json({'error':'Ingen adgang'},403)
            with db() as c:
                users = c.execute("SELECT id,name,email FROM users WHERE is_admin=0").fetchall()
                counts = {r['user_id']:r['cnt'] for r in
                    c.execute("SELECT user_id,COUNT(*) cnt FROM bookings GROUP BY user_id").fetchall()}
            return self.json([{**dict(r),'bookingCount':counts.get(r['id'],0)} for r in users])

        self.json({'error':'Ikke fundet'},404)

    # ── POST ──────────────────────────────────────────────────────────────────
    def do_POST(self):
        path = urlparse(self.path).path
        b = self.body()

        if path == '/api/register':
            name = b.get('name','').strip()
            email = b.get('email','').strip().lower()
            pwd = b.get('pwd','')
            if not name or '@' not in email or len(pwd) < 6:
                return self.json({'error':'Ugyldige data'},400)
            with db() as c:
                if c.execute("SELECT 1 FROM users WHERE email=?",(email,)).fetchone():
                    return self.json({'error':'Email er allerede i brug'},400)
                uid = secrets.token_hex(8)
                c.execute("INSERT INTO users VALUES (?,?,?,?,0)",(uid,name,email,hash_pwd(pwd)))
                c.commit()
            token = secrets.token_hex(32); sessions[token] = uid
            self.send_response(200); self.send_header('Content-Type','application/json')
            self.set_cookie(token); self.end_headers()
            self.wfile.write(json.dumps({'id':uid,'name':name,'email':email,'isAdmin':False}).encode())

        elif path == '/api/login':
            email = b.get('email','').strip().lower()
            pwd = b.get('pwd','')
            with db() as c:
                u = c.execute("SELECT * FROM users WHERE email=?",(email,)).fetchone()
            if not u or u['pwd_hash'] != hash_pwd(pwd):
                return self.json({'error':'Forkert email eller adgangskode'},401)
            token = secrets.token_hex(32); sessions[token] = u['id']
            self.send_response(200); self.send_header('Content-Type','application/json')
            self.set_cookie(token); self.end_headers()
            self.wfile.write(json.dumps(self.user_dict(u)).encode())

        elif path == '/api/logout':
            for part in self.headers.get('Cookie','').split(';'):
                k,_,v = part.strip().partition('=')
                if k == 'session': sessions.pop(v,None)
            self.send_response(200); self.send_header('Content-Type','application/json')
            self.clr_cookie(); self.end_headers(); self.wfile.write(b'{"ok":true}')

        elif path == '/api/bookings':
            u = session_user(self)
            if not u: return self.json({'error':'Ikke logget ind'},401)
            tbl  = b.get('table')
            bdate = b.get('date','')
            slot  = b.get('slot','')
            try:
                bd = datetime.strptime(bdate,'%Y-%m-%d').date()
            except:
                return self.json({'error':'Ugyldig dato'},400)
            if bd < date.today(): return self.json({'error':'Dato er i fortiden'},400)
            if bd > date.today()+timedelta(14): return self.json({'error':'Max 14 dage frem'},400)

            # Week quota check
            mon = bd - timedelta(bd.weekday()); sun = mon + timedelta(6)
            now_dt = datetime.now().strftime('%Y-%m-%dT%H:%M')
            with db() as c:
                cnt = c.execute(
                    "SELECT COUNT(*) FROM bookings WHERE user_id=? AND date>=? AND date<=? AND date||'T'||slot>=?",
                    (u['id'], str(mon), str(sun), now_dt)).fetchone()[0]
                if cnt >= 2: return self.json({'error':'Du har allerede 2 bookinger denne uge'},400)
                try:
                    bid = secrets.token_hex(8)
                    c.execute("INSERT INTO bookings VALUES (?,?,?,?,?,?)",
                        (bid, u['id'], u['name'], tbl, bdate, slot))
                    c.commit()
                    row = c.execute("SELECT * FROM bookings WHERE id=?",(bid,)).fetchone()
                    self.json(dict(row))
                except sqlite3.IntegrityError:
                    self.json({'error':'Tidslot er allerede optaget'},409)
        else:
            self.json({'error':'Ikke fundet'},404)

    # ── DELETE ────────────────────────────────────────────────────────────────
    def do_DELETE(self):
        path = urlparse(self.path).path
        u = session_user(self)

        m = re.match(r'^/api/bookings/(\w+)$', path)
        if m:
            bid = m.group(1)
            with db() as c:
                row = c.execute("SELECT * FROM bookings WHERE id=?",(bid,)).fetchone()
                if not row: return self.json({'error':'Ikke fundet'},404)
                if not u or (u['id'] != row['user_id'] and not u['is_admin']):
                    return self.json({'error':'Ingen adgang'},403)
                c.execute("DELETE FROM bookings WHERE id=?",(bid,)); c.commit()
            return self.json({'ok':True})

        m = re.match(r'^/api/admin/users/(\w+)$', path)
        if m:
            if not u or not u['is_admin']: return self.json({'error':'Ingen adgang'},403)
            uid = m.group(1)
            with db() as c:
                c.execute("DELETE FROM bookings WHERE user_id=?",(uid,))
                c.execute("DELETE FROM users WHERE id=?",(uid,)); c.commit()
            return self.json({'ok':True})

        self.json({'error':'Ikke fundet'},404)

if __name__ == '__main__':
    init_db()
    PORT = int(os.environ.get('PORT', 8080))
    with http.server.ThreadingHTTPServer(('0.0.0.0', PORT), H) as srv:
        print(f'🏓 Hvidovre Bordtennis Klub kører på port {PORT}')
        srv.serve_forever()
