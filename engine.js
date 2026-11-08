'use strict';
// Spiellogik "OSI-Frames" – ohne Abhängigkeiten, damit sie testbar bleibt.
const BC = 'FF:FF:FF:FF:FF:FF';
const LAYER = ['Bitübertragung', 'Sicherung', 'Vermittlung', 'Transport', 'Sitzung', 'Darstellung', 'Anwendung'];
const LBL = { 'l2.src': 'Quell-MAC', 'l2.dst': 'Ziel-MAC', 'l2.type': 'Typ', 'l3.src': 'Quell-IP', 'l3.dst': 'Ziel-IP', 'l3.ttl': 'TTL', 'l3.proto': 'Protokoll', 'l3.info': 'ARP', 'l3.mac': 'MAC-Antwort', 'l4.src': 'Quell-Port', 'l4.dst': 'Ziel-Port', 'l4.flags': 'Flags', 'l7': 'Nutzdaten' };
const TXD = {
  ARP: { srv: 'R1', n: 2, name: 'ARP – MAC des Gateways erfragen' },
  DNS: { srv: 'DNS', n: 2, name: 'DNS – IP von www.beispiel.de erfragen' },
  TCP: { srv: 'WEB', n: 3, name: 'TCP-Handshake mit dem Webserver' },
  HTTP: { srv: 'WEB', n: 2, name: 'HTTP – Webseite abrufen' }
};
const TXS = { 1: ['DNS', 'HTTP'], 2: ['DNS', 'HTTP'], 3: ['ARP', 'DNS', 'TCP', 'HTTP'] };
const L7OPT = ['www.beispiel.de = 172.16.0.80', 'www.beispiel.de = 172.16.0.53', 'www.beispiel.de = 192.168.1.1', 'NXDOMAIN (Name unbekannt)'];
const pad = n => String(n).padStart(2, '0');
const get = (o, p) => p.split('.').reduce((a, k) => (a == null ? a : a[k]), o);
const clone = o => JSON.parse(JSON.stringify(o));
const hm = d => d.mac || d.lan.mac, hi = d => d.ip || d.lan.ip;
const lim = d => (d.t === 'switch' ? 2 : d.t === 'router' ? 3 : 7);
const isClientId = id => /^C\d+$/.test(id);

function mkClient(n) {
  return { id: 'C' + n, t: 'client', n: 'Client ' + n, mac: 'CC:00:00:00:00:' + pad(n), ip: '192.168.1.' + (10 + n), port: 40000 + n, gw: 'R1', inbox: [], todo: null, ti: 0, arp: true, webIp: null, done: false };
}
function mkDevs() {
  const d = {
    C1: mkClient(1),
    SW1: { id: 'SW1', t: 'switch', n: 'Switch 1' },
    R1: { id: 'R1', t: 'router', n: 'Router 1', lan: { mac: 'AA:01:00:00:00:01', ip: '192.168.1.1' }, wan: { mac: 'AA:01:00:00:00:02', ip: '10.0.0.1' } },
    R2: { id: 'R2', t: 'router', n: 'Router 2', wan: { mac: 'AA:02:00:00:00:01', ip: '10.0.0.2' }, lan: { mac: 'AA:02:00:00:00:02', ip: '172.16.0.1' } },
    SW2: { id: 'SW2', t: 'switch', n: 'Switch 2' },
    DNS: { id: 'DNS', t: 'host', n: 'DNS-Server', mac: 'BB:00:00:00:00:53', ip: '172.16.0.53', port: 53, gw: 'R2' },
    WEB: { id: 'WEB', t: 'host', n: 'Webserver', mac: 'BB:00:00:00:00:80', ip: '172.16.0.80', port: 80, gw: 'R2' }
  };
  for (const x of Object.values(d)) x.inbox = x.inbox || [];
  return d;
}

// ---------- Topologie ----------
function nbs(r, id) {
  const cl = Object.values(r.devs).filter(x => x.t === 'client').map(x => x.id);
  return ({ SW1: [...cl, 'R1'], R1: ['SW1', 'R2'], R2: ['R1', 'SW2'], SW2: ['R2', 'DNS', 'WEB'], DNS: ['SW2'], WEB: ['SW2'] })[id] || ['SW1'];
}
function macOfIp(r, ip) {
  const x = Object.values(r.devs).find(x => (x.t === 'client' || x.t === 'host') && x.ip === ip);
  return x ? x.mac : null;
}
function route(r, id, ip) {
  const R1 = r.devs.R1, R2 = r.devs.R2;
  if (id === 'R1') return ip.startsWith('192.168.1.') ? { src: R1.lan.mac, dst: macOfIp(r, ip), nb: 'SW1' } : { src: R1.wan.mac, dst: R2.wan.mac, nb: 'R2' };
  return ip.startsWith('172.16.0.') ? { src: R2.lan.mac, dst: macOfIp(r, ip), nb: 'SW2' } : { src: R2.wan.mac, dst: R1.wan.mac, nb: 'R1' };
}

// ---------- Frames ----------
function mk(r, tx, leg, c) {
  const s = r.devs[TXD[tx].srv], fromC = leg % 2 === 0;
  const f = { tx, leg, owner: c.id, opened: 1, from: null, l4: null, l7: null };
  if (tx === 'ARP') {
    f.l2 = { src: fromC ? c.mac : hm(s), dst: fromC ? BC : c.mac, type: 'ARP' };
    f.l3 = fromC ? { info: 'Wer hat ' + hi(s) + '? (Absender ' + c.ip + ')' } : { info: hi(s) + ' ist bei:', mac: hm(s) };
    return f;
  }
  const a = fromC ? c : s, b = fromC ? s : c, udp = tx === 'DNS';
  f.l2 = { src: a.mac, dst: r.devs[a.gw].lan.mac, type: 'IPv4' };
  f.l3 = { src: a.ip, dst: b.ip, ttl: 64, proto: udp ? 'UDP' : 'TCP' };
  f.l4 = { src: fromC ? c.port : s.port, dst: fromC ? s.port : c.port };
  if (!udp) f.l4.flags = tx === 'TCP' ? ['SYN', 'SYN, ACK', 'ACK'][leg] : 'PSH, ACK';
  if (tx === 'DNS') f.l7 = fromC ? 'Frage: A-Record von www.beispiel.de' : 'www.beispiel.de = ' + r.devs.WEB.ip;
  if (tx === 'HTTP') f.l7 = fromC ? 'GET /index.html HTTP/1.1' : '200 OK – Willkommen auf www.beispiel.de';
  return f;
}
function ekeys(f) {
  if (f.tx === 'ARP') return f.leg === 0 ? ['l2.dst'] : ['l2.dst', 'l3.mac'];
  const k = ['l2.dst', 'l3.dst', 'l4.dst'];
  if (f.tx === 'DNS' && f.leg === 1) k.push('l7');
  return k;
}

// ---------- Erwartetes (richtiges) Verhalten ----------
function work(d) { return d.inbox.length ? { mode: 'recv', f: d.inbox[0] } : d.todo ? { mode: 'create' } : null; }
function expRecv(r, d, f) {
  if (d.t === 'switch') {
    if (f.l2.dst === BC) return { next: 'FLOOD', frame: f, keys: [] };
    const nb = nbs(r, d.id).find(n => hm(r.devs[n]) === f.l2.dst);
    return { next: nb || 'DROP', frame: f, keys: [] };
  }
  if (d.t === 'router' && f.l2.type !== 'ARP') {
    const rt = route(r, d.id, f.l3.dst), nf = clone(f);
    nf.l2 = { src: rt.src, dst: rt.dst, type: 'IPv4' }; nf.l3.ttl = f.l3.ttl - 1;
    return { next: rt.nb, frame: nf, keys: ['l2.src', 'l2.dst', 'l3.ttl'] };
  }
  if (f.leg === TXD[f.tx].n - 1) return { next: 'PROCESS', frame: null, keys: [] };
  const nf = mk(r, f.tx, f.leg + 1, r.devs[f.owner]);
  return { next: d.t === 'client' || d.id === 'R1' ? 'SW1' : 'SW2', frame: nf, keys: ekeys(nf) };
}
function expOf(r, d) {
  const w = work(d); if (!w) return null;
  let e;
  if (w.mode === 'create') { const f = mk(r, d.todo.tx, d.todo.leg, d); e = { next: 'SW1', frame: f, keys: ekeys(f) }; }
  else e = expRecv(r, d, w.f);
  if (r.level < 2) e.keys = [];
  return { w, e };
}

// ---------- Aktionen ----------
function drop(r, d, f, why) {
  r.log.push('✘ ' + d.n + ': ' + why + ' – Frame (' + f.tx + ') geht verloren.');
  r.errors.push({ dev: d.n, tx: f.tx, why });
  for (const x of Object.values(r.devs)) x.inbox = x.inbox.filter(y => !(y.owner === f.owner && y.tx === f.tx));
  const o = r.devs[f.owner]; o.todo = { tx: f.tx, leg: 0 };
  r.log.push('⏱ ' + o.n + ': Zeitüberschreitung – ' + TXD[f.tx].name + ' muss neu gesendet werden.');
}
function deliver(r, to, f, from) {
  const t = r.devs[to];
  if (t.t === 'client' && t.id !== f.owner) return;           // fremder Client ignoriert Broadcast
  const nf = clone(f); nf.opened = 1; nf.from = from; t.inbox.push(nf);
}
function advance(r, c) {
  c.ti++;
  const list = TXS[r.level];
  if (c.ti >= list.length) { c.done = true; c.todo = null; r.log.push('🏁 ' + c.n + ' hat alle Aufgaben geschafft!'); }
  else c.todo = { tx: list[c.ti], leg: 0 };
  if (Object.values(r.devs).filter(x => x.t === 'client').every(x => x.done)) { r.phase = 'done'; r.log.push('🎉 Alle Clients sind fertig!'); }
}
function final(r, f) {
  const c = r.devs[f.owner];
  if (f.tx === 'ARP') c.arp = true;
  if (f.tx === 'DNS') c.webIp = String(f.l7).split('= ')[1];
  r.log.push('✔ ' + TXD[f.tx].name + ' für ' + c.n + ' abgeschlossen.');
  advance(r, c);
}
function send(r, d, a) {
  const x = expOf(r, d); if (!x) return;
  const { w, e } = x, f = w.mode === 'recv' ? w.f : e.frame;
  if (w.mode === 'recv' && f.opened < lim(d)) return drop(r, d, f, 'hat den Frame nur bis Schicht ' + f.opened + ' geöffnet und kann ihn nicht verarbeiten');
  for (const k of e.keys) if (String(get(e.frame, k)) !== String((a.fields || {})[k])) return drop(r, d, f, 'Feld „' + LBL[k] + '“ ist falsch');
  if (a.next !== e.next) {
    const nm = a.next === 'DROP' ? 'hat den Frame verworfen' : a.next === 'FLOOD' ? 'hat unnötig geflutet' : a.next === 'PROCESS' ? 'hat den Frame selbst verarbeitet statt weiterzuleiten' : 'hat an das falsche Gerät gesendet (' + (r.devs[a.next] ? r.devs[a.next].n : '?') + ')';
    return drop(r, d, f, nm);
  }
  if (w.mode === 'recv') d.inbox.shift(); else d.todo = null;
  if (e.next === 'PROCESS') return final(r, f);
  r.log.push('✔ ' + d.n + ': ' + f.tx + ' (Frame ' + (f.leg + 1) + ') → ' + (e.next === 'FLOOD' ? 'alle anderen Ports' : r.devs[e.next].n));
  if (e.next === 'FLOOD') { for (const n of nbs(r, d.id)) if (n !== f.from) deliver(r, n, e.frame, d.id); }
  else deliver(r, e.next, e.frame, d.id);
}

// ---------- Räume & Spieler ----------
const createRoom = code => ({ code, phase: 'lobby', level: 1, devs: mkDevs(), players: [], log: [], errors: [] });
const isHost = (r, id) => !!r.players[0] && r.players[0].id === id;
function relDev(r, p) { if (p.dev && p.dev !== 'C1' && isClientId(p.dev)) delete r.devs[p.dev]; p.dev = null; }
function addPlayer(r, id, name) {
  if (r.players.length >= 24 || r.players.some(p => p.name === name)) return false;
  r.players.push({ id, name, dev: null }); return true;
}
function removePlayer(r, id) {
  const p = r.players.find(x => x.id === id); if (!p) return;
  if (r.phase === 'lobby') relDev(r, p);
  r.players = r.players.filter(x => x !== p);
}
function claim(r, id, dev) {
  const p = r.players.find(x => x.id === id); if (!p || r.phase !== 'lobby') return;
  if (dev === 'NEW') {
    let n = 2; while (r.devs['C' + n] && n <= 14) n++;
    if (n > 14) return; dev = 'C' + n; relDev(r, p); r.devs[dev] = mkClient(n); p.dev = dev; return;
  }
  if (!r.devs[dev] || r.players.some(x => x.dev === dev && x !== p)) return;
  relDev(r, p); p.dev = dev;
}
function release(r, id) { const p = r.players.find(x => x.id === id); if (p && r.phase === 'lobby') relDev(r, p); }
function setLevel(r, id, n) { if (isHost(r, id) && r.phase === 'lobby' && TXS[n]) r.level = n; }
function start(r, id) {
  if (!isHost(r, id) || r.phase !== 'lobby') return;
  for (const k of Object.keys(r.devs)) if (isClientId(k) && k !== 'C1' && !r.players.some(p => p.dev === k)) delete r.devs[k];
  const list = TXS[r.level];
  for (const d of Object.values(r.devs)) {
    d.inbox = []; d.todo = null;
    if (d.t === 'client') Object.assign(d, { ti: 0, done: false, webIp: null, arp: r.level < 3, todo: { tx: list[0], leg: 0 } });
  }
  r.log = ['Level ' + r.level + ' gestartet. Besetzte Rollen spielt ihr selbst, freie übernimmt der Computer.']; r.errors = []; r.phase = 'play';
}
function again(r, id) { if (isHost(r, id) && r.phase === 'done') { r.phase = 'lobby'; r.log = []; } }
function open(r, id) {
  const p = r.players.find(x => x.id === id), d = p && r.devs[p.dev];
  if (r.phase !== 'play' || !d || !d.inbox.length) return;
  const f = d.inbox[0];
  if (f.opened >= 7) return;
  if (f.opened >= lim(d)) return drop(r, d, f, 'ist ein Gerät der Schicht ' + lim(d) + ' und kann Schicht ' + (f.opened + 1) + ' nicht öffnen');
  f.opened++;
}
function act(r, id, a) {
  const p = r.players.find(x => x.id === id), d = p && r.devs[p.dev];
  if (r.phase !== 'play' || !d || !a) return;
  send(r, d, { next: String(a.next), fields: a.fields && typeof a.fields === 'object' ? a.fields : {} });
}
function tick(r) {   // freie Rollen werden vom Computer korrekt gespielt
  if (r.phase !== 'play') return false;
  let ch = false;
  for (const d of Object.values(r.devs)) {
    if (r.players.some(p => p.dev === d.id)) continue;
    const x = expOf(r, d); if (!x) continue;
    if (x.w.mode === 'recv') x.w.f.opened = lim(d);
    send(r, d, { next: x.e.next, fields: Object.fromEntries(x.e.keys.map(k => [k, get(x.e.frame, k)])) });
    ch = true;
  }
  return ch;
}

// ---------- Sicht für einen Spieler ----------
function info(r, d) {
  const L = [], R1 = r.devs.R1, R2 = r.devs.R2;
  if (d.t === 'client') L.push('Meine MAC: ' + d.mac, 'Meine IP: ' + d.ip + ' (Netz 192.168.1.0/24)', 'Mein Quell-Port: ' + d.port, 'Gateway: 192.168.1.1 → MAC ' + (d.arp ? R1.lan.mac : 'unbekannt (erst per ARP erfragen)'), 'DNS-Server: ' + r.devs.DNS.ip, 'www.beispiel.de → ' + (d.webIp || 'noch unbekannt'));
  else if (d.t === 'switch') { L.push('MAC-Tabelle:'); nbs(r, d.id).forEach((n, i) => L.push(hm(r.devs[n]) + ' → Port ' + (i + 1) + ' (' + r.devs[n].n + ')')); L.push('Broadcast ' + BC + ' → alle Ports'); }
  else if (d.t === 'router') {
    L.push('Schnittstelle LAN: ' + d.lan.mac + ' / ' + d.lan.ip, 'Schnittstelle WAN: ' + d.wan.mac + ' / ' + d.wan.ip);
    if (d.id === 'R1') { L.push('Route 192.168.1.0/24 → direkt (LAN)', 'Route 172.16.0.0/24 → via 10.0.0.2 (WAN)', 'ARP: 10.0.0.2 = ' + R2.wan.mac); Object.values(r.devs).filter(x => x.t === 'client').forEach(c => L.push('ARP: ' + c.ip + ' = ' + c.mac)); }
    else L.push('Route 172.16.0.0/24 → direkt (LAN)', 'Route 192.168.1.0/24 → via 10.0.0.1 (WAN)', 'ARP: 10.0.0.1 = ' + R1.wan.mac, 'ARP: 172.16.0.53 = ' + r.devs.DNS.mac, 'ARP: 172.16.0.80 = ' + r.devs.WEB.mac);
    L.push('Beim Weiterleiten: TTL − 1, neue Quell- und Ziel-MAC');
  } else L.push('Meine MAC: ' + d.mac, 'Meine IP: ' + d.ip, 'Dienst auf Port ' + d.port, 'Gateway: 172.16.0.1 → MAC ' + R2.lan.mac);
  return L;
}
function vf(f, hide, all) {
  const op = all ? 7 : f.opened, out = [];
  const rows = (p, o) => Object.entries(o).map(([k, v]) => [p + '.' + k, LBL[p + '.' + k] || k, v]);
  for (let n = 1; n <= 7; n++) {
    const o = n <= op; let rw = [];
    if (o) {
      if (n === 1) rw = [['', 'Signal', 'Bits auf dem Kabel']];
      else if (n === 2) rw = rows('l2', f.l2);
      else if (n === 3) rw = f.l3 ? rows('l3', f.l3) : [['', '', 'kein Header']];
      else if (n === 4) rw = f.l4 ? rows('l4', f.l4) : [['', '', 'kein Header']];
      else if (n === 7) rw = [['l7', 'Nutzdaten', f.l7 || 'keine Nutzdaten']];
      else rw = [['', '', '(in diesem Spiel ohne eigene Daten)']];
      rw = rw.map(([k, l, v]) => [k, l, hide.includes(k) ? '?' : v]);
    }
    out.push({ n, name: LAYER[n - 1], open: o, rows: rw });
  }
  return { tx: f.tx, leg: f.leg, opened: f.opened, layers: out };
}
function dview(r, d) {
  const o = { id: d.id, n: d.n, t: d.t, info: info(r, d), queue: d.inbox.length + (d.todo ? 1 : 0), lim: lim(d) };
  const x = expOf(r, d); if (!x) return o;
  o.mode = x.w.mode; o.keys = x.e.keys;
  if (x.w.mode === 'recv') { o.frame = vf(x.w.f, [], false); o.task = TXD[x.w.f.tx].name + ' – Frame ' + (x.w.f.leg + 1) + '/' + TXD[x.w.f.tx].n; }
  else { o.frame = vf(x.e.frame, x.e.keys, true); o.task = TXD[d.todo.tx].name + ' – Frame ' + (d.todo.leg + 1) + '/' + TXD[d.todo.tx].n; }
  o.opts = nbs(r, d.id).map(n => ({ id: n, label: '→ ' + r.devs[n].n }));
  if (x.w.mode === 'recv') {
    if (d.t === 'switch') o.opts.push({ id: 'FLOOD', label: '📢 Flooden (alle Ports außer Eingang)' });
    else o.opts.push({ id: 'PROCESS', label: '✅ Selbst verarbeiten (Anwendung)' });
    o.opts.push({ id: 'DROP', label: '🗑 Verwerfen' });
  }
  return o;
}
function lists(r) {
  const macs = new Set([BC]), ips = new Set(), ports = new Set([53, 80]);
  for (const d of Object.values(r.devs)) {
    if (d.mac) macs.add(d.mac); if (d.ip) ips.add(d.ip); if (d.port) ports.add(d.port);
    if (d.lan) { macs.add(d.lan.mac); ips.add(d.lan.ip); } if (d.wan) { macs.add(d.wan.mac); ips.add(d.wan.ip); }
  }
  return { macs: [...macs].sort(), ips: [...ips].sort(), ports: [...ports].sort((a, b) => a - b), l7: L7OPT };
}
function view(r, id) {
  const me = r.players.find(p => p.id === id);
  const ids = ['C1', 'SW1', 'R1', 'R2', 'SW2', 'DNS', 'WEB', ...Object.keys(r.devs).filter(k => isClientId(k) && k !== 'C1')];
  const cl = Object.values(r.devs).filter(x => x.t === 'client');
  const o = {
    code: r.code, phase: r.phase, level: r.level, me: me && me.name, host: r.players[0] && r.players[0].name, isHost: isHost(r, id),
    roster: ids.map(k => { const d = r.devs[k], p = r.players.find(x => x.dev === k); return { id: k, n: d.n, t: d.t, who: p ? p.name : null, work: d.inbox.length + (d.todo ? 1 : 0) }; }),
    log: r.log.slice(-14), errCount: r.errors.length, progress: { done: cl.reduce((a, c) => a + c.ti, 0), total: cl.length * TXS[r.level].length }, lists: lists(r)
  };
  if (me && me.dev && r.phase === 'play') o.dev = dview(r, r.devs[me.dev]);
  if (r.phase === 'done') o.errors = r.errors.slice(-40);
  return o;
}

module.exports = { createRoom, addPlayer, removePlayer, claim, release, setLevel, start, again, open, act, tick, view, expOf, lim, get, TXS };
