const express = require('express'), http = require('http'), { Server } = require('socket.io');
const E = require('./engine');
const app = express(), srv = http.createServer(app), io = new Server(srv);
app.use(express.static('public'));
const rooms = {};
const emit = r => r.players.forEach(p => io.to(p.id).emit('state', E.view(r, p.id)));

io.on('connection', s => {
  let r = null;
  const run = fn => { if (r) { fn(r); emit(r); } };
  s.on('join', ({ room, name }) => {
    room = String(room || '').trim().toUpperCase().slice(0, 8); name = String(name || '').trim().slice(0, 20);
    if (!room || !name || r) return;
    const rm = rooms[room] = rooms[room] || E.createRoom(room);
    if (!E.addPlayer(rm, s.id, name)) return s.emit('err', 'Name schon vergeben oder Raum voll');
    r = rm; emit(r);
  });
  s.on('claim', d => run(x => E.claim(x, s.id, String(d))));
  s.on('release', () => run(x => E.release(x, s.id)));
  s.on('level', n => run(x => E.setLevel(x, s.id, Number(n))));
  s.on('start', () => run(x => E.start(x, s.id)));
  s.on('again', () => run(x => E.again(x, s.id)));
  s.on('open', () => run(x => E.open(x, s.id)));
  s.on('send', a => run(x => E.act(x, s.id, a)));
  s.on('disconnect', () => {
    if (!r) return;
    E.removePlayer(r, s.id);
    if (!r.players.length) delete rooms[r.code]; else emit(r);
  });
});
setInterval(() => { for (const r of Object.values(rooms)) if (E.tick(r)) emit(r); }, 1200);
srv.listen(3000, () => console.log('OSI-Frames auf Port 3000'));
