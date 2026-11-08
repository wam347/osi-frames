const E = require('./engine');
let fail = 0; const ok = (c, m) => { if (!c) { fail++; console.log('FEHLER:', m); } };
// 1) Nur Bots, alle Level
for (const lv of [1, 2, 3]) {
  const r = E.createRoom('T'); E.addPlayer(r, 'a', 'Host'); E.setLevel(r, 'a', lv); E.start(r, 'a');
  let n = 0; while (r.phase === 'play' && n < 3000) { E.tick(r); n++; E.view(r, 'a'); }
  ok(r.phase === 'done', 'Level ' + lv + ' nicht fertig'); ok(r.errors.length === 0, 'Bots machen Fehler: ' + JSON.stringify(r.errors[0]));
  console.log('Level', lv, r.phase, 'Ticks:', n, 'Fehler:', r.errors.length);
}
// 2) Mensch als Switch 1 + zusätzlicher Client
const r = E.createRoom('T2'); E.addPlayer(r, 'h', 'Host'); E.addPlayer(r, 's', 'Schueler'); E.addPlayer(r, 'c', 'Extra');
E.claim(r, 's', 'SW1'); E.claim(r, 'c', 'NEW'); E.setLevel(r, 'h', 3); E.start(r, 'h');
ok(Object.keys(r.devs).includes('C2'), 'Extra-Client fehlt');
let n = 0; const sw = r.devs.SW1;
while (!sw.inbox.length && n++ < 200) E.tick(r);
ok(sw.inbox.length > 0, 'Switch bekam keinen Frame');
let v = E.view(r, 's'); ok(v.dev.mode === 'recv' && v.dev.frame.layers[2].open === false, 'Schicht 3 sollte verschlossen sein');
E.open(r, 's'); v = E.view(r, 's'); ok(v.dev.frame.layers[1].open, 'Schicht 2 offen');
E.act(r, 's', { next: 'R1', fields: {} });            // ARP-Broadcast gezielt statt geflutet → falsch
ok(r.errors.length === 1, 'Falsche Entscheidung nicht bestraft');
// Schicht 3 am Switch öffnen = Fehler
n = 0; while (!sw.inbox.length && n++ < 300) E.tick(r);
E.open(r, 's'); E.open(r, 's'); ok(r.errors.length === 2, 'Zu tiefes Öffnen nicht bestraft');
// Danach richtig spielen: der Spieler tut das Erwartete
n = 0; let guard = 0;
while (r.phase === 'play' && guard++ < 5000) {
  E.tick(r);
  for (const id of ['s', 'c']) {
    const p = r.players.find(x => x.id === id), d = r.devs[p.dev], x = E.expOf(r, d);
    if (!x) continue;
    if (x.w.mode === 'recv') x.w.f.opened = E.lim(d);
    E.act(r, id, { next: x.e.next, fields: Object.fromEntries(x.e.keys.map(k => [k, E.get(x.e.frame, k)])) });
  }
}
ok(r.phase === 'done', 'Mensch-Runde nicht beendet'); console.log('Runde mit Menschen:', r.phase, 'Fehler gesamt:', r.errors.length);
console.log(fail ? 'TESTS FEHLGESCHLAGEN' : 'ALLE TESTS OK'); process.exit(fail ? 1 : 0);
