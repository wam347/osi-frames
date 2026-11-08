# OSI-Frames (Prototyp)
Kooperatives Multiplayer-Lernspiel zum OSI-Modell. Jeder Schüler ist ein Gerät
(Client, Switch, Router, DNS-Server, Webserver) und entscheidet, wie weit er einen Frame öffnet,
welche Felder er setzt und wohin er ihn sendet. Freie Rollen spielt der Computer.

Pflichtgeräte: Client 1, Switch 1, Router 1, Router 2, Switch 2, DNS-Server, Webserver (7).
Weitere Schüler werden zusätzliche Clients (bis 14).

Start Docker:  docker compose up -d --build   → http://<NAS-IP>:3020
Lokal:         npm install && npm start       → http://localhost:3000
Test (Logik):  node test.js

Level 1: Schichten öffnen + Ziel wählen.
Level 2: zusätzlich Felder ausfüllen.
Level 3: zusätzlich ARP und TCP-Handshake.
