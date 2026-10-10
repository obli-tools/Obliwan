/**
 * ObliWAN bench — the application's only page, served by gui.ts.
 *
 * Self-contained on purpose: no font, script, stylesheet or image is fetched
 * from anywhere (the server's Content-Security-Policy would refuse it anyway),
 * because the window opens on a bench whose network may be nothing but the
 * router being prepared. The favicon is an inline SVG data URI; Edge's app
 * mode uses it, with the <title>, for the window and its taskbar entry.
 *
 * Text is French and addressed to the person preparing the router, not to an
 * engineer: no family, port, transport or account in the main path. Every
 * value that came from a router or from ObliWAN is written with textContent,
 * never as HTML. The page never receives a secret back: the factory password
 * and the bench variables go to the local server, which keeps them.
 *
 * SEVERAL ROUTERS AT ONCE. The board (`#board`) shows one card per router
 * in progress, from `GET /api/cards` every second: its link (« Prise 11 »),
 * site, MAC, step, elapsed time, a colour, and the ONE next action the
 * application chose for it (gui.ts `cardState`). The steps below the board
 * are the card being typed in (`cur`): every request they send names it
 * (`x-bench-card`), a long operation started on a card goes on while another one
 * is typed in, and what it ends with is drawn when that card is shown again
 * (`views`, `onCard`). « Préparer un autre routeur » is always offered. A
 * card that starts needing the technician beeps (Web Audio, nothing
 * fetched) and makes the title blink; the application flashes the window.
 * « Préparer ce PC » explains the cabling (one link per router) and lists
 * the links this PC holds.
 *
 * No template literal and no "${" in the script below: this whole page is a
 * String.raw template.
 */
export const PAGE = String.raw`<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ObliWAN — Préparation des routeurs</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E%3Crect width='64' height='64' rx='14' fill='%232563eb'/%3E%3Cpath d='M16 42 L32 22 L48 42' stroke='white' stroke-width='7' fill='none' stroke-linecap='round' stroke-linejoin='round'/%3E%3Ccircle cx='32' cy='46' r='4' fill='white'/%3E%3C/svg%3E">
<style>
:root{--bg:#0b1220;--panel:#111a2c;--panel2:#16213a;--line:#24324f;--text:#e6edf7;--muted:#8fa0bb;--accent:#3b82f6;--accent2:#2563eb;--ok:#22c55e;--warn:#f59e0b;--bad:#ef4444;color-scheme:dark}
*{box-sizing:border-box}
html,body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 "Segoe UI",system-ui,-apple-system,sans-serif}
header{display:flex;align-items:center;gap:14px;padding:14px 28px;border-bottom:1px solid var(--line);background:#0d1526}
.logo{width:34px;height:34px;border-radius:9px;background:var(--accent2);display:grid;place-items:center}
.brand b{display:block;font-size:16px;letter-spacing:.2px}
.brand span{color:var(--muted);font-size:13px}
.chip{margin-left:auto;display:flex;align-items:center;gap:8px;padding:6px 12px;border:1px solid var(--line);border-radius:999px;color:var(--muted);font-size:13px;background:var(--panel)}
.dot{width:8px;height:8px;border-radius:50%;background:var(--muted)}
.dot.ok{background:var(--ok)}.dot.warn{background:var(--warn)}.dot.bad{background:var(--bad)}
main{max-width:860px;margin:0 auto;padding:26px 28px 40px}
.banner{max-width:860px;margin:14px auto 0;padding:10px 16px;border-radius:10px;border:1px solid #6b4f12;background:#2a2110;color:#fcd98b;font-size:14px;display:flex;gap:12px;align-items:center}
.banner.info{border-color:#1e3a6b;background:#0f1d38;color:#bcd3ff}
.card{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:24px 26px;margin-bottom:18px}
h1{font-size:22px;margin:0 0 6px}
h2{font-size:17px;margin:0 0 14px}
p{margin:6px 0}
.muted{color:var(--muted)}
.small{font-size:13px}
label{display:block;font-size:13px;color:var(--muted);margin:14px 0 6px}
input,select{width:100%;padding:11px 13px;border-radius:9px;border:1px solid var(--line);background:#0c1424;color:var(--text);font:inherit;outline:none}
input:focus,select:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(59,130,246,.25)}
.row{display:grid;grid-template-columns:1fr 1fr;gap:16px}
.row3{display:grid;grid-template-columns:2fr 1fr 1fr;gap:12px}
button{font:inherit;cursor:pointer;border-radius:9px;border:1px solid var(--line);background:var(--panel2);color:var(--text);padding:10px 18px}
button:hover{border-color:#36507d}
button.primary{background:var(--accent2);border-color:var(--accent2);color:#fff;font-weight:600}
button.primary:hover{background:var(--accent)}
button.big{padding:14px 26px;font-size:16px}
button:disabled{opacity:.5;cursor:default}
.actions{display:flex;gap:12px;margin-top:22px;align-items:center;flex-wrap:wrap}
details{margin-top:16px;border:1px solid var(--line);border-radius:10px;padding:4px 14px 12px}
summary{cursor:pointer;color:var(--muted);padding:8px 0;font-size:14px}
.steps{display:flex;gap:8px;margin-bottom:18px}
.step{flex:1;padding:9px 12px;border-radius:10px;background:var(--panel);border:1px solid var(--line);color:var(--muted);font-size:13px}
.step.on{border-color:var(--accent);color:var(--text)}
.step.done{color:var(--ok)}
.err{margin-top:16px;padding:12px 14px;border-radius:10px;border:1px solid #6b1d1d;background:#2a1212;color:#fecaca;white-space:pre-wrap}
.okbox{margin-top:16px;padding:12px 14px;border-radius:10px;border:1px solid #14532d;background:#0f2417;color:#bbf7d0}
.warnbox{margin-top:16px;padding:12px 14px;border-radius:10px;border:1px solid #6b4f12;background:#2a2110;color:#fcd98b}
.confirmbox{margin-top:16px;padding:14px 16px;border-radius:10px;border:2px solid #f97316;background:#2a1708;color:#fed7aa}
.confirmbox p{margin:0;font-weight:600}
.check{display:flex;align-items:flex-start;gap:12px;margin:12px 0 0;padding:10px 12px;border-radius:8px;border:1px solid rgba(255,255,255,.18);background:rgba(0,0,0,.22);color:inherit;font-size:15px;font-weight:600;line-height:1.4;text-align:left;cursor:pointer}
.check input{flex:0 0 auto;width:22px;height:22px;margin:0;padding:0;cursor:pointer;accent-color:#f97316}
.kv{display:grid;grid-template-columns:200px 1fr;gap:8px 18px;margin:8px 0}
.kv div:nth-child(odd){color:var(--muted)}
.kv div:nth-child(even){font-weight:600;word-break:break-all}
.code{font:600 30px/1.2 Consolas,"Cascadia Mono",monospace;letter-spacing:3px;padding:14px 18px;border-radius:12px;background:#0c1424;border:1px dashed #36507d;display:inline-block;margin:10px 0}
.spin{width:18px;height:18px;border:3px solid #2b3c5e;border-top-color:var(--accent);border-radius:50%;display:inline-block;animation:r 1s linear infinite;vertical-align:-3px;margin-right:10px}
@keyframes r{to{transform:rotate(360deg)}}
.progress{margin-top:16px;color:var(--muted)}
.list{margin-top:12px;border:1px solid var(--line);border-radius:10px;max-height:300px;overflow:auto}
.item{padding:10px 14px;border-bottom:1px solid var(--line);cursor:pointer;display:flex;gap:12px;align-items:center}
.item:last-child{border-bottom:0}
.item:hover,.item.sel{background:#15233f}
.tag{font-size:12px;padding:2px 8px;border-radius:999px;border:1px solid var(--line);color:var(--muted);margin-left:auto;white-space:nowrap}
.tag.ok{color:var(--ok);border-color:#14532d}
.big-ok{font-size:44px;color:var(--ok);line-height:1}.big-ok.warn{color:var(--warn)}
.countdown{font:700 64px/1 Consolas,"Cascadia Mono",monospace;letter-spacing:2px;margin:14px 0 6px;color:var(--warn)}
.instr{font-size:20px;font-weight:600;line-height:1.4;margin:10px 0}
.elapsed{color:var(--muted);font-size:14px;margin-top:6px}
.testbanner{margin:12px 0;padding:12px 14px;border-radius:10px;border:2px solid var(--bad);background:#3a0d0d;color:#fecaca;font-weight:700;font-size:16px}
.big-ok.bad{color:var(--bad)}
.radio{display:flex;gap:10px;align-items:center;padding:10px 12px;border:1px solid var(--line);border-radius:10px;margin-top:8px;cursor:pointer}
.radio input{width:auto}
footer{text-align:center;color:#5d6d88;font-size:12px;padding:0 0 22px}
.boardbar{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:12px;flex-wrap:wrap}
.boardbar .btns{display:flex;gap:10px}
.board{display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:12px;margin-bottom:18px}
.bcard{border-radius:12px;padding:12px 14px;border:2px solid var(--line);background:var(--panel);cursor:pointer}
.bcard.cur{outline:3px solid var(--accent);outline-offset:2px}
.bh{display:flex;justify-content:space-between;gap:8px;font-weight:700;font-size:16px}
.bmeta{color:var(--muted);font-size:12px;margin-top:2px;word-break:break-all}
.bact{font-size:16px;font-weight:700;line-height:1.35;margin-top:10px}
.bcount{font:700 30px/1 Consolas,"Cascadia Mono",monospace;color:#facc15;margin-top:8px}
.bbtn{margin-top:10px;padding:6px 12px;font-size:13px}
.tone-idle{border-color:#33415e}
.tone-wait{border-color:var(--accent);background:#0f1d38}
.tone-act{border-color:#facc15;background:#2a2608;animation:pulse 1.2s ease-in-out infinite}
.tone-hold{border-color:var(--warn);background:#2a1d08}
.tone-hold .bact{color:#fcd98b}
.tone-ok{border-color:var(--ok);background:#0f2417}
.tone-ok .bact{color:#bbf7d0}
.tone-warn{border-color:#f97316;background:#2a1708}
.tone-bad{border-color:var(--bad);background:#2a1212;animation:pulse 1.2s ease-in-out infinite}
.tone-bad .bact{color:#fecaca}
@keyframes pulse{50%{box-shadow:0 0 0 5px rgba(250,204,21,.35)}}
.curhead{margin:0 0 10px;color:var(--muted);font-size:14px}
.howto{margin:10px 0 0 0;padding-left:22px}
.howto li{margin:6px 0}
.drawing{display:block;width:100%;max-width:640px;height:auto;margin:14px auto;color:var(--text)}
[hidden]{display:none!important}
</style>
</head>
<body>
<header>
  <div class="logo"><svg width="20" height="20" viewBox="0 0 64 64"><path d="M14 44 L32 20 L50 44" stroke="white" stroke-width="8" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg></div>
  <div class="brand"><b>ObliWAN</b><span>Préparation des routeurs</span></div>
  <div class="chip"><span id="chip-dot" class="dot"></span><span id="chip-text">Démarrage…</span></div>
</header>
<div id="banner-update" class="banner" hidden><span id="update-text"></span><button id="update-go">Installer la mise à jour</button></div>
<main>

<section id="s-url" class="card" hidden>
  <h1>Adresse d'ObliWAN</h1>
  <p class="muted">Ce poste ne sait pas encore à quel serveur ObliWAN s'adresser. Saisissez l'adresse que vous a donnée votre administrateur.</p>
  <label for="url">Adresse du serveur ObliWAN</label>
  <input id="url" type="url" placeholder="https://obliwan.example.com" autocomplete="off" spellcheck="false">
  <div class="actions"><button id="url-go" class="primary">Continuer</button><button id="url-cancel" hidden>Annuler</button></div>
  <div id="url-err" class="err" hidden></div>
</section>

<section id="s-checking" class="card" hidden>
  <h1><span class="spin"></span>Connexion à ObliWAN…</h1>
  <p class="muted" id="checking-url"></p>
</section>

<section id="s-pending" class="card" hidden>
  <h1>Ce poste attend l'autorisation d'un administrateur</h1>
  <p class="muted">Rien ne peut être préparé tant qu'un administrateur d'ObliWAN n'a pas autorisé ce poste. Donnez-lui le nom du poste et le code ci-dessous ; cet écran s'actualise tout seul.</p>
  <div class="kv"><div>Nom du poste</div><div id="pending-name"></div><div>Numéro du poste</div><div id="pending-id"></div></div>
  <div class="small muted">Code de vérification</div>
  <div class="code" id="pending-code"></div>
  <p class="small muted"><span class="spin"></span>En attente de l'autorisation…</p>
  <details><summary>Pour l'administrateur</summary><p class="small muted" id="pending-text"></p></details>
  <div class="actions"><button id="pending-url" class="linkish">Changer l'adresse d'ObliWAN</button></div>
</section>

<section id="s-revoked" class="card" hidden>
  <h1>Ce poste n'est plus autorisé</h1>
  <p id="revoked-text"></p>
  <p class="muted">Aucun routeur ne peut être préparé depuis ce poste. Vous pouvez demander une nouvelle autorisation : un administrateur devra l'approuver à nouveau.</p>
  <div class="actions"><button id="revoked-renew" class="primary">Demander une nouvelle autorisation</button></div>
</section>

<section id="s-problem" class="card" hidden>
  <h1 id="problem-title">ObliWAN ne répond pas</h1>
  <p id="problem-text"></p>
  <div class="actions"><button id="problem-retry" class="primary">Réessayer</button><button id="problem-url">Changer l'adresse d'ObliWAN</button></div>
</section>

<section id="s-app" hidden>
  <div class="boardbar">
    <div><b>Routeurs sur l'établi</b> <span id="slots-line" class="small muted"></span></div>
    <div class="btns"><button id="setup-open">Préparer ce PC</button><button id="new-card" class="primary">Préparer un autre routeur</button></div>
  </div>
  <div id="slots-warn" class="warnbox" hidden></div>
  <div id="board" class="board" hidden></div>
  <div id="board-err" class="err" hidden></div>
  <details id="hist" class="card" hidden><summary><b>Préparés aujourd'hui</b> <span id="hist-count" class="small muted"></span></summary><div id="hist-list"></div></details>
  <div id="cur-head" class="curhead" hidden>Ci-dessous : <b id="cur-label"></b></div>

  <div id="p-setup" class="card" hidden>
    <h2>Préparer ce PC pour plusieurs routeurs à la fois</h2>
    <p>Tous les routeurs neufs répondent à la même adresse, 192.168.88.1. Pour en préparer plusieurs en même temps, chacun doit être sur <b>sa propre prise</b>, séparée des autres. Sinon, ne branchez qu'un routeur à la fois.</p>
    <svg class="drawing" viewBox="0 0 640 210" role="img" aria-label="Ce PC, trois prises, trois routeurs : un câble par routeur, jamais deux routeurs sur une prise">
      <rect x="8" y="55" width="120" height="100" rx="10" fill="none" stroke="currentColor" stroke-width="3"/>
      <text x="68" y="100" text-anchor="middle" font-size="17" fill="currentColor">Ce PC</text>
      <text x="68" y="122" text-anchor="middle" font-size="11" fill="currentColor" opacity=".7">sans passerelle</text>
      <line x1="128" y1="35" x2="168" y2="35" stroke="currentColor" stroke-width="2"/>
      <line x1="128" y1="105" x2="168" y2="105" stroke="currentColor" stroke-width="2"/>
      <line x1="128" y1="175" x2="168" y2="175" stroke="currentColor" stroke-width="2"/>
      <rect x="168" y="15" width="130" height="40" rx="7" fill="none" stroke="#3b82f6" stroke-width="2.5"/>
      <rect x="168" y="85" width="130" height="40" rx="7" fill="none" stroke="#3b82f6" stroke-width="2.5"/>
      <rect x="168" y="155" width="130" height="40" rx="7" fill="none" stroke="#3b82f6" stroke-width="2.5"/>
      <text x="233" y="33" text-anchor="middle" font-size="14" font-weight="700" fill="currentColor">Prise 11</text>
      <text x="233" y="49" text-anchor="middle" font-size="11" fill="currentColor" opacity=".75">192.168.88.11</text>
      <text x="233" y="103" text-anchor="middle" font-size="14" font-weight="700" fill="currentColor">Prise 12</text>
      <text x="233" y="119" text-anchor="middle" font-size="11" fill="currentColor" opacity=".75">192.168.88.12</text>
      <text x="233" y="173" text-anchor="middle" font-size="14" font-weight="700" fill="currentColor">Prise 13</text>
      <text x="233" y="189" text-anchor="middle" font-size="11" fill="currentColor" opacity=".75">192.168.88.13</text>
      <line x1="298" y1="35" x2="440" y2="35" stroke="#22c55e" stroke-width="3"/>
      <line x1="298" y1="105" x2="440" y2="105" stroke="#22c55e" stroke-width="3"/>
      <line x1="298" y1="175" x2="440" y2="175" stroke="#22c55e" stroke-width="3"/>
      <text x="369" y="28" text-anchor="middle" font-size="11" fill="currentColor" opacity=".75">un câble</text>
      <rect x="440" y="15" width="190" height="40" rx="7" fill="none" stroke="currentColor" stroke-width="2.5"/>
      <rect x="440" y="85" width="190" height="40" rx="7" fill="none" stroke="currentColor" stroke-width="2.5"/>
      <rect x="440" y="155" width="190" height="40" rx="7" fill="none" stroke="currentColor" stroke-width="2.5"/>
      <text x="535" y="33" text-anchor="middle" font-size="13" font-weight="700" fill="currentColor">Routeur A</text>
      <text x="535" y="49" text-anchor="middle" font-size="11" fill="currentColor" opacity=".75">ether3</text>
      <text x="535" y="103" text-anchor="middle" font-size="13" font-weight="700" fill="currentColor">Routeur B</text>
      <text x="535" y="119" text-anchor="middle" font-size="11" fill="currentColor" opacity=".75">ether3</text>
      <text x="535" y="173" text-anchor="middle" font-size="13" font-weight="700" fill="currentColor">Routeur C</text>
      <text x="535" y="189" text-anchor="middle" font-size="11" fill="currentColor" opacity=".75">ether3</text>
    </svg>
    <ol class="howto">
      <li><b>Une prise par routeur</b> : un adaptateur USB-Ethernet par routeur, ou un switch administrable avec un VLAN différent sur chaque port. Jamais un switch ordinaire : les routeurs s'y mélangeraient.</li>
      <li>Sur chaque prise, donnez à ce PC une <b>adresse fixe différente</b> : 192.168.88.11, puis .12, .13… (masque 255.255.255.0, sans passerelle). Jamais 192.168.88.1, jamais en DHCP.</li>
      <li>Collez sur chaque adaptateur (ou port) une étiquette avec le dernier nombre de son adresse : 11, 12, 13… C'est le nom de la prise à l'écran.</li>
      <li>Branchez chaque routeur par son port <b>ether3</b> (jamais ether1), et son <b>ether1</b> sur une prise qui donne accès à Internet : il en a besoin pour se mettre à jour. Vous n'avez jamais à dire sur quelle prise du poste il est : ObliWAN le trouve.</li>
    </ol>
    <label>Prises détectées sur ce PC</label>
    <p class="small muted">Si une prise manque, branchez-y un routeur allumé, attendez quelques secondes, puis cliquez sur « Actualiser » : Windows peut ne pas montrer une carte réseau dont le câble ne mène nulle part.</p>
    <div id="setup-list" class="list"></div>
    <div id="setup-refused" class="err" hidden></div>
    <div class="actions"><button id="setup-refresh">Actualiser</button><button id="setup-done" class="primary big">C'est prêt</button></div>
  </div>

  <div class="steps" id="steps-bar"><div class="step" id="st-router">1. Routeur</div><div class="step" id="st-site">2. Client et site</div><div class="step" id="st-summary">3. Vérification</div><div class="step" id="st-run">4. Préparation</div></div>

  <div id="p-router" class="card">
    <h2>Préparer un routeur</h2>
    <p class="muted">Branchez le câble de ce poste sur un port du routeur autre qu'ether1 — <b>ether3</b> de préférence, puis recopiez l'adresse MAC et le mot de passe imprimés sur son étiquette : la MAC de l'étiquette (celle d'ether1) suffit, quel que soit le port utilisé.</p>
    <div class="row">
      <div><label for="mac">Adresse MAC de l'étiquette (ether1)</label><input id="mac" placeholder="48:A9:8A:12:34:56" autocomplete="off" spellcheck="false"></div>
      <div><label for="pw">Mot de passe d'usine</label><input id="pw" type="password" autocomplete="off" placeholder="laisser vide s'il n'y en a pas"></div>
    </div>
    <details id="adv"><summary>Options avancées</summary>
      <div class="row3">
        <div><label for="host">Adresse du routeur sur l'établi</label><input id="host" value="192.168.88.1" spellcheck="false"></div>
        <div><label for="user">Compte</label><input id="user" value="admin" spellcheck="false"></div>
        <div><label for="port">Port</label><input id="port" value="8728" inputmode="numeric"></div>
      </div>
    </details>
    <div class="actions"><button id="find" class="primary big">Rechercher le routeur</button></div>
    <div id="find-progress" class="progress" hidden><span class="spin"></span><span></span></div>
    <div id="find-err" class="err" hidden></div>
    <div id="resume-note" class="warnbox" hidden></div>
    <div id="found" hidden>
      <div class="okbox" id="found-ok">Routeur trouvé et reconnu : son adresse MAC correspond à l'étiquette.</div>
      <div class="kv" id="found-kv"></div>
      <div class="actions" id="found-next"><button id="to-site" class="primary big">Continuer</button><button id="other-router">Ce n'est pas ce routeur</button></div>
    </div>
  </div>

  <div id="p-site" class="card" hidden>
    <h2>Pour quel client et quel site ?</h2>
    <label for="tenant">Client</label>
    <select id="tenant"><option value="">Chargement…</option></select>
    <label for="search">Site (code ou nom)</label>
    <input id="search" placeholder="Rechercher un site…" autocomplete="off" spellcheck="false">
    <div id="sites" class="list" hidden></div>
    <div id="site-err" class="err" hidden></div>
    <div id="plan-progress" class="progress" hidden><span class="spin"></span><span>ObliWAN prépare le plan…</span></div>
    <div id="upgrade" class="warnbox" hidden>
      <p id="upgrade-text"></p>
      <div class="actions"><button id="upgrade-go" class="primary big">Mettre à jour RouterOS puis continuer</button></div>
      <div id="upgrade-progress" class="progress" hidden><span class="spin"></span><span id="upgrade-label"></span><div class="elapsed" id="upgrade-elapsed"></div></div>
    </div>
    <div id="upgrade-done" class="okbox" hidden></div>
    <div id="upgrade-err" class="err" hidden></div>
    <div id="plan" hidden>
      <div id="cands"></div>
      <div id="vars"></div>
      <div id="warns"></div>
    </div>
    <div class="actions"><button id="site-back">Retour</button><button id="to-summary" class="primary big" disabled>Continuer</button></div>
  </div>

  <div id="p-devmode" class="card" hidden>
    <h2>Une fonction doit être autorisée sur le routeur</h2>
    <p id="dm-text"></p>
    <div id="dm-start" class="actions"><button id="dm-go" class="primary big">Envoyer la demande au routeur</button><button id="dm-back">Retour</button></div>
    <div id="dm-wait" hidden>
      <div class="countdown" id="dm-count" hidden>5:00</div>
      <p class="instr" id="dm-instr" hidden>Appuyez UNE fois brièvement sur RESET à l'arrière du routeur — ou débranchez puis rebranchez son alimentation.</p>
      <p class="muted"><span class="spin"></span><span id="dm-label">Envoi de la demande au routeur…</span></p>
      <div class="elapsed" id="dm-elapsed"></div>
    </div>
    <div id="dm-ok" class="okbox" hidden>Le routeur a accepté : la suite continue automatiquement.</div>
    <div id="dm-err" class="err" hidden></div>
    <div id="dm-retry-row" class="actions" hidden><button id="dm-retry" class="primary big">Recommencer</button><button id="dm-back2">Retour</button></div>
    <details id="dm-adv"><summary>Options avancées</summary>
      <p class="small muted">Réservé à un test à distance, quand personne ne peut appuyer sur le bouton du routeur. Le routeur sera enregistré comme un TEST et pourra ne pas fonctionner correctement.</p>
      <label for="ov-text">Pour confirmer, tapez : CONTINUER EN TEST</label>
      <input id="ov-text" autocomplete="off" spellcheck="false">
      <div class="actions"><button id="ov-go">Continuer malgré le mode appareil (test)</button></div>
      <div id="ov-err" class="err" hidden></div>
    </details>
  </div>

  <div id="p-summary" class="card" hidden>
    <h2>Vérifiez avant de préparer</h2>
    <div id="sum-test" class="testbanner" hidden>TEST — mode appareil non conforme</div>
    <div class="kv" id="sum-kv"></div>
    <div class="warnbox">Le routeur va être entièrement effacé, puis il redémarrera et appliquera la configuration de ce site.</div>
    <div id="sum-used" class="warnbox" hidden><b>Ce routeur a déjà servi</b> : <span id="sum-used-text"></span>. Toute sa configuration actuelle sera perdue.
      <label class="check"><input type="checkbox" id="sum-used-ok"><span>Je confirme que ce routeur peut être entièrement effacé et réaffecté à ce site.</span></label></div>
    <div id="sum-replace" class="confirmbox" hidden><p id="sum-replace-text"></p>
      <label class="check"><input type="checkbox" id="sum-replace-ok"><span id="sum-replace-label"></span></label></div>
    <div id="sum-err" class="err" hidden></div>
    <div class="actions"><button id="sum-back">Retour</button><button id="go" class="primary big">Préparer le routeur</button><span id="go-hint" class="small muted" hidden>Cochez d'abord la confirmation du remplacement, ci-dessus.</span></div>
  </div>

  <div id="p-run" class="card" hidden>
    <div id="run-progress"><h2><span class="spin"></span><span id="run-label">Préparation…</span></h2><div class="elapsed" id="run-elapsed"></div><p class="muted">Ne débranchez pas le routeur.</p></div>
    <div id="run-test" class="testbanner" hidden>TEST — mode appareil non conforme</div>
    <div id="run-ok" hidden>
      <div class="big-ok" id="run-mark">✓</div>
      <h1 id="run-title">Configuration appliquée — vous pouvez débrancher et mettre en carton</h1>
      <p class="muted" id="run-sub"></p>
      <div class="kv" id="run-kv"></div>
      <div id="run-note"></div>
    </div>
    <div id="run-err" hidden><h2>La préparation n'a pas abouti</h2><div class="err" id="run-err-text"></div>
      <div id="run-blocked" class="warnbox" hidden><p>Le routeur est toujours branché et reconnu : autorisez la fonction bloquée, puis la préparation reprendra.</p><div class="actions"><button id="run-wizard" class="primary big">Autoriser sur le routeur</button></div></div>
    </div>
    <div class="actions" id="run-actions" hidden><button id="next" class="primary big">Préparer le routeur suivant</button></div>
  </div>
</section>
</main>
<footer id="foot"></footer>
<script>
(function () {
  "use strict";
  var token = new URLSearchParams(location.search).get("t") || "";
  var $ = function (id) { return document.getElementById(id); };
  var show = function (el, on) { (typeof el === "string" ? $(el) : el).hidden = !on; };
  var state = null, phaseShown = null, step = "router", found = null, plan = null, siteSel = null, tenants = [];
  // Per candidate: what device-mode it needs and what the box blocks of it.
  var checks = [];
  // The operator's typed test override (device-mode), for the next preparation.
  var override = false, overrideText = "";
  // An upgrade offered by the last plan (shown again when its card is).
  var upgradeOffer = null;
  // True while the preparer is retyping the address: the 2 s poller must not
  // pull the pending/problem screen back over the half-typed field.
  var editingUrl = false;

  // ── the cards ─────────────────────────────────────────────────────────────
  // "cur" is the card the steps below the board show and act on ("" until
  // the application named one: requests then go to its first card). What a
  // card shown earlier held is kept in views[id]; what an operation of a card
  // ended with while another card was shown waits in views[id].deferred.
  var cur = "", views = {}, running = {}, watchedOps = {}, attention = {};
  var lastBoard = null, boardAt = 0, setupShownOnce = false;
  function viewOf(id) { return views[id] || (views[id] = { deferred: [] }); }
  // Runs fn now when card id is shown, or when it is shown again.
  function onCard(id, fn) {
    if (id === cur || !id) { fn(); return; }
    viewOf(id).deferred.push(fn);
  }
  function anyRunning() { for (var k in running) if (running[k]) return true; return false; }

  // A request that broke on the way (no answer at all) is told apart from a
  // refusal: "network" is set, and the sentence says what to do in French.
  function netError() {
    var e = new Error("La liaison avec l'application de ce poste a été interrompue. Si sa fenêtre s'est fermée, relancez-la depuis le menu Démarrer ; sinon, attendez quelques secondes et recommencez.");
    e.network = true; e.body = {};
    return e;
  }
  // "card": the card the request acts on (x-bench-card); none: the first one.
  // "op" (long operations only): its id, and the request is sent DETACHED —
  // the application answers 202 if it has not ended within a few seconds.
  function api(method, path, body, op, card) {
    var headers = { "content-type": "application/json", "x-bench-token": token };
    if (op) { headers["x-bench-op"] = op; headers["x-bench-async"] = "1"; }
    if (card) headers["x-bench-card"] = card;
    return fetch(path, {
      method: method,
      headers: headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      cache: "no-store"
    }).then(function (r) {
      return r.text().then(function (t) {
        var j = {};
        try { j = JSON.parse(t); } catch (e) { j = { error: t }; }
        if (!r.ok) { var e = new Error(j.error || ("Erreur " + r.status)); e.status = r.status; e.body = j; throw e; }
        return j;
      }, function () { throw netError(); });
    }, function () { throw netError(); });
  }
  function newOp() {
    var s = "", c = typeof crypto !== "undefined" && crypto.getRandomValues ? crypto.getRandomValues(new Uint8Array(12)) : null;
    for (var i = 0; i < 12; i++) s += ("0" + (c ? c[i] : Math.floor(Math.random() * 256)).toString(16)).slice(-2);
    return s;
  }
  // What became of operation "op", read back from the application: resolves
  // or rejects exactly as the request's own answer would have.
  function outcomeOf(op) {
    var misses = 0;
    watchedOps[op] = true;
    return new Promise(function (resolve, reject) {
      (function again() {
        api("GET", "/api/outcome?op=" + encodeURIComponent(op)).then(function (r) {
          misses = 0;
          var o = r.outcome;
          if (!o || o.pending) { setTimeout(again, 1500); return; }
          if (o.status >= 200 && o.status < 300) { resolve(o.body); return; }
          var e = new Error((o.body && o.body.error) || ("Erreur " + o.status)); e.status = o.status; e.body = o.body || {};
          reject(e);
        }, function (e) {
          if (e.network && ++misses < 20) { setTimeout(again, 1500); return; }
          reject(e);
        });
      })();
    });
  }
  // A long operation on the router. Detached (202): it goes on, and its
  // outcome is read back by short polls — a request held for minutes per
  // card would take the browser's few connections to this application, and
  // the board would freeze. When the request itself breaks, the operation
  // did not either: its outcome is read back instead of shown as a failure.
  function longApi(method, path, body, card) {
    var op = newOp();
    watchedOps[op] = true;
    return api(method, path, body, op, card).then(function (r) {
      return r && r.detached === true && r.op === op ? outcomeOf(op) : r;
    }, function (e) {
      if (!e.network) throw e;
      return outcomeOf(op);
    });
  }
  function text(el, v) { (typeof el === "string" ? $(el) : el).textContent = v == null ? "" : String(v); }
  function kv(el, pairs) {
    el = $(el); el.textContent = "";
    pairs.forEach(function (p) {
      if (p[1] == null || p[1] === "") return;
      var a = document.createElement("div"); a.textContent = p[0];
      var b = document.createElement("div"); b.textContent = String(p[1]);
      el.appendChild(a); el.appendChild(b);
    });
  }
  function err(el, e) { el = $(el); el.textContent = e ? (e.message || String(e)) : ""; el.hidden = !e; }

  // ── liveness: the process ends when this window is gone (not mid-operation) ─
  try { new EventSource("/api/events?t=" + encodeURIComponent(token)); } catch (e) { /* the heartbeat still runs */ }
  setInterval(function () { api("POST", "/api/heartbeat").catch(function () {}); }, 5000);
  api("POST", "/api/heartbeat").catch(function () {});

  // ── progress of a long request ────────────────────────────────────────────
  function dur(ms) {
    var s = Math.max(0, Math.round(ms / 1000)), m = Math.floor(s / 60), r = s % 60;
    return m > 0 ? m + " min " + (r < 10 ? "0" : "") + r + " s" : r + " s";
  }
  function clock(ms) {
    var s = Math.max(0, Math.ceil(ms / 1000)), m = Math.floor(s / 60), r = s % 60;
    return m + ":" + (r < 10 ? "0" : "") + r;
  }
  // Polls the local server for the label of card id's long request, and
  // draws the times it carries (elapsed since, countdown to) on the server's
  // clock — only while that card is the one shown.
  function watchProgress(target, extras, id) {
    extras = extras || {};
    id = id === undefined ? cur : id;
    var last = null, offset = 0;
    var t = setInterval(function () {
      api("GET", "/api/progress", undefined, null, id).then(function (p) {
        if (cur !== id) return;
        if (p.label) text(target, p.label);
        last = p.timer || null;
        if (typeof p.now === "number") offset = p.now - Date.now();
      }).catch(function () {});
    }, 600);
    var d = setInterval(function () {
      if (cur !== id) return;
      var nowS = Date.now() + offset;
      if (extras.count) {
        // The countdown (and the instruction beside it) only while the
        // application says a press is awaited: once the box went down it is
        // gone, so that nobody presses again while it boots.
        var on = !!(last && last.countdownEndsAt);
        show(extras.count, on);
        if (extras.instr) show(extras.instr, on);
        if (on) text(extras.count, clock(Math.max(0, last.countdownEndsAt - nowS)));
      }
      if (extras.elapsed) {
        if (last && last.since) text(extras.elapsed, "Temps écoulé : " + dur(nowS - last.since) + (last.deadline ? " (" + dur(last.deadline - last.since) + " au plus)" : ""));
        else text(extras.elapsed, "");
      }
    }, 250);
    return function () { clearInterval(t); clearInterval(d); if (extras.elapsed && cur === id) text(extras.elapsed, ""); };
  }

  // ── a card needs the technician: a sound, a blinking title ────────────────
  var audio = null, blink = null, TITLE = "ObliWAN — Préparation des routeurs";
  function beep() {
    try {
      var AC = typeof AudioContext !== "undefined" ? AudioContext : null;
      if (!AC) return;
      audio = audio || new AC();
      if (audio.state === "suspended" && audio.resume) audio.resume();
      [0, 0.28, 0.56].forEach(function (at, i) {
        var o = audio.createOscillator(), g = audio.createGain(), t0 = audio.currentTime + at;
        o.type = "sine"; o.frequency.value = i === 2 ? 1320 : 880;
        g.gain.setValueAtTime(0.0001, t0);
        g.gain.exponentialRampToValueAtTime(0.35, t0 + 0.02);
        g.gain.exponentialRampToValueAtTime(0.0001, t0 + 0.22);
        o.connect(g); g.connect(audio.destination); o.start(t0); o.stop(t0 + 0.24);
      });
    } catch (e) { /* no sound on this machine: the title and the board still say it */ }
  }
  function titleAlert() {
    if (blink) return;
    var on = false;
    blink = setInterval(function () { on = !on; document.title = (on ? "(!) Un routeur vous attend — " : "") + TITLE; }, 900);
  }
  function titleCalm() {
    if (blink) { clearInterval(blink); blink = null; }
    document.title = TITLE;
  }
  if (typeof window !== "undefined" && window.addEventListener) window.addEventListener("focus", titleCalm);
  // The first click also opens the sound (a browser may hold it until then).
  if (document.addEventListener) document.addEventListener("click", function () { titleCalm(); try { if (audio && audio.state === "suspended") audio.resume(); } catch (e) { /* none */ } });

  // ── the gate ──────────────────────────────────────────────────────────────
  var GATE = ["s-url", "s-checking", "s-pending", "s-revoked", "s-problem", "s-app"];
  function screen(id) { GATE.forEach(function (s) { show(s, s === id); }); }
  function render(s) {
    state = s;
    text("foot", "Outil d'établi ObliWAN v" + s.version + (s.baseUrl ? " — " + s.baseUrl : ""));
    var dot = $("chip-dot");
    dot.className = "dot " + (s.phase === "approved" ? "ok" : s.phase === "pending" || s.phase === "checking" ? "warn" : "bad");
    text("chip-text", s.phase === "approved" && s.station ? "Poste autorisé · " + s.station.name
      : s.phase === "pending" ? "En attente d'autorisation" : s.phase === "need-url" ? "Non configuré"
      : s.phase === "checking" ? "Connexion…" : s.phase === "revoked" ? "Poste révoqué" : "ObliWAN injoignable");
    // No "opened in your browser" banner any more: the page only ever runs in
    // its own application window (window.ts, "NO BROWSER FALLBACK").
    if (s.update && s.update.available) { text("update-text", "Une nouvelle version de cet outil est disponible (" + s.update.available + ")."); show("banner-update", true); }
    else show("banner-update", false);

    var p = s.phase;
    if (editingUrl) {
      if (s.urlEditable && p !== "need-url") return; // keep the half-typed address on screen
      editingUrl = false; show("url-cancel", false);
    }
    show("pending-url", !!s.urlEditable);
    if (p === "need-url") { if (phaseShown !== p) { screen("s-url"); $("url").value = ""; } }
    else if (p === "checking") { screen("s-checking"); text("checking-url", s.baseUrl); }
    else if (p === "pending") {
      screen("s-pending");
      text("pending-name", s.station.name); text("pending-id", "n° " + s.station.stationId);
      text("pending-code", s.station.verificationCode || "(aucun code fourni)");
      text("pending-text", s.text);
    } else if (p === "revoked") { screen("s-revoked"); text("revoked-text", s.text); }
    else if (p === "approved") { if (phaseShown !== p) { screen("s-app"); goStep(step); resume(); pollBoard(); } }
    else {
      screen("s-problem");
      text("problem-title", p === "redirected" ? "L'adresse d'ObliWAN redirige ailleurs" : p === "localError" ? "Problème sur ce poste" : p === "refused" ? "ObliWAN refuse ce poste" : "ObliWAN ne répond pas");
      text("problem-text", s.text);
      show("problem-url", !!s.urlEditable);
    }
    phaseShown = p;
  }
  function poll() {
    api("GET", "/api/state").then(render).catch(function () {
      text("chip-text", "Application arrêtée"); $("chip-dot").className = "dot bad";
    });
  }
  setInterval(function () { if (!state || state.phase !== "approved") poll(); }, 2000);
  setInterval(function () { if (state && state.phase === "approved" && !anyRunning()) poll(); }, 15000);
  poll();

  $("url-go").onclick = function () {
    err("url-err", null);
    api("POST", "/api/url", { url: $("url").value }).then(function (s) {
      editingUrl = false; show("url-cancel", false); phaseShown = null; render(s);
    }).catch(function (e) { err("url-err", e); });
  };
  $("url").addEventListener("keydown", function (e) { if (e.key === "Enter") $("url-go").click(); });
  $("pending-url").onclick = $("problem-url").onclick = function () {
    if (!editingUrl) { editingUrl = true; $("url").value = state && state.baseUrl || ""; err("url-err", null); }
    screen("s-url"); show("url-cancel", true); $("url").focus();
  };
  $("url-cancel").onclick = function () {
    editingUrl = false; show("url-cancel", false); phaseShown = null;
    if (state) render(state);
  };
  $("problem-retry").onclick = function () { api("GET", "/api/state?refresh=1").then(render).catch(function () {}); };
  $("revoked-renew").onclick = function () { api("POST", "/api/station/renew").then(render).catch(function (e) { text("revoked-text", e.message); }); };
  $("update-go").onclick = function () {
    $("update-go").disabled = true;
    api("POST", "/api/update/apply").then(function (r) { text("update-text", r.message || "Installation lancée : l'application va se fermer."); })
      .catch(function (e) { text("update-text", e.message); $("update-go").disabled = false; });
  };
  function gateError(e) { if (e && e.body && e.body.gate) { phaseShown = null; poll(); } }

  // ── the board: one card per router in progress ───────────────────────────
  function siteText(s) { return s ? (s.code ? s.code + " — " : "") + (s.name || "") : ""; }
  function cardTitle(c) { return c.slot ? c.slot.label : "Routeur n°" + c.id; }
  function pollBoard() {
    return api("GET", "/api/cards").then(function (r) {
      lastBoard = r; boardAt = Date.now();
      err("board-err", null);
      var list = r.cards || [];
      if (!cur && list.length) {
        var b = list.filter(function (c) { return c.busy; })[0] || list[0];
        cur = b.id;
      }
      // A card that started needing the technician since the last look.
      var ring = false;
      list.forEach(function (c) {
        if (attention[c.id] !== undefined && c.attention > attention[c.id]) ring = true;
        attention[c.id] = c.attention;
      });
      if (ring) { beep(); titleAlert(); }
      renderBoard();
      renderHistory(r.history || []);
      // First run on a PC with several links (or a refused one): how to cable it.
      var sl = r.slots || { slots: [], refused: [] };
      if (!setupShownOnce && (sl.slots.length >= 2 || sl.refused.length) && !setupDone()) { setupShownOnce = true; openSetup(); }
      return r;
    }).catch(function (e) { if (!e.network) err("board-err", e); });
  }
  setInterval(function () { if (state && state.phase === "approved") pollBoard(); }, 1000);
  // #24: what this PC prepared today, newest first (history.ts). Text only.
  function renderHistory(h) {
    show("hist", h.length > 0);
    text("hist-count", "(" + h.length + ")");
    var box = $("hist-list"); while (box.firstChild) box.removeChild(box.firstChild);
    h.forEach(function (e) {
      var d = document.createElement("div");
      d.className = "small";
      var t = new Date(e.at).toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit" });
      d.textContent = t + " · " + (e.ok ? (e.test ? "TEST " : "OK ") : "ÉCHEC ") + "· " + (e.site || "?") + (e.tenant ? " (" + e.tenant + ")" : "")
        + " · " + (e.model || "") + (e.serial ? " n° " + e.serial : "") + (e.mac ? " · " + e.mac : "")
        + (e.iccid ? " · SIM " + e.iccid : "") + (e.deviceId ? " · fiche n° " + e.deviceId : "")
        + (!e.ok && e.message ? " — " + e.message : "");
      d.style.color = e.ok ? (e.test ? "#e0b341" : "") : "#e5484d";
      box.appendChild(d);
    });
  }
  function renderBoard() {
    var r = lastBoard;
    if (!r) return;
    var list = r.cards || [], sl = r.slots || { slots: [], refused: [] };
    var nowS = r.now + (Date.now() - boardAt);
    text("slots-line", sl.slots.length
      ? "· " + sl.slots.length + " prise" + (sl.slots.length > 1 ? "s" : "") + " : " + sl.slots.map(function (s) { return s.label; }).join(", ")
      // A link is listed only while its cable is live (slots.ts): before any
      // router is plugged in and powered, a PC equipped for several shows none.
      : "· aucune prise active : une prise n'apparaît qu'avec un routeur allumé branché dessus (sans prise à adresse fixe : un routeur à la fois)");
    if (sl.refused.length) {
      text("slots-warn", "Prise refusée : " + sl.refused.map(function (x) { return "« " + x.iface + " » " + x.reason; }).join(" ") + " Voir « Préparer ce PC ».");
      show("slots-warn", true);
    } else show("slots-warn", false);
    // Shown on a one-router PC too while a card is red for an unplugged box:
    // its « Abandonner » is there.
    var many = list.length > 1 || sl.slots.length >= 2 || list.some(function (c) { return c.unplugged; });
    show("board", many); show("cur-head", many);
    var board = $("board"); board.textContent = "";
    list.forEach(function (c) {
      var el = document.createElement("div");
      el.className = "bcard tone-" + c.tone + (c.id === cur ? " cur" : "");
      var h = document.createElement("div"); h.className = "bh";
      var a = document.createElement("span"); a.textContent = cardTitle(c);
      var t = document.createElement("span"); t.className = "bmeta";
      t.textContent = c.startedAt ? dur((c.endedAt || nowS) - c.startedAt) : "n°" + c.id;
      h.appendChild(a); h.appendChild(t); el.appendChild(h);
      var m1 = document.createElement("div"); m1.className = "bmeta"; m1.textContent = c.site ? "Site " + siteText(c.site) : "Site : pas encore choisi"; el.appendChild(m1);
      if (c.mac) { var m2 = document.createElement("div"); m2.className = "bmeta"; m2.textContent = "MAC " + c.mac; el.appendChild(m2); }
      if (c.step) { var m3 = document.createElement("div"); m3.className = "bmeta"; m3.textContent = c.step; el.appendChild(m3); }
      var act = document.createElement("div"); act.className = "bact"; act.textContent = c.action; el.appendChild(act);
      if (c.timer && c.timer.countdownEndsAt) {
        var cd = document.createElement("div"); cd.className = "bcount"; cd.textContent = clock(c.timer.countdownEndsAt - nowS); el.appendChild(cd);
      }
      // Any card not running can be closed — a found router waiting for its
      // site too: a refusal may name it (« fermez la carte n°2 »).
      if (!c.busy && list.length > 1) {
        var x = document.createElement("button"); x.className = "bbtn"; x.id = "close-" + c.id;
        x.textContent = c.tone === "ok" ? "Mis en carton : fermer" : "Fermer cette carte";
        x.onclick = function (ev) { if (ev && ev.stopPropagation) ev.stopPropagation(); closeCard(c.id); };
        el.appendChild(x);
      }
      // A box that looks unplugged: give up instead of waiting up to 30 min.
      if (c.busy && c.unplugged && !c.abandoned) {
        var ab = document.createElement("button"); ab.className = "bbtn"; ab.id = "abandon-" + c.id;
        ab.textContent = "Abandonner ce routeur";
        ab.onclick = function (ev) { if (ev && ev.stopPropagation) ev.stopPropagation(); abandonCard(c.id); };
        el.appendChild(ab);
      }
      el.onclick = function () { focusCard(c.id); };
      board.appendChild(el);
    });
    var me = list.filter(function (c) { return c.id === cur; })[0];
    text("cur-label", me ? cardTitle(me) + (me.site ? " · " + siteText(me.site) : "") + " (n°" + me.id + ")" : "");
  }
  function abandonCard(id) {
    api("POST", "/api/cards/abandon", {}, null, id).then(function () { return pollBoard(); })
      .catch(function (e) { err("board-err", e); });
  }
  function closeCard(id) {
    api("POST", "/api/cards/close", {}, null, id).then(function () {
      delete views[id]; delete running[id];
      if (id === cur) { cur = ""; return pollBoard().then(function () { if (cur) loadView(cur); }); }
      return pollBoard();
    }).catch(function (e) { err("board-err", e); });
  }
  $("new-card").onclick = function () {
    titleCalm();
    api("POST", "/api/cards", {}).then(function (r) {
      var id = r.card.id;
      if (id !== cur) { saveView(); views[id] = { step: "router", deferred: [] }; cur = id; applyView(views[id]); }
      else { resetRouter(); $("mac").value = ""; $("pw").value = ""; goStep("router"); }
      pollBoard();
      $("mac").focus();
    }).catch(function (e) { err("board-err", e); gateError(e); });
  };
  function focusCard(id) {
    titleCalm();
    if (id === cur) return;
    saveView();
    cur = id;
    loadView(id);
    renderBoard();
  }

  // What the steps hold for the card shown, kept when another one is shown.
  function saveView() {
    if (!cur) return;
    var v = viewOf(cur);
    v.step = step; v.found = found; v.plan = plan; v.checks = checks; v.siteSel = siteSel;
    v.override = override; v.overrideText = overrideText; v.upgradeOffer = upgradeOffer;
    v.mac = $("mac").value; v.tenantId = $("tenant").value; v.search = $("search").value;
    v.bench = benchValues(); v.revision = chosenRevision();
  }
  function applyView(v) {
    step = v.step || "router"; found = v.found || null; plan = v.plan || null; checks = v.checks || [];
    siteSel = v.siteSel || (plan && plan.site ? { id: plan.site.id, code: plan.site.code, name: plan.site.name } : null);
    override = !!v.override; overrideText = v.overrideText || ""; upgradeOffer = null;
    show("found", false); err("find-err", null); show("resume-note", false); show("find-progress", false);
    $("mac").value = v.mac || (found ? found.mac : ""); $("pw").value = "";
    $("find").disabled = !!running[cur];
    if (found) { showFound(found); show("found", true); }
    show("sites", false); show("plan", false); show("upgrade", false); show("upgrade-done", false); show("upgrade-progress", false);
    err("upgrade-err", null); err("site-err", null); show("plan-progress", false); $("to-summary").disabled = true;
    $("search").value = v.search || "";
    if (tenants.length) { $("tenant").value = v.tenantId || ""; if ($("tenant").value) listSites(); }
    if (plan) {
      renderPlan({ plan: plan, deviceMode: checks });
      Array.prototype.forEach.call(document.querySelectorAll("#vars input"), function (i) { if (v.bench && v.bench[i.dataset.key] != null) i.value = v.bench[i.dataset.key]; });
      if (v.revision != null) Array.prototype.forEach.call(document.querySelectorAll("#cands input"), function (i) { i.checked = Number(i.value) === v.revision; });
      checkReady();
    }
    if (v.upgradeOffer) showUpgrade(v.upgradeOffer);
    if (step === "devmode") step = "site"; // the wizard starts again from its button
    if (step === "summary" && !(plan && found && siteSel)) step = plan ? "site" : "router";
    show("run-progress", !!running[cur]); show("run-ok", false); show("run-err", false); show("run-actions", false); show("run-blocked", false); show("run-test", false);
    if (step === "summary") toSummary(); else goStep(step);
    if (step === "run" && !running[cur] && v.runRender) v.runRender();
    var d = v.deferred || []; v.deferred = [];
    d.forEach(function (f) { f(); });
  }
  function loadView(id) {
    if (views[id]) { applyView(views[id]); return; }
    // Nothing remembered by this window for that card (another window
    // started it): what the application holds of it.
    applyView(viewOf(id));
    api("GET", "/api/card", undefined, null, id).then(function (r) {
      if (cur !== id) return;
      var v = viewOf(id);
      v.found = r.box || null; v.step = r.box ? "router" : "router";
      if (r.plan) { v.plan = r.plan.plan; v.checks = r.plan.deviceMode || []; v.step = "site"; }
      if (r.upgrade) { v.upgradeOffer = r.upgrade; v.step = "site"; }
      var o = r.outcome;
      if (o && o.kind === "prepare" && !watchedOps[o.op]) {
        if (o.pending) { applyView(v); endRun(outcomeOf(o.op), startRun(false, id), id); return; }
        if (!r.box) { v.step = "run"; applyView(v); endRun(o.status >= 200 && o.status < 300 ? Promise.resolve(o.body) : Promise.reject(outcomeError(o)), function () {}, id); return; }
      }
      applyView(v);
    }).catch(function () {});
  }
  function outcomeError(o) { var e = new Error((o.body && o.body.error) || ("Erreur " + o.status)); e.status = o.status; e.body = o.body || {}; return e; }

  // ── « Préparer ce PC » ────────────────────────────────────────────────────
  function setupDone() { try { return typeof localStorage !== "undefined" && localStorage.getItem("obliwan-bench-setup") === "1"; } catch (e) { return false; } }
  function openSetup() {
    show("p-setup", true); show("steps-bar", false);
    PANELS.forEach(function (n) { show("p-" + n, false); });
    api("GET", "/api/slots").then(renderSetup).catch(function (e) { err("setup-refused", e); });
  }
  function closeSetup() { show("p-setup", false); show("steps-bar", true); goStep(step); }
  function renderSetup(sl) {
    var list = $("setup-list"); list.textContent = "";
    (sl.slots || []).forEach(function (s) {
      var it = document.createElement("div"); it.className = "item";
      var b = document.createElement("b"); b.textContent = s.label;
      var n = document.createElement("span"); n.textContent = s.iface + " — " + s.address;
      var tg = document.createElement("span"); tg.className = "tag" + (s.card ? "" : " ok"); tg.textContent = s.card ? "routeur en cours (n°" + s.card + ")" : "libre";
      it.appendChild(b); it.appendChild(n); it.appendChild(tg); list.appendChild(it);
    });
    if (!list.children.length) {
      var none = document.createElement("div"); none.className = "item muted";
      none.textContent = "Aucune prise à adresse fixe 192.168.88.x sur ce PC : un seul routeur à la fois. Suivez les étapes ci-dessus pour en préparer plusieurs.";
      list.appendChild(none);
    }
    var refused = sl.refused || [];
    if (refused.length) err("setup-refused", new Error(refused.map(function (x) { return "« " + x.iface + " » " + x.reason; }).join("\n")));
    else err("setup-refused", null);
  }
  $("setup-open").onclick = openSetup;
  $("setup-refresh").onclick = function () { api("GET", "/api/slots").then(renderSetup).catch(function (e) { err("setup-refused", e); }); };
  $("setup-done").onclick = function () {
    try { if (typeof localStorage !== "undefined") localStorage.setItem("obliwan-bench-setup", "1"); } catch (e) { /* asked again next time */ }
    closeSetup();
  };

  // ── the clerk's path, for the card shown ─────────────────────────────────
  var STEPS = ["router", "site", "summary", "run"];
  // The device-mode wizard is part of step 2: it shows under that heading.
  var PANELS = ["router", "site", "devmode", "summary", "run"];
  function goStep(s) {
    step = s;
    var shown = s === "devmode" ? "site" : s;
    show("p-setup", false); show("steps-bar", true);
    PANELS.forEach(function (n) { show("p-" + n, n === s); });
    STEPS.forEach(function (n, i) {
      var el = $("st-" + n);
      el.className = "step" + (n === shown ? " on" : STEPS.indexOf(shown) > i ? " done" : "");
    });
    if (s === "site" && !tenants.length) loadTenants();
  }

  // Leaves the password field alone: the find handler reads it AFTER calling
  // this. It is cleared once the local server holds it (a successful find), and
  // on "next" / "other router".
  function resetRouter() {
    found = null; plan = null; siteSel = null; checks = []; override = false; overrideText = ""; upgradeOffer = null;
    show("found", false); err("find-err", null); show("resume-note", false);
  }
  function showFound(b) {
    found = b;
    kv("found-kv", [["Modèle", found.model || found.board], ["Numéro de série", found.serial], ["Version RouterOS", found.version],
      ["Wi-Fi", found.wifiStack === "wifi" ? "wifi (RouterOS 7.13+)" : found.wifiStack === "wireless" ? "wireless" : "aucun"],
      ["Mode appareil", found.deviceMode || "non lu"],
      ["Adresse MAC", found.mac], ["Branché sur", found.slot ? found.slot.label + " (" + found.slot.iface + ")" : null], ["Trouvé à l'adresse", found.address]]);
  }
  $("find").onclick = function () {
    var id = cur;
    if (running[id]) return;
    var body = {
      mac: $("mac").value, password: $("pw").value,
      host: $("host").value, username: $("user").value, port: $("port").value
    };
    running[id] = true; $("find").disabled = true; resetRouter();
    show("find-progress", true); text($("find-progress").lastChild, "Recherche du routeur sur le réseau…");
    var stop = watchProgress($("find-progress").lastChild, {}, id);
    api("POST", "/api/router/find", body, null, id).then(function (r) {
      onCard(id, function () {
        $("pw").value = "";
        showFound(r.box);
        show("found", true);
        show("to-site", true);
      });
    }).catch(function (e) { onCard(id, function () { err("find-err", e); }); gateError(e); })
      .then(function () { stop(); running[id] = false; onCard(id, function () { $("find").disabled = false; show("find-progress", false); }); pollBoard(); });
  };
  $("other-router").onclick = function () { api("POST", "/api/router/forget", undefined, null, cur).catch(function () {}); resetRouter(); $("pw").value = ""; $("mac").focus(); };
  $("to-site").onclick = function () { goStep("site"); };
  $("site-back").onclick = function () { goStep("router"); };

  function loadTenants() {
    api("GET", "/api/tenants").then(function (r) {
      tenants = r.tenants || [];
      var sel = $("tenant"); sel.textContent = "";
      var o = document.createElement("option"); o.value = ""; o.textContent = tenants.length ? "Choisissez le client…" : "Aucun client";
      sel.appendChild(o);
      tenants.forEach(function (t) { var x = document.createElement("option"); x.value = String(t.id); x.textContent = t.name; sel.appendChild(x); });
      if (tenants.length === 1) { sel.value = String(tenants[0].id); searchSites(); }
    }).catch(function (e) { err("site-err", e); gateError(e); });
  }
  var searchTimer = null;
  function clearPlan() {
    plan = null; siteSel = null; checks = []; upgradeOffer = null; show("plan", false); $("to-summary").disabled = true;
    show("upgrade", false); show("upgrade-done", false); err("upgrade-err", null);
  }
  function searchSites() {
    clearPlan(); err("site-err", null);
    listSites();
  }
  // The list of sites for the chosen customer, without touching the plan.
  function listSites() {
    var tid = $("tenant").value;
    if (!tid) { show("sites", false); return; }
    api("GET", "/api/sites?tenantId=" + encodeURIComponent(tid) + "&search=" + encodeURIComponent($("search").value.trim()))
      .then(function (r) {
        var list = $("sites"); list.textContent = "";
        (r.sites || []).forEach(function (s) {
          var it = document.createElement("div"); it.className = "item" + (siteSel && siteSel.id === s.id ? " sel" : "");
          var b = document.createElement("b"); b.textContent = s.code || "—";
          var n = document.createElement("span"); n.textContent = s.name + (s.country ? " (" + s.country + ")" : "");
          var tg = document.createElement("span"); tg.className = "tag" + (s.provisioned ? " ok" : ""); tg.textContent = s.provisioned ? "déjà équipé" : "nouveau";
          it.appendChild(b); it.appendChild(n); it.appendChild(tg);
          it.onclick = function () { Array.prototype.forEach.call(list.children, function (c) { c.classList.remove("sel"); }); it.classList.add("sel"); pickSite(s); };
          list.appendChild(it);
        });
        if (!list.children.length) { var none = document.createElement("div"); none.className = "item muted"; none.textContent = "Aucun site ne correspond."; list.appendChild(none); }
        show("sites", true);
      }).catch(function (e) { err("site-err", e); gateError(e); });
  }
  $("tenant").onchange = searchSites;
  $("search").addEventListener("input", function () { clearTimeout(searchTimer); searchTimer = setTimeout(searchSites, 300); });

  function pickSite(s) {
    var id = cur;
    clearPlan(); siteSel = s; err("site-err", null); show("plan-progress", true);
    api("POST", "/api/plan", { siteId: s.id }, null, id).then(function (r) {
      onCard(id, function () {
        if (r.upgrade) { showUpgrade(r.upgrade); return; }
        renderPlan(r);
      });
    }).catch(function (e) { onCard(id, function () { err("site-err", e); }); gateError(e); })
      .then(function () { onCard(id, function () { show("plan-progress", false); }); pollBoard(); });
  }
  function showUpgrade(u) {
    upgradeOffer = u;
    text("upgrade-text", "Ce routeur est en RouterOS " + (u.from || "?") + " : le modèle de configuration de ce site exige au moins la version "
      + (u.minimum || u.to) + ". Il faut d'abord le mettre à jour en RouterOS " + u.to + " (quelques minutes, le routeur redémarre une fois). Ne le débranchez pas pendant la mise à jour.");
    show("upgrade", true); $("upgrade-go").disabled = !!running[cur]; err("upgrade-err", null);
  }
  $("upgrade-go").onclick = function () {
    var id = cur;
    if (running[id]) return;
    running[id] = true; $("upgrade-go").disabled = true; $("site-back").disabled = true; err("upgrade-err", null);
    show("upgrade-progress", true); text("upgrade-label", "Vérification du routeur…");
    var stop = watchProgress($("upgrade-label"), { elapsed: $("upgrade-elapsed") }, id);
    longApi("POST", "/api/router/upgrade", undefined, id).then(function (r) {
      onCard(id, function () {
        show("upgrade", false); upgradeOffer = null;
        if (r.box) showFound(r.box);
        text("upgrade-done", "RouterOS mis à jour : " + r.upgraded.from + " → " + r.upgraded.to + ".");
        show("upgrade-done", true);
        if (r.planError) { err("site-err", new Error(r.planError)); return; }
        renderPlan(r);
        // The plan is ready: continue on our own only when there is nothing to
        // choose (ONE configuration) and nothing to type. Several candidates
        // wait for the technician's choice, as after any other plan.
        if (plan.candidates.length === 1 && !$("to-summary").disabled) $("to-summary").click();
      });
    }).catch(function (e) {
      onCard(id, function () {
        err("upgrade-err", e); $("upgrade-go").disabled = false;
        if (e.body && e.body.rebooted) { $("upgrade-go").disabled = true; err("upgrade-err", new Error(e.message + " Puis revenez à l'étape 1 et relancez la recherche du routeur.")); }
      });
      gateError(e);
    }).then(function () {
      stop(); running[id] = false;
      onCard(id, function () { $("site-back").disabled = false; show("upgrade-progress", false); });
      pollBoard();
    });
  };
  function renderPlan(r) {
    plan = r.plan; checks = r.deviceMode || [];
    var c = $("cands"); c.textContent = "";
    if (plan.candidates.length > 1) {
      var l = document.createElement("label"); l.textContent = "Plusieurs modèles de configuration conviennent : choisissez celui à appliquer"; c.appendChild(l);
    }
    plan.candidates.forEach(function (cd, i) {
      var lab = document.createElement("label"); lab.className = "radio";
      var r2 = document.createElement("input"); r2.type = "radio"; r2.name = "cand"; r2.value = String(cd.revisionId); r2.checked = i === 0;
      var sp = document.createElement("span"); sp.textContent = cd.templateName + (cd.revision != null ? " — révision " + cd.revision : "");
      lab.appendChild(r2); lab.appendChild(sp); c.appendChild(lab);
      if (plan.candidates.length === 1) lab.hidden = true;
    });
    var v = $("vars"); v.textContent = "";
    plan.benchVariables.forEach(function (bv) {
      var l = document.createElement("label"); l.textContent = bv.label + (bv.required ? " *" : ""); l.htmlFor = "bv-" + bv.key;
      var inp = document.createElement("input"); inp.id = "bv-" + bv.key; inp.dataset.key = bv.key; inp.dataset.required = bv.required ? "1" : "";
      inp.type = bv.secret ? "password" : "text"; inp.autocomplete = "off"; inp.oninput = checkReady;
      v.appendChild(l); v.appendChild(inp);
    });
    var w = $("warns"); w.textContent = "";
    plan.warnings.forEach(function (x) { var d = document.createElement("div"); d.className = "warnbox"; d.textContent = x; w.appendChild(d); });
    show("plan", true); checkReady();
  }
  function benchValues() {
    var out = {};
    Array.prototype.forEach.call(document.querySelectorAll("#vars input"), function (i) { out[i.dataset.key] = i.value; });
    return out;
  }
  function checkReady() {
    var ok = !!plan;
    Array.prototype.forEach.call(document.querySelectorAll("#vars input"), function (i) { if (i.dataset.required && !i.value.trim()) ok = false; });
    $("to-summary").disabled = !ok;
  }
  function chosenRevision() { var r = document.querySelector("input[name=cand]:checked"); return r ? Number(r.value) : null; }
  function checkFor(revisionId) { return checks.filter(function (k) { return k.revisionId === revisionId; })[0] || null; }
  function toSummary() {
    var a = plan.allocation || {};
    var cand = plan.candidates.filter(function (c) { return c.revisionId === chosenRevision(); })[0];
    var tname = (tenants.filter(function (t) { return String(t.id) === $("tenant").value; })[0] || {}).name;
    kv("sum-kv", [["Client", tname || (plan.tenant && plan.tenant.name)], ["Site", (siteSel.code ? siteSel.code + " — " : "") + siteSel.name],
      ["Routeur", (found.model || found.board) + (found.serial ? " · n° " + found.serial : "")],
      ["Branché sur", found.slot ? found.slot.label + " (" + found.slot.iface + ")" : null],
      ["Identifiant PPP", a.ppp_username], ["Adresse IP du tunnel", a.tunnel_ip], ["Réseau local", a.lan_subnet],
      ["Nom du routeur", a.system_identity], ["Configuration", cand ? cand.templateName : ""]]);
    show("sum-test", override);
    var used = (found && found.previouslyConfigured) || [];
    show("sum-used", used.length > 0);
    text("sum-used-text", used.join(", "));
    $("sum-used-ok").checked = false;
    // Every time the summary is drawn (another site, another plan, another
    // card), the confirmations start unticked: one given for a previous
    // choice confirms nothing.
    var rep = replaceOf();
    show("sum-replace", !!rep);
    text("sum-replace-text", rep ? rep.message : "");
    text("sum-replace-label", rep ? "Je confirme remplacer le routeur actuel de ce site (appareil n°" + rep.deviceId + ") : il sera désactivé." : "");
    $("sum-replace-ok").checked = false;
    err("sum-err", null);
    updateGo();
    goStep("summary");
  }
  // The site's current router, which this preparation retires (the plan's
  // "replaces"), or null. Its confirmation is REQUIRED: « Préparer le
  // routeur » stays disabled until it is ticked.
  function replaceOf() {
    var r = plan && plan.replaces;
    return r && typeof r.deviceId === "number" ? r : null;
  }
  function updateGo() {
    var held = !!replaceOf() && !$("sum-replace-ok").checked;
    $("go").disabled = held;
    show("go-hint", held);
  }
  $("sum-replace-ok").onchange = function () { err("sum-err", null); updateGo(); };
  $("sum-used-ok").onchange = function () { err("sum-err", null); };
  // Before anything is committed: a candidate whose device-mode needs the box
  // blocks opens the wizard instead of the summary.
  $("to-summary").onclick = function () {
    var k = checkFor(chosenRevision());
    if (k && k.blocked && k.blocked.length && !override) { openWizard(k.message); return; }
    toSummary();
  };
  $("sum-back").onclick = function () { goStep("site"); };

  // ── the device-mode wizard ────────────────────────────────────────────────
  function openWizard(message) {
    text("dm-text", message || "Ce routeur bloque une fonction dont sa configuration a besoin.");
    show("dm-start", true); show("dm-wait", false); show("dm-ok", false); err("dm-err", null); show("dm-retry-row", false);
    err("ov-err", null); $("ov-text").value = ""; $("dm-go").disabled = false;
    goStep("devmode");
  }
  function runWizard() {
    var id = cur;
    if (running[id]) return;
    var revision = chosenRevision();
    running[id] = true; $("dm-go").disabled = true; err("dm-err", null); show("dm-retry-row", false); show("dm-start", false);
    show("dm-wait", true); show("dm-count", false); show("dm-instr", false); text("dm-label", "Envoi de la demande au routeur…");
    var stop = watchProgress($("dm-label"), { count: $("dm-count"), instr: $("dm-instr"), elapsed: $("dm-elapsed") }, id);
    longApi("POST", "/api/router/device-mode", { revisionId: revision }, id).then(function (r) {
      onCard(id, function () {
        if (r.box) showFound(r.box);
        checks = checks.map(function (k) { return k.revisionId === revision ? { revisionId: k.revisionId, needed: k.needed, blocked: [], message: null } : k; });
        show("dm-wait", false); show("dm-ok", true);
        setTimeout(function () { if (cur === id && step === "devmode") toSummary(); }, 900);
      });
    }).catch(function (e) {
      onCard(id, function () { show("dm-wait", false); err("dm-err", e); show("dm-retry-row", true); });
      gateError(e);
    }).then(function () { stop(); running[id] = false; pollBoard(); });
  }
  $("dm-go").onclick = runWizard;
  $("dm-retry").onclick = runWizard;
  $("dm-back").onclick = $("dm-back2").onclick = function () { if (!running[cur]) goStep("site"); };
  $("ov-go").onclick = function () {
    var typed = $("ov-text").value.trim().toUpperCase();
    if (typed !== "CONTINUER EN TEST") { err("ov-err", new Error("Tapez exactement : CONTINUER EN TEST")); return; }
    override = true; overrideText = typed; err("ov-err", null);
    toSummary();
  };

  function startRun(isTest, id) {
    id = id === undefined ? cur : id;
    running[id] = true;
    var v = viewOf(id); v.runRender = null; v.step = "run";
    if (cur === id) {
      goStep("run");
      show("run-progress", true); show("run-ok", false); show("run-err", false); show("run-actions", false); show("run-blocked", false);
      show("run-test", isTest);
      text("run-label", "ObliWAN prépare la configuration de ce routeur…");
    }
    return watchProgress($("run-label"), { elapsed: $("run-elapsed") }, id);
  }
  $("go").onclick = function () {
    var id = cur;
    if (running[id]) return;
    // Every confirmation is judged BEFORE anything starts: a box left
    // unticked keeps the summary on screen, with the reason above the
    // button — nothing sent, nothing running. (The run screen used to start
    // first, and stayed on its spinner with nothing sent.)
    err("sum-err", null);
    var used = (found && found.previouslyConfigured) || [];
    if (used.length && !$("sum-used-ok").checked) { err("sum-err", new Error("Ce routeur a déjà servi : cochez d'abord la confirmation qu'il peut être entièrement effacé.")); return; }
    var rep = replaceOf();
    if (rep && !$("sum-replace-ok").checked) { err("sum-err", new Error("Ce site a déjà un routeur : cochez d'abord la confirmation de son remplacement.")); updateGo(); return; }
    var body = { siteId: siteSel.id, revisionId: chosenRevision(), bench: benchValues() };
    if (used.length) body.confirmWipe = true;
    if (rep) body.confirmReplaceDeviceId = rep.deviceId;
    if (override) { body.deviceModeOverride = true; body.overrideConfirm = overrideText; }
    var stop = startRun(override, id);
    endRun(longApi("POST", "/api/prepare", body, id), stop, id);
  };
  // The outcome of a preparation, drawn on its card's run step — now if that
  // card is shown, otherwise when it is shown again (views[id].runRender).
  function endRun(p, stop, id) {
    id = id === undefined ? cur : id;
    var site = siteSel;
    var settle = function (render) {
      var v = viewOf(id);
      v.runRender = render; v.step = "run";
      running[id] = false; stop();
      if (cur === id) render();
      pollBoard();
    };
    return p.then(function (r) {
      settle(function () {
        show("run-progress", false); show("run-err", false); show("run-blocked", false);
        show("run-ok", true); show("run-actions", true); text("next", "Préparer le routeur suivant");
        show("run-test", !!r.testOverride);
        var c = r.concentrator || {};
        var lc = r.localCheck || {};
        kv("run-kv", [["Site", siteText(site || r.site)], ["Identifiant PPP", r.allocation && r.allocation.ppp_username],
          ["Nom annoncé par le routeur", lc.mndpIdentity || "aucun"], ["Fiche ObliWAN", "équipement n° " + r.deviceId],
          // The card ObliWAN links the mobile line by. "None read" is an
          // answer (no modem, no card), never a reason to hold the box; the
          // note says which, so that "no modem" and "no card" differ.
          ["Carte SIM (ICCID)", r.sim && r.sim.iccid ? r.sim.iccid : (r.simNote ? "aucune lue : " + r.simNote : "aucune lue")]]);
        // The local check is the proof this screen can give: the box came back
        // under its NEW name. Anything less is orange: do not ship it.
        var confirmed = lc.identityMatches === true && lc.lanReachable !== false;
        var ready = confirmed && c.state === "provisioned" && !r.testOverride;
        $("run-mark").className = "big-ok" + (ready ? "" : r.testOverride ? " bad" : " warn"); text("run-mark", ready ? "✓" : "!");
        text("run-title", confirmed ? (r.testOverride ? "TEST — configuration appliquée sur un routeur au mode appareil non conforme" : "Configuration appliquée — vous pouvez débrancher et mettre en carton")
          : "Le routeur n'a pas confirmé : ne l'expédiez pas, appelez un technicien");
        text("run-sub", confirmed
          ? (ready ? "Il apparaîtra comme connecté dans ObliWAN une fois installé chez le client." : "Lisez les avertissements ci-dessous avant de l'expédier.")
          : (lc.mndpIdentity ? "Le routeur s'annonce sous le nom « " + lc.mndpIdentity + " » au lieu de « " + ((r.allocation && r.allocation.system_identity) || "?") + " »." : "Le routeur ne s'est pas annoncé sur ce poste après son redémarrage."));
        var note = $("run-note"); note.textContent = "";
        var cn = document.createElement("div");
        cn.className = c.state === "provisioned" ? "okbox" : "warnbox";
        cn.textContent = (c.state === "provisioned" ? "Accès au concentrateur prêt. "
          : c.state === "pending" ? "Accès au concentrateur PAS ENCORE créé : le routeur ne pourra joindre ObliWAN qu'une fois cet accès créé. "
          : "Accès au concentrateur NON créé. ") + (c.message || "");
        note.appendChild(cn);
        if (lc.identityMatches && lc.lanReachable === false) {
          var nl = document.createElement("div"); nl.className = "warnbox";
          nl.textContent = "Le réseau local du routeur n'a pas répondu depuis ce poste : ne l'expédiez pas, appelez un technicien.";
          note.appendChild(nl);
        }
        if (r.reset === "no-answer") {
          var nr = document.createElement("div"); nr.className = "warnbox";
          nr.textContent = "Le routeur n'a plus répondu après l'ordre de réinitialisation.";
          note.appendChild(nr);
        }
        if (!r.resultRecorded) { var rr = document.createElement("div"); rr.className = "warnbox"; rr.textContent = "Le résultat n'a pas pu être enregistré dans ObliWAN" + (r.resultError ? " (" + r.resultError + ")" : "") + " : signalez-le."; note.appendChild(rr); }
        // The platform's own warnings (they refused nothing): each says who
        // must act and whether the box may be shipped.
        (Array.isArray(r.warnings) ? r.warnings : []).forEach(function (x) { var nw = document.createElement("div"); nw.className = "warnbox"; nw.textContent = x; note.appendChild(nw); });
        found = null; plan = null; override = false; overrideText = "";
      });
    }).catch(function (e) {
      settle(function () {
        show("run-progress", false); show("run-ok", false);
        show("run-err", true); show("run-actions", true); text("run-err-text", e.message); text("next", "Recommencer");
        // A device-mode refusal KEEPS the box: the wizard is offered right here
        // (not on a reopened window, which has lost the plan it would need).
        show("run-blocked", false);
        if (e.body && e.body.blocked && e.body.wizard && plan) {
          show("run-blocked", true);
          $("run-wizard").onclick = function () { openWizard(e.body.blocked.message); };
        }
      });
      gateError(e);
    });
  }

  // ── a window reopened while (or after) an operation ran ───────────────────
  // The application never stops in the middle of an operation on a router;
  // it reopens its window instead. This page then reads what is running, or
  // what ended without anybody seeing it, and shows it on its card.
  var resumed = false;
  function resume() {
    if (resumed) return;
    resumed = true;
    api("GET", "/api/outcome").then(function (r) {
      var o = r.outcome;
      if (!o) { if (cur) loadView(cur); return; }
      if (o.card) cur = o.card;
      watchedOps[o.op] = true;
      if (o.kind === "prepare") { endRun(outcomeOf(o.op), startRun(false, cur), cur); return; }
      var id = cur;
      running[id] = true; goStep("router");
      show("find-progress", true); text($("find-progress").lastChild, "Une opération sur le routeur est en cours…");
      var stop = watchProgress($("find-progress").lastChild, {}, id);
      outcomeOf(o.op).then(function () {
        onCard(id, function () {
          text("resume-note", "L'opération lancée avant la réouverture de cette fenêtre s'est terminée. Relancez la recherche du routeur pour continuer.");
          show("resume-note", true);
        });
      }, function (e) { onCard(id, function () { err("find-err", new Error(e.message + " Relancez la recherche du routeur pour continuer.")); }); })
        .then(function () { stop(); running[id] = false; onCard(id, function () { show("find-progress", false); }); });
    }).catch(function () { /* nothing to resume */ });
  }
  $("next").onclick = function () {
    api("POST", "/api/router/forget", undefined, null, cur).catch(function () {});
    var v = viewOf(cur); v.runRender = null;
    resetRouter(); $("mac").value = ""; $("pw").value = ""; clearPlan(); show("sites", false); $("search").value = ""; show("run-test", false);
    goStep("router"); $("mac").focus();
  };
})();
</script>
</body>
</html>
`;
