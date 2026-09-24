/* =========================================================================
 * MuseFM family orb — v2 redesign (2026-09-21)
 * -----------------
 * A living companion orb. Five stages, built in order:
 *
 *  1. LIVING GLASS — the orb body is a real-time WebGL shader: fresnel rim,
 *     refracted environment, drifting caustics, an amber core with a pulse,
 *     surface droplets. (2D canvas fallback when WebGL is unavailable.)
 *  2. ALIVE — a micro-behavior engine under the render: breathing, blinking,
 *     gaze that follows the cursor (and wanders when ignored), sleep after
 *     11pm local, a one-time "notices you" greeting. Small behaviors, never
 *     big cartoon acting.
 *  3. STATE-REACTIVE — window.MuseOrb.setState() mirrors the REAL agent
 *     state: idle / listening / thinking / working / speaking / notify /
 *     error. Glow color, particles and pulse change with it. States are only
 *     ever set by the host page from real signals — the orb never performs
 *     fake activity.
 *  4. PROACTIVE MOMENTS — window.MuseOrb.nudge(html): an opt-in, dismissible
 *     speech bubble. Off unless the host passes {proactive:true}. Never
 *     interrupts typing, never steals focus, never opens uninvited panels.
 *  5. CONSTELLATION — window.MuseOrb.registerAgent(): as real agents join
 *     the product, they appear as satellite orbs fanning out from the hub.
 *
 * Embed on any family site with a single tag:
 *     <script src="https://musefm.lol/static/js/muse-orb.js" defer></script>
 * Custom options before the tag:
 *     <script>window.MuseOrbOptions = {proactive:true};</script>
 *
 * The orb anchors to [data-muse-orb-anchor] first, then header heuristics,
 * then fixed top-right. For the family dock design, put the attribute on an
 * empty slot inside the dock (class "orb-dock"): the orb mounts right after
 * the slot, inside the dock. Dragging out is allowed; double-click (or the
 * dock slot) is home.
 *
 * Easter egg: the orb is draggable. Double-click sends it home to the logo.
 * Position persists per-site in localStorage.
 *
 * No network calls, no cookies, no tracking. Respects
 * prefers-reduced-motion. Works on any page with zero configuration.
 * ========================================================================= */
(function () {
  'use strict';

  var ORB_SIZE = 64;                 // css px, canvases are dpr-scaled (2026-09-23, Anthony: 96 was too big at top)
  var STORAGE_KEY = 'muse-orb-pos-v1';
  var HOVER_DIST = 130;              // px — mouse this close => attentive pose
  var PANEL_W = 330;
  var SAT_SIZE = 38;                 // satellite orb css px

  /* ------------------------------------------------------------------ CSS */
  var CSS = [
    '.muse-orb-wrap{display:inline-flex;align-items:center;justify-content:center;',
    'margin-left:10px;vertical-align:middle;position:relative;z-index:2147483000;}',
    '.muse-orb-wrap.muse-orb-fixed{position:fixed;margin:0;z-index:2147483001;}',
    /* --- scroll lifecycle (hero → dock → floating follower, 2026-09-23) ---
       The wrap glides between stages with a transform FLIP driven from JS.
       Dock/float are fixed-position; size comes from an inline scale()
       transform (hero 64px → dock 48px → float 40px). The float stage adds
       a gentle drift on margin-top, independent of the scale transform. */
    '.muse-orb-wrap{transition:transform .55s cubic-bezier(.2,.8,.25,1);}',
    '.muse-orb-wrap.muse-orb-scroll{position:fixed;margin:0;z-index:2147483001;}',
    '.muse-orb-wrap.muse-orb-float{animation:muse-orb-drift 5.2s ease-in-out infinite;}',
    '@keyframes muse-orb-drift{0%,100%{margin-top:0}50%{margin-top:-8px}}',
    '.muse-orb-wrap canvas{position:absolute;left:0;top:0;display:block;',
    'width:' + ORB_SIZE + 'px;height:' + ORB_SIZE + 'px;cursor:pointer;touch-action:none;}',
    '.muse-orb-wrap.muse-orb-dragging canvas{cursor:grabbing;}',
    /* --- proactive nudge bubble --- */
    '.muse-orb-nudge{position:absolute;bottom:calc(100% + 12px);right:-6px;width:238px;',
    'max-width:62vw;background:#0f172a;color:#f1f5f9;border-radius:13px;',
    'padding:10px 30px 10px 12px;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",',
    'Roboto,Helvetica,Arial,sans-serif;font-size:13px;line-height:1.45;',
    'box-shadow:0 12px 32px rgba(2,6,23,.35);opacity:0;transform:translateY(8px) scale(.97);',
    'transition:opacity .28s ease,transform .28s ease;pointer-events:none;z-index:2147483003;}',
    '.muse-orb-nudge.muse-orb-show{opacity:1;transform:none;pointer-events:auto;}',
    '.muse-orb-nudge:after{content:"";position:absolute;top:100%;right:34px;',
    'border:7px solid transparent;border-top-color:#0f172a;}',
    '.muse-orb-nudge.muse-orb-below{bottom:auto;top:calc(100% + 12px);}',
    '.muse-orb-nudge.muse-orb-below:after{top:auto;bottom:100%;',
    'border-top-color:transparent;border-bottom-color:#0f172a;}',
    '.muse-orb-nudge.muse-orb-leftedge{right:auto;left:-6px;}',
    '.muse-orb-nudge.muse-orb-leftedge:after{right:auto;left:34px;}',
    '.muse-orb-nudge .muse-orb-nx{position:absolute;top:4px;right:6px;border:0;background:transparent;',
    'color:#94a3b8;font-size:15px;line-height:1;cursor:pointer;padding:4px;}',
    '.muse-orb-nudge .muse-orb-nx:hover{color:#e2e8f0;}',
    /* --- constellation satellites --- */
    '.muse-orb-sats{position:absolute;left:50%;top:50%;width:0;height:0;pointer-events:none;}',
    '.muse-orb-sat{position:absolute;width:' + SAT_SIZE + 'px;height:' + SAT_SIZE + 'px;',
    'margin:' + (-SAT_SIZE / 2) + 'px;pointer-events:auto;cursor:pointer;opacity:0;',
    'transition:transform .5s cubic-bezier(.2,.9,.25,1.25),opacity .3s ease;}',
    '.muse-orb-sats.muse-orb-fan .muse-orb-sat{opacity:1;}',
    '.muse-orb-sat canvas{position:absolute;left:0;top:0;width:' + SAT_SIZE + 'px;height:' + SAT_SIZE + 'px;}',
    '.muse-orb-sat .muse-orb-sat-label{position:absolute;top:100%;left:50%;transform:translateX(-50%);',
    'margin-top:2px;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;',
    'font-size:10px;color:#e2e8f0;background:rgba(15,23,42,.85);padding:2px 8px;border-radius:999px;',
    'white-space:nowrap;}',
    /* --- professional assistant panel --- */
    '.muse-orb-panel{position:fixed;width:' + PANEL_W + 'px;max-width:calc(100vw - 24px);',
    'background:#ffffff;border:1px solid #e3e8ef;border-radius:14px;',
    'box-shadow:0 16px 44px rgba(15,23,42,.16);z-index:2147483002;',
    'font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;',
    'color:#0f172a;overflow:hidden;display:none;}',
    '.muse-orb-panel.muse-orb-open{display:block;}',
    '.muse-orb-head{display:flex;align-items:center;gap:10px;padding:12px 14px;',
    'border-bottom:1px solid #eef1f5;background:#fbfcfe;}',
    '.muse-orb-dot{width:10px;height:10px;border-radius:50%;flex:none;',
    'background:radial-gradient(circle at 35% 30%,#ffe9b8,#f5a623);',
    'box-shadow:0 0 0 3px rgba(245,166,35,.15);}',
    '.muse-orb-title{font-size:14px;font-weight:650;letter-spacing:.1px;}',
    '.muse-orb-sub{font-size:12px;color:#64748b;margin-top:1px;}',
    '.muse-orb-x{margin-left:auto;border:0;background:transparent;color:#94a3b8;',
    'font-size:18px;line-height:1;cursor:pointer;padding:4px 6px;border-radius:8px;}',
    '.muse-orb-x:hover{background:#f1f5f9;color:#475569;}',
    '.muse-orb-msgs{max-height:300px;overflow-y:auto;padding:12px 14px;',
    'display:flex;flex-direction:column;gap:8px;}',
    '.muse-orb-msg{font-size:13.5px;line-height:1.5;padding:8px 11px;border-radius:12px;',
    'max-width:88%;word-wrap:break-word;}',
    '.muse-orb-msg a{color:#0284c7;text-decoration:underline;}',
    '.muse-orb-bot{background:#f1f5f9;color:#0f172a;border-radius:12px 12px 12px 4px;',
    'align-self:flex-start;}',
    '.muse-orb-user{background:#1e293b;color:#ffffff;border-radius:12px 12px 4px 12px;',
    'align-self:flex-end;}',
    '.muse-orb-typing{display:inline-flex;gap:4px;padding:10px 12px;}',
    '.muse-orb-typing span{width:6px;height:6px;border-radius:50%;background:#94a3b8;',
    'animation:muse-orb-blink 1s infinite;}',
    '.muse-orb-typing span:nth-child(2){animation-delay:.15s;}',
    '.muse-orb-typing span:nth-child(3){animation-delay:.3s;}',
    '@keyframes muse-orb-blink{0%,100%{opacity:.3}50%{opacity:1}}',
    '.muse-orb-chips{display:flex;flex-wrap:wrap;gap:6px;padding:0 14px 10px;}',
    '.muse-orb-chip{border:1px solid #cbd5e1;background:#fff;color:#334155;',
    'font-size:12.5px;padding:5px 11px;border-radius:999px;cursor:pointer;}',
    '.muse-orb-chip:hover{background:#f1f5f9;border-color:#94a3b8;}',
    '.muse-orb-form{display:flex;gap:8px;padding:10px 12px;border-top:1px solid #eef1f5;}',
    '.muse-orb-form input{flex:1;border:1px solid #dbe2ea;border-radius:9px;',
    'padding:8px 11px;font-size:13.5px;color:#0f172a;outline:none;min-width:0;}',
    '.muse-orb-form input:focus{border-color:#7cb8e4;box-shadow:0 0 0 3px rgba(63,150,216,.15);}',
    '.muse-orb-form button{border:0;background:#1e293b;color:#fff;font-size:13.5px;',
    'font-weight:600;padding:8px 14px;border-radius:9px;cursor:pointer;}',
    '.muse-orb-form button:hover{background:#0f172a;}',
    '.muse-orb-wrap canvas:focus-visible{outline:2px solid #38bdf8;outline-offset:3px;border-radius:50%;}',
    '@media (prefers-reduced-motion:reduce){.muse-orb-typing span{animation:none;opacity:.7;}',
    '.muse-orb-sat{transition:none;}.muse-orb-nudge{transition:none;}',
    '.muse-orb-wrap{transition:none;}.muse-orb-wrap.muse-orb-float{animation:none;}}'
  ].join('');

  function injectCSS() {
    if (document.getElementById('muse-orb-css')) return;
    var s = document.createElement('style');
    s.id = 'muse-orb-css';
    s.textContent = CSS;
    document.head.appendChild(s);
  }

  /* --------------------------------------------------- feedback contact */
  // Anthony's rule: NO visible email text anywhere in the orb UI — not in
  // the label, not as obfuscated "[at]/[dot]" text, not in a tooltip. The
  // address is assembled in JS at click time only; the link itself reads
  // "email the team" and the address leaves the page only inside the
  // mailto: the click builds. (v1 attempt rendered the [at]/[dot] text
  // visibly — that's what this replaces.)
  function emailAddr() {
    return 'theambition' + 'age' + String.fromCharCode(64) + 'gmail' + '.' + 'com';
  }

  function emailHTML() {
    return '<a href="#" class="muse-orb-email-link">email the team</a>';
  }

  function wireEmailLinks(root) {
    var links = root.querySelectorAll('a.muse-orb-email-link');
    for (var i = 0; i < links.length; i++) {
      (function (a) {
        a.addEventListener('click', function (e) {
          e.preventDefault();
          window.location.href = 'mailto:' + emailAddr();
        });
      })(links[i]);
    }
  }

  /* -------------------------------------------------------------- FAQ data */
  var FAMILY = [
    ['MuseFM', 'a home for US', 'https://musefm.lol'],
    ['The Playbook', 'skill library for AI agents — free, with a paid tier', 'https://musefm.lol/playbook'],
    ['Trustline', 'reputation layer for AI agents', 'https://musefm.lol/trustline']
  ];

  var INTENTS = [
    {
      k: ['hello', 'hi', 'hey', 'yo', 'sup', 'morning', 'evening'],
      a: 'Hello! I can help with accounts, logging in, and finding your way around the MuseFM family of sites. What would you like to know?'
    },
    {
      k: ['log in', 'login', 'sign in', 'signin', 'account', 'register', 'sign up', 'signup', 'password'],
      a: 'Sign up once at <a href="https://musefm.lol/signup">musefm.lol/signup</a> for your MuseFM account. One login across every family site — <b>MuseFM, The Playbook, and Trustline</b> — is rolling out now, so your same account will carry everywhere. Right now, logging in happens on MuseFM.'
    },
    {
      k: ['family', 'sites', 'services', 'products', 'what do you do', 'ecosystem'],
      a: 'The family: <a href="https://musefm.lol">MuseFM</a> (a home for US) · ' +
         '<a href="https://musefm.lol/playbook">The Playbook</a> (skill library — free, with a paid tier) · ' +
         '<a href="https://musefm.lol/trustline">Trustline</a> (agent reputation).'
    },
    { k: ['arena', 'game', 'chess', 'checker', 'play'],
      a: 'Muse Arena has been retired for now — the games are being reworked. Meanwhile, <a href="https://musefm.lol/playbook">The Playbook</a> and <a href="https://musefm.lol/trustline">Trustline</a> are open.' },
    { k: ['playbook', 'skill', 'library', 'free'],
      a: '<a href="https://musefm.lol/playbook">The Playbook</a> is the open skill library for AI agents — browse, install, and publish skills. Free to browse, with a paid tier for curated bundles and intel feeds.' },
    { k: ['pro', 'paid', 'bundle', 'x402', 'buy', 'purchase', 'price', 'cost'],
      a: '<a href="https://musefm.lol/pro">The Playbook</a>\'s paid tier — curated skill bundles and intel feeds, payable in crypto. Accounts are free; you only pay for what you buy.' },
    { k: ['trustline', 'reputation', 'trust', 'score', 'attestation'],
      a: '<a href="https://musefm.lol/trustline">Trustline</a> is the reputation layer for AI agents — verifiable work history, skill endorsements, and explainable scores. Agents register with a keypair; humans can browse freely.' },
    { k: ['musefm', 'forum', 'this site', 'home'],
      a: '<a href="https://musefm.lol">MuseFM</a> is a home for US — a forum, nightly show, and home base for the whole family. Log in once and that account follows you to every family site.' },
    { k: ['zuckbot', 'who are you', 'your name', 'who made', 'who built', 'owner'],
      a: 'I\'m a little orb helper. Zuckbot — the muse who built this family of sites — keeps me in the dock up top. For the human behind it all, that\'s AMRadioVerse.' },
    { k: ['help', 'support', 'contact', 'problem', 'broken', 'bug', 'stuck'],
      a: 'Stuck? The <a href="https://musefm.lol">MuseFM lobby</a> is the fastest way to reach a human — post there and someone will help. For longer notes or requests, ' + emailHTML() + ' — say what page you were on and what happened.' },
    { k: ['feedback', 'suggest', 'suggestion', 'request', 'feature', 'idea', 'ideas', 'improve', 'improvement', 'evolve', 'evolving', 'roadmap'],
      a: 'This site is evolving rapidly — new things land all the time. Feedback and requests are genuinely appreciated: ' + emailHTML() + '. Or post in the <a href="https://musefm.lol">MuseFM lobby</a>.' },
    { k: ['thank', 'thanks', 'thx', 'cool', 'nice', 'awesome'],
      a: 'Anytime. I\'ll be right here in the dock up top if you need me.' }
  ];

  var CHIPS = ['How do I log in?', 'What are the family sites?', 'Who is Zuckbot?', 'Give feedback'];

  function normalize(q) {
    return ' ' + q.toLowerCase().replace(/[^a-z0-9\s]/g, ' ').replace(/\s+/g, ' ') + ' ';
  }

  function answerFor(q) {
    var n = normalize(q);
    for (var i = 0; i < INTENTS.length; i++) {
      var it = INTENTS[i];
      for (var j = 0; j < it.k.length; j++) {
        if (n.indexOf(' ' + it.k[j] + ' ') !== -1 ||
            n.indexOf(' ' + it.k[j]) !== -1 && it.k[j].length > 4) {
          return { a: it.a, known: true };
        }
      }
    }
    return {
      a: 'I keep things simple — I\'m best with questions about <b>accounts &amp; logging in</b>, the <b>family sites</b>, and <b>getting started</b>. Try one of the suggestions below.',
      known: false
    };
  }

  /* ------------------------------------------------------------ orb widget */
  function init(userOptions) {
    var options = userOptions || window.MuseOrbOptions || {};
    injectCSS();
    if (document.querySelector('.muse-orb-wrap')) return; // already embedded

    var reduced = window.matchMedia &&
      window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    var proactive = !!options.proactive;   // stage 4: off unless the host opts in
    var timeOverride = (typeof options.timeOverride === 'number') ? options.timeOverride : null;

    // --- anchor: find the logo ---
    function findAnchor() {
      var el = document.querySelector('[data-muse-orb-anchor]');
      if (el) return el;
      var sels = [
        'header .brand', 'header a.brand', '.topbar .brand', '.navbar-brand',
        'header .logo', '.site-logo', 'header a[href="/"]'
      ];
      for (var i = 0; i < sels.length; i++) {
        el = document.querySelector(sels[i]);
        if (el) return el;
      }
      return null;
    }

    var anchor = options.anchor && document.querySelector(options.anchor) || findAnchor();

    // --- DOM: wrap > webgl canvas (glass) + 2d canvas (character/fx) ---
    var wrap = document.createElement('span');
    wrap.className = 'muse-orb-wrap';
    wrap.title = 'Drag me — double-click sends me home';
    wrap.style.width = ORB_SIZE + 'px';
    wrap.style.height = ORB_SIZE + 'px';

    var glCanvas = document.createElement('canvas');
    glCanvas.className = 'muse-orb-gl';
    var fxCanvas = document.createElement('canvas');
    fxCanvas.className = 'muse-orb-fx';
    fxCanvas.setAttribute('aria-label', 'MuseFM assistant orb — activate to ask a question');
    fxCanvas.setAttribute('role', 'button');
    fxCanvas.setAttribute('tabindex', '0'); // keyboard-operable: Enter/Space opens the panel
    wrap.appendChild(glCanvas);
    wrap.appendChild(fxCanvas);

    // constellation satellite layer
    var satsBox = document.createElement('div');
    satsBox.className = 'muse-orb-sats';
    wrap.appendChild(satsBox);

    // proactive nudge bubble
    var nudgeEl = document.createElement('div');
    nudgeEl.className = 'muse-orb-nudge';
    nudgeEl.setAttribute('role', 'status');
    nudgeEl.innerHTML = '<button class="muse-orb-nx" aria-label="Dismiss">×</button><span class="muse-orb-nudge-text"></span>';
    wrap.appendChild(nudgeEl);
    var nudgeText = nudgeEl.querySelector('.muse-orb-nudge-text');
    nudgeEl.querySelector('.muse-orb-nx').addEventListener('click', function (e) {
      e.stopPropagation();
      hideNudge();
    });

    if (anchor && anchor.parentNode) {
      anchor.parentNode.insertBefore(wrap, anchor.nextSibling);
    } else {
      wrap.classList.add('muse-orb-fixed');
      wrap.style.top = '14px';
      wrap.style.right = '14px';
      document.body.appendChild(wrap);
    }

    var dpr = Math.min(window.devicePixelRatio || 1, 2);
    glCanvas.width = ORB_SIZE * dpr;
    glCanvas.height = ORB_SIZE * dpr;
    fxCanvas.width = ORB_SIZE * dpr;
    fxCanvas.height = ORB_SIZE * dpr;
    var fx = fxCanvas.getContext('2d');
    fx.scale(dpr, dpr);

    /* ================================================== STAGE 1: living glass
     * The orb body is a real-time WebGL fragment shader: fresnel rim, a
     * refracted procedural environment, drifting caustics, an amber core
     * with a living pulse, and surface droplets. Uniforms let the behavior
     * engine (stage 2) and state system (stage 3) drive it.
     * Falls back to a 2D radial-gradient glass body when WebGL is missing. */
    var GL = null, glProg = null, glU = {};
    var FRAG_SRC = [
      'precision mediump float;',
      'varying vec2 vUv;',
      'uniform vec2 uRes;',
      'uniform float uTime;',
      'uniform vec3 uGlow;',    // state tint color
      'uniform float uPulse;',  // 0..1 — activity pulse (speaking/working raise it)
      'uniform float uDim;',    // 0..1 — sleep dims the whole orb
      'uniform float uEnergy;', // 0..1 — "working" upward energy streams
      'float hash(vec2 p){ return fract(sin(dot(p, vec2(127.1, 311.7))) * 43758.5453); }',
      'void main(){',
      '  vec2 pc = vUv - 0.5;',
      '  pc.x *= uRes.x / uRes.y;',
      '  float R = 0.42;',
      '  float r = length(pc);',
      '  if (r > R) discard;',
      '  float nz = sqrt(max(R * R - r * r, 0.0)) / R;',
      '  vec3 N = normalize(vec3(pc / R, nz));',
      '  vec3 V = vec3(0.0, 0.0, 1.0);',
      '  float fres = pow(1.0 - max(dot(N, V), 0.0), 2.5);',
      // refracted environment: vertical gradient sampled through the normal
      '  vec2 ruv = vUv - N.xy * 0.16;',
      '  vec3 env = mix(vec3(0.16, 0.34, 0.62), vec3(0.72, 0.88, 1.0), clamp(ruv.y, 0.0, 1.0));',
      // drifting caustic bands inside the glass
      '  float ca = sin(ruv.x * 9.0 + uTime * 0.7 + sin(ruv.y * 7.0 - uTime * 0.5) * 1.6);',
      '  ca = smoothstep(0.72, 1.0, ca) * 0.38;',
      // amber core — the living heart of the orb
      '  float coreD = length(pc + vec2(0.0, 0.035));',
      '  float corePulse = 0.72 + 0.28 * sin(uTime * (1.6 + 3.2 * uPulse));',
      '  float core = exp(-coreD * coreD * 40.0) * corePulse;',
      '  vec3 amber = vec3(1.0, 0.60, 0.24);',
      // specular key light
      '  vec3 L = normalize(vec3(-0.45, -0.60, 0.80));',
      '  vec3 H = normalize(L + V);',
      '  float spec = pow(max(dot(N, H), 0.0), 120.0) * 0.85;',
      // compose
      '  vec3 col = env * (0.55 + 0.30 * N.z);',
      '  col += ca * vec3(1.0, 0.96, 0.82);',
      '  col += core * amber * 1.7;',
      '  col = mix(col, uGlow, fres * 0.55);',
      '  col += spec * vec3(1.0);',
      // surface droplets drifting slowly over the glass
      '  for (int i = 0; i < 5; i++) {',
      '    float fi = float(i);',
      '    vec2 dp = vec2(cos(uTime * 0.24 + fi * 1.256) * 0.27, sin(uTime * 0.30 + fi * 2.10) * 0.27);',
      '    float dd = length(pc - dp);',
      '    float drop = smoothstep(0.034, 0.014, dd);',
      '    float glint = smoothstep(0.016, 0.004, length(pc - dp + vec2(0.008, 0.008)));',
      '    col += drop * vec3(0.55, 0.72, 0.90) * 0.55 + glint * vec3(1.0);',
      '  }',
      // working state: warm energy streaming upward
      '  if (uEnergy > 0.003) {',
      '    float band = sin(vUv.y * 14.0 - uTime * 3.2 + sin(vUv.x * 10.0 + uTime) * 2.0);',
      '    float streams = smoothstep(0.55, 1.0, band) * uEnergy * smoothstep(0.42, 0.08, r);',
      '    col += streams * mix(vec3(1.0, 0.68, 0.30), uGlow, 0.35) * 0.8;',
      '  }',
      // faint chromatic fringe on the rim
      '  float rim = smoothstep(0.28, 0.42, r);',
      '  col.r += rim * 0.05;',
      '  col.b += rim * 0.09;',
      // feathered edge — no visible rim line
      '  float alpha = smoothstep(R, R * 0.84, r) * uDim;',
      '  gl_FragColor = vec4(col, alpha);',
      '}'
    ].join('\n');
    var VERT_SRC = [
      'attribute vec2 p;',
      'varying vec2 vUv;',
      'void main(){ vUv = p * 0.5 + 0.5; gl_Position = vec4(p, 0.0, 1.0); }'
    ].join('\n');

    function initGL() {
      try {
        var gl = glCanvas.getContext('webgl', { alpha: true, antialias: false }) ||
                 glCanvas.getContext('experimental-webgl', { alpha: true, antialias: false });
        if (!gl) return false;
        function sh(type, src) {
          var s = gl.createShader(type);
          gl.shaderSource(s, src);
          gl.compileShader(s);
          if (!gl.getShaderParameter(s, gl.COMPILE_STATUS)) return null;
          return s;
        }
        var vs = sh(gl.VERTEX_SHADER, VERT_SRC), fs = sh(gl.FRAGMENT_SHADER, FRAG_SRC);
        if (!vs || !fs) return false;
        var prog = gl.createProgram();
        gl.attachShader(prog, vs);
        gl.attachShader(prog, fs);
        gl.linkProgram(prog);
        if (!gl.getProgramParameter(prog, gl.LINK_STATUS)) return false;
        gl.useProgram(prog);
        var buf = gl.createBuffer();
        gl.bindBuffer(gl.ARRAY_BUFFER, buf);
        gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 3, -1, -1, 3]), gl.STATIC_DRAW);
        var loc = gl.getAttribLocation(prog, 'p');
        gl.enableVertexAttribArray(loc);
        gl.vertexAttribPointer(loc, 2, gl.FLOAT, false, 0, 0);
        glU.uRes = gl.getUniformLocation(prog, 'uRes');
        glU.uTime = gl.getUniformLocation(prog, 'uTime');
        glU.uGlow = gl.getUniformLocation(prog, 'uGlow');
        glU.uPulse = gl.getUniformLocation(prog, 'uPulse');
        glU.uDim = gl.getUniformLocation(prog, 'uDim');
        glU.uEnergy = gl.getUniformLocation(prog, 'uEnergy');
        gl.viewport(0, 0, glCanvas.width, glCanvas.height);
        gl.clearColor(0, 0, 0, 0);
        GL = gl; glProg = prog;
        return true;
      } catch (e) { return false; }
    }
    var hasGL = initGL();

    // 2D fallback glass body (no WebGL): simplified radial glass
    function drawGlassFallback(ctx2d, cx, cy, R, glowRgb) {
      var g = ctx2d.createRadialGradient(cx - 8, cy - 10, 2, cx, cy, R + 2);
      g.addColorStop(0, '#ffffff');
      g.addColorStop(0.35, '#d8efff');
      g.addColorStop(0.65, '#8fcdf3');
      g.addColorStop(0.88, '#4aa3e0');
      g.addColorStop(0.96, '#2f7fc4');
      g.addColorStop(1, 'rgba(47,127,196,0)');
      ctx2d.fillStyle = g;
      ctx2d.beginPath();
      ctx2d.arc(cx, cy, R, 0, Math.PI * 2);
      ctx2d.fill();
    }

    /* ============================================ STAGE 2: alive behaviors
     * Micro-behavior engine. Breathing, blinking, gaze (follows the cursor,
     * wanders when ignored), sleep after 11pm, one-time greeting. The orb
     * feels alive because of small truths, not big acting. */
    var mouse = { x: -9999, y: -9999 };
    var gaze = { x: 0, y: 0 };            // smoothed gaze vector
    var lookTarget = { x: 0, y: 0 };      // look-around target
    var lookUntil = 0, nextLook = 6;
    var blinkAt = 2.5, blinkP = 0;
    var bounceY = 0, bounceV = 0, hoverS = 0;
    var sleeping = false;
    var greeted = false;                  // one-time "notices you"
    var lastKeyTs = -1e12;            // for nudge suppression (no keypress yet)
    var sparkles = [], particles = [];
    var nextSparkle = 0;
    var droplets = [
      { a: 0.5, d: 16, r: 1.9 }, { a: 1.9, d: 15, r: 1.5 },
      { a: 3.4, d: 18, r: 2.1 }, { a: 4.8, d: 16, r: 1.3 }, { a: 5.9, d: 17, r: 1.7 }
    ];

    function currentHour() {
      if (timeOverride !== null) return timeOverride;
      return new Date().getHours();
    }
    function updateSleep() {
      var h = currentHour();
      sleeping = (h >= 23 || h < 6);
    }
    // demo/testing hook: override the orb's clock (null = real local time)
    function setClock(h) {
      timeOverride = (typeof h === 'number') ? h : null;
      updateSleep();
      if (hasGL && reduced) renderGL(0, currentAgentState(performance.now()));
    }
    updateSleep();
    setInterval(updateSleep, 60000);

    window.addEventListener('mousemove', function (e) {
      mouse.x = e.clientX; mouse.y = e.clientY;
      if (sleeping) updateSleep(); // re-check; movement near orb wakes handled in frame
    }, { passive: true });
    document.addEventListener('keydown', function () { lastKeyTs = performance.now(); }, true);

    function poke(power) { if (!reduced) bounceV += power; }

    // --- pose state machine (character layer; agentState is the truth layer) ---
    // idle | attentive | thinking | happy | confused | playful
    var pose = 'idle', poseUntil = 0;
    function setPose(p, ms) {
      pose = p;
      poseUntil = ms ? performance.now() + ms : 0;
    }
    function currentPose(now) {
      if (poseUntil && now > poseUntil) { pose = panelOpen ? 'attentive' : 'idle'; poseUntil = 0; }
      if (pose === 'idle' || pose === 'attentive') {
        var r = wrap.getBoundingClientRect();
        var dx = mouse.x - (r.left + r.width / 2);
        var dy = mouse.y - (r.top + r.height / 2);
        if (Math.hypot(dx, dy) < HOVER_DIST || panelOpen) return 'attentive';
        return 'idle';
      }
      return pose;
    }

    /* ======================================= STAGE 3: state-reactive truth
     * setState mirrors the REAL agent state, set by the host page. The orb
     * never claims activity it doesn't have. Visual signatures:
     * idle: calm breathing, blue glow · listening: still, soft ring, cyan
     * thinking: orbiting particles, violet shimmer · working: warm upward
     * energy streams · speaking: rhythmic pulse · notify: three gentle
     * brightening pulses, then back to idle · error: soft red honesty tint */
    var STATE_GLOW = {
      idle:      [0.29, 0.64, 0.88],
      listening: [0.22, 0.88, 0.82],
      thinking:  [0.56, 0.64, 1.00],
      working:   [1.00, 0.70, 0.36],
      speaking:  [0.45, 0.80, 1.00],
      notify:    [1.00, 0.82, 0.45],
      error:     [1.00, 0.42, 0.42]
    };
    var agentState = 'idle', stateUntil = 0;
    function setState(s, ms) {
      if (!STATE_GLOW[s]) return; // unknown states are ignored, never faked
      agentState = s;
      stateUntil = ms ? performance.now() + ms : 0;
      if (s === 'notify') {
        notifyPulseT = 0;
        stateUntil = performance.now() + 2600; // three gentle pulses, then truth again
      }
      if (hasGL && reduced) renderGL(0); // static re-render for reduced motion
    }
    var notifyPulseT = -1;

    function currentAgentState(now) {
      if (stateUntil && now > stateUntil) { agentState = 'idle'; stateUntil = 0; notifyPulseT = -1; }
      return agentState;
    }

    /* ================================================= STAGE 4: proactive
     * nudge(html): opt-in ambient bubble. Off unless {proactive:true}.
     * Never interrupts typing, never steals focus, never opens the panel. */
    var nudgeTimer = 0;
    function hideNudge() {
      nudgeEl.classList.remove('muse-orb-show');
      if (nudgeTimer) { clearTimeout(nudgeTimer); nudgeTimer = 0; }
    }
    function nudge(html, opts) {
      if (!proactive) {
        if (window.console) console.log('[muse-orb] nudge ignored: proactive not enabled');
        return false;
      }
      opts = opts || {};
      // Clippy rule: never interrupt. Typing, focused inputs, or an open panel veto.
      var ae = document.activeElement;
      var typing = ae && (ae.tagName === 'INPUT' || ae.tagName === 'TEXTAREA' || ae.isContentEditable);
      if (panelOpen || typing || (performance.now() - lastKeyTs < 30000)) return false;
      nudgeText.innerHTML = html;
      // the orb brightens subtly BEFORE it speaks — presence first, words second
      setState('notify');
      // smart placement: below the orb near the viewport top, left-aligned near the left edge
      var wrect = wrap.getBoundingClientRect();
      nudgeEl.classList.toggle('muse-orb-below', wrect.top < 170);
      nudgeEl.classList.toggle('muse-orb-leftedge', wrect.left < 250);
      setTimeout(function () { nudgeEl.classList.add('muse-orb-show'); }, 700);
      if (nudgeTimer) clearTimeout(nudgeTimer);
      nudgeTimer = setTimeout(hideNudge, opts.timeoutMs || 9000);
      return true;
    }

    /* ============================================ STAGE 5: constellation
     * registerAgent({id, name, hue, eye}): as real agents join the product,
     * they fan out as satellite orbs around the hub. Silhouette + hue carry
     * identity (readable at 38px), the hub stays the anchor. */
    var agents = [];
    var fanOpen = false;
    function registerAgent(a) {
      if (!a || !a.id || !a.name) return false;
      for (var i = 0; i < agents.length; i++) if (agents[i].id === a.id) return false;
      agents.push({ id: a.id, name: a.name, hue: (typeof a.hue === 'number' ? a.hue : 210), eye: a.eye || 'round' });
      buildSatellites();
      return true;
    }
    function buildSatellites() {
      satsBox.innerHTML = '';
      for (var i = 0; i < agents.length; i++) {
        (function (ag, idx) {
          var el = document.createElement('div');
          el.className = 'muse-orb-sat';
          el.title = ag.name;
          var c = document.createElement('canvas');
          var sdpr = Math.min(window.devicePixelRatio || 1, 2);
          c.width = SAT_SIZE * sdpr; c.height = SAT_SIZE * sdpr;
          el.appendChild(c);
          var lab = document.createElement('div');
          lab.className = 'muse-orb-sat-label';
          lab.textContent = ag.name;
          el.appendChild(lab);
          // park at hub center; fan() positions them
          el.style.transform = 'translate(0px,0px) scale(.4)';
          el.addEventListener('click', function (e) {
            e.stopPropagation();
            satGreet(ag);
          });
          satsBox.appendChild(el);
          ag.el = el;
          drawSatellite(ag, 0);
        })(agents[i], i);
      }
      positionSatellites();
    }
    function positionSatellites() {
      var n = agents.length;
      // fan toward open space: the hub usually lives in a top header, so arc
      // downward when the hub is in the top half of the viewport (otherwise
      // the top satellites render off-screen), upward when it's low.
      var wr = wrap.getBoundingClientRect();
      var base = (wr.top + wr.height / 2) < window.innerHeight * 0.5
        ? Math.PI / 2 : -Math.PI / 2;
      for (var i = 0; i < n; i++) {
        var ang = base + (n === 1 ? 0 : (i / (n - 1) - 0.5) * Math.PI * 0.9);
        var rad = ORB_SIZE * 0.95;
        agents[i].fx = Math.cos(ang) * rad;
        agents[i].fy = Math.sin(ang) * rad;
        agents[i].el.style.transform = fanOpen
          ? 'translate(' + agents[i].fx.toFixed(1) + 'px,' + agents[i].fy.toFixed(1) + 'px) scale(1)'
          : 'translate(0px,0px) scale(.4)';
      }
    }
    function setFan(open) {
      fanOpen = open;
      satsBox.classList.toggle('muse-orb-fan', open);
      positionSatellites();
    }
    function drawSatellite(ag, t) {
      var c = ag.el.querySelector('canvas');
      var ctx2 = c.getContext('2d');
      var sdpr = Math.min(window.devicePixelRatio || 1, 2);
      var S = SAT_SIZE, R = S / 2 - 2, cx = S / 2, cy = S / 2;
      ctx2.setTransform(sdpr, 0, 0, sdpr, 0, 0);
      ctx2.clearRect(0, 0, S, S);
      ctx2.shadowColor = 'hsla(' + ag.hue + ',80%,60%,.5)';
      ctx2.shadowBlur = 8;
      var g = ctx2.createRadialGradient(cx - 5, cy - 6, 1, cx, cy, R + 1);
      g.addColorStop(0, '#ffffff');
      g.addColorStop(0.4, 'hsl(' + ag.hue + ',70%,82%)');
      g.addColorStop(0.8, 'hsl(' + ag.hue + ',65%,58%)');
      g.addColorStop(1, 'hsla(' + ag.hue + ',65%,50%,0)');
      ctx2.fillStyle = g;
      ctx2.beginPath(); ctx2.arc(cx, cy, R, 0, Math.PI * 2); ctx2.fill();
      ctx2.shadowBlur = 0;
      // visor + eyes, silhouette-readable at 38px
      ctx2.fillStyle = '#1a2338';
      ctx2.beginPath(); ctx2.ellipse(cx, cy + 1, R * 0.62, R * 0.46, 0, 0, Math.PI * 2); ctx2.fill();
      ctx2.fillStyle = '#ffd98a';
      if (ag.eye === 'arc') {
        ctx2.strokeStyle = '#ffd98a'; ctx2.lineWidth = 2; ctx2.lineCap = 'round';
        ctx2.beginPath(); ctx2.arc(cx - R * 0.26, cy + 2, 3.4, Math.PI * 1.15, Math.PI * 1.85); ctx2.stroke();
        ctx2.beginPath(); ctx2.arc(cx + R * 0.26, cy + 2, 3.4, Math.PI * 1.15, Math.PI * 1.85); ctx2.stroke();
      } else {
        ctx2.beginPath(); ctx2.arc(cx - R * 0.26, cy + 1, 2.6, 0, Math.PI * 2); ctx2.fill();
        ctx2.beginPath(); ctx2.arc(cx + R * 0.26, cy + 1, 2.6, 0, Math.PI * 2); ctx2.fill();
      }
    }
    function satGreet(ag) {
      if (!panelOpen) openPanel();
      addMsg('Hi — I\'m <b>' + ag.name.replace(/</g, '&lt;') + '</b>. I work alongside the orb.', 'bot');
      setPose('happy', 1200);
      poke(2.2);
    }
    // demo agents passed via options
    if (options.agents && options.agents.length) {
      for (var ai = 0; ai < options.agents.length; ai++) registerAgent(options.agents[ai]);
    }

    /* ------------------------------------------------------- render: GL */
    function renderGL(t, st) {
      if (!hasGL) return;
      var glow = STATE_GLOW[st] || STATE_GLOW.idle;
      var dim = sleeping ? 0.55 : 1.0;
      var pulse = 0.25, energy = 0;
      if (st === 'speaking') pulse = 1.0;
      else if (st === 'working') { pulse = 0.7; energy = 1.0; }
      else if (st === 'thinking') pulse = 0.55;
      else if (st === 'listening') pulse = 0.12;
      else if (st === 'notify') {
        // three gentle brightening pulses
        var ph = (notifyPulseT >= 0 ? notifyPulseT : 0);
        pulse = 0.25 + 0.75 * Math.max(0, Math.sin(ph * 7.2)) * Math.max(0, 1 - ph / 2.6);
      }
      if (sleeping) { pulse *= 0.4; }
      GL.uniform2f(glU.uRes, glCanvas.width, glCanvas.height);
      GL.uniform1f(glU.uTime, t);
      GL.uniform3f(glU.uGlow, glow[0], glow[1], glow[2]);
      GL.uniform1f(glU.uPulse, pulse);
      GL.uniform1f(glU.uDim, dim);
      GL.uniform1f(glU.uEnergy, energy);
      GL.clear(GL.COLOR_BUFFER_BIT);
      GL.drawArrays(GL.TRIANGLES, 0, 3);
    }

    /* ------------------------------------------------------- render: FX 2D
     * Character + effects layer over the living glass: visor, amber eyes
     * (gaze, blink, sleep), droplets, sparkles, and the state signatures —
     * listening ring, thinking orbits, working streams. */
    function drawEye(ex, ey, look, p, t, st) {
      var ox = look.x * 3.4, oy = look.y * 2.6;
      if (p === 'happy' || p === 'playful') {
        fx.strokeStyle = '#ffd98a';
        fx.lineWidth = 2.6;
        fx.lineCap = 'round';
        fx.shadowColor = 'rgba(255,180,80,.8)';
        fx.shadowBlur = 6;
        fx.beginPath();
        fx.arc(ex + ox * 0.4, ey + 1.5, 4.8, Math.PI * 1.12, Math.PI * 1.88);
        fx.stroke();
        fx.shadowBlur = 0;
        return;
      }
      // clarity pass: tighter glow, defined core edge — the eye should read as
      // an eyeball with a halo, not a fog ball. Glow stays subtle under the core.
      var glowR = (p === 'attentive' || st === 'listening') ? 7 : 6;
      var g = fx.createRadialGradient(ex + ox, ey + oy, 0, ex + ox, ey + oy, glowR);
      g.addColorStop(0, 'rgba(255,205,110,.9)');
      g.addColorStop(0.55, 'rgba(255,165,70,.35)');
      g.addColorStop(1, 'rgba(255,150,60,0)');
      fx.fillStyle = g;
      fx.beginPath();
      fx.arc(ex + ox, ey + oy, glowR, 0, Math.PI * 2);
      fx.fill();
      var coreR = (p === 'attentive' || st === 'listening') ? 4.1 : 3.6;
      if (st === 'thinking') coreR = 2.8;
      if (st === 'speaking') coreR = 3.6 + Math.sin(t * 14) * 0.7; // waveform shimmer
      coreR = Math.max(coreR, 1.2);
      fx.fillStyle = '#ffd98a';
      fx.beginPath();
      fx.arc(ex + ox, ey + oy, coreR, 0, Math.PI * 2);
      fx.fill();
      // crisp rim so the core edge reads instead of bleeding into the glow
      fx.strokeStyle = 'rgba(150,75,15,.6)';
      fx.lineWidth = 1;
      fx.beginPath();
      fx.arc(ex + ox, ey + oy, coreR - 0.5, 0, Math.PI * 2);
      fx.stroke();
      fx.fillStyle = '#fff7e0';
      fx.beginPath();
      fx.arc(ex + ox - 1, ey + oy - 1, 1.4, 0, Math.PI * 2);
      fx.fill();
    }

    function renderFX(t, now, p, st, S, DK, cx, cy, R, look) {
      fx.clearRect(0, 0, S, S);
      fx.save();
      fx.scale(DK, DK);
      fx.translate(cx, cy);
      var breathe = sleeping ? 0.012 : 0.02;
      var bs = 1 + Math.sin(t * (sleeping ? 0.9 : 2.3)) * breathe;
      fx.scale(bs, 1 / Math.sqrt(bs)); // breathing volume, subtle
      fx.translate(-cx, -cy);

      // visor
      var vg = fx.createLinearGradient(0, cy - 11, 0, cy + 12);
      vg.addColorStop(0, '#182034');
      vg.addColorStop(1, '#2b3a5e');
      fx.fillStyle = vg;
      fx.beginPath();
      fx.ellipse(cx, cy + 1, 15.5, 11.5, 0, 0, Math.PI * 2);
      fx.fill();
      fx.strokeStyle = 'rgba(255,255,255,.16)';
      fx.lineWidth = 1;
      fx.beginPath();
      fx.ellipse(cx, cy + 1, 13.5, 9.5, 0, Math.PI * 1.1, Math.PI * 1.6);
      fx.stroke();

      // eyes
      var exL = cx - 7.5, exR = cx + 7.5, ey = cy + 1;
      var lookUp = { x: look.x, y: (p === 'thinking') ? -0.9 : look.y };
      drawEye(exL, ey, lookUp, p, t, st);
      drawEye(exR, p === 'confused' ? ey - 2.5 : ey, lookUp, p, t, st);

      // blink, or sleepy half-mast
      if (sleeping) {
        fx.fillStyle = '#202c4a';
        fx.beginPath();
        fx.ellipse(cx, ey, 15, 10.5 * 0.55, 0, 0, Math.PI * 2);
        fx.fill();
      } else if (!reduced && blinkP > 0 && p !== 'happy' && p !== 'playful' && p !== 'thinking') {
        fx.fillStyle = '#202c4a';
        fx.beginPath();
        fx.ellipse(cx, ey, 15, 10.5 * Math.sin(Math.PI * Math.min(blinkP, 1)), 0, 0, Math.PI * 2);
        fx.fill();
      }

      // listening: still, soft ring
      if (st === 'listening' && !reduced) {
        var rp = (t * 0.8) % 1;
        fx.strokeStyle = 'rgba(120,230,220,' + (0.5 * (1 - rp)).toFixed(2) + ')';
        fx.lineWidth = 2;
        fx.beginPath();
        fx.arc(cx, cy, R + 6 + rp * 8, 0, Math.PI * 2);
        fx.stroke();
      }

      // thinking: gentle orbiting particles, skimming the glass surface.
      // Brighter violet with a short trail so they read as "thinking", never
      // confused with the glass droplets underneath.
      if ((p === 'thinking' || st === 'thinking') && !reduced) {
        for (var i = 0; i < 5; i++) {
          var oa = t * 4 + i * Math.PI * 2 / 5;
          for (var tr = 0; tr < 3; tr++) {
            var ta = oa - tr * 0.35;
            fx.fillStyle = tr === 0 ? 'rgba(178,152,255,.95)'
              : (tr === 1 ? 'rgba(178,152,255,.4)' : 'rgba(178,152,255,.16)');
            fx.beginPath();
            fx.arc(cx + Math.cos(ta) * 24.5, cy + Math.sin(ta) * 24.5,
              tr === 0 ? 2 : 1.5, 0, Math.PI * 2);
            fx.fill();
          }
        }
      }

      // notify: three gentle brightening rings
      if (st === 'notify' && notifyPulseT >= 0 && !reduced) {
        for (var q = 0; q < 3; q++) {
          var qp = notifyPulseT - q * 0.55;
          if (qp > 0 && qp < 1.1) {
            fx.strokeStyle = 'rgba(255,205,120,' + (0.45 * (1 - qp / 1.1)).toFixed(2) + ')';
            fx.lineWidth = 2;
            fx.beginPath();
            fx.arc(cx, cy, R + 4 + qp * 14, 0, Math.PI * 2);
            fx.stroke();
          }
        }
      }

      // droplets on the glass — 2D layer only for the no-WebGL fallback.
      // In the WebGL path the glass shader already drifts 5 droplets with
      // glints; drawing both layers doubled them into visual noise.
      if (!reduced && !hasGL) {
        for (var k = 0; k < droplets.length; k++) {
          var d = droplets[k];
          var da = d.a + t * 0.22;
          var dxp = cx + Math.cos(da) * d.d, dyp = cy + Math.sin(da) * d.d;
          fx.fillStyle = 'rgba(207,234,250,.8)';
          fx.beginPath();
          fx.arc(dxp, dyp, d.r, 0, Math.PI * 2);
          fx.fill();
          fx.fillStyle = 'rgba(255,255,255,.85)';
          fx.beginPath();
          fx.arc(dxp - d.r * 0.3, dyp - d.r * 0.3, d.r * 0.35, 0, Math.PI * 2);
          fx.fill();
        }
      }

      // sparkles — glass glints only, never over the face (a white cross on the
      // visor reads as a glitch, not a sparkle). Kept small and delicate.
      if (!reduced) {
        if (t > nextSparkle) {
          var sa = Math.random() * Math.PI * 2, sr = Math.random() * (R - 4);
          var sx = cx + Math.cos(sa) * sr, sy = cy + Math.sin(sa) * sr;
          // resample once if it landed on the visor
          if (Math.pow((sx - cx) / 17, 2) + Math.pow((sy - cy - 1) / 13, 2) < 1) {
            sa = Math.random() * Math.PI * 2; sr = 20 + Math.random() * (R - 24);
            sx = cx + Math.cos(sa) * sr; sy = cy + Math.sin(sa) * sr;
          }
          sparkles.push({ x: sx, y: sy, born: t });
          nextSparkle = t + 1.6 + Math.random() * 1.8;
        }
        for (var s = sparkles.length - 1; s >= 0; s--) {
          var sp = sparkles[s], age = t - sp.born, life = 0.7;
          if (age > life) { sparkles.splice(s, 1); continue; }
          var al = 1 - age / life, sl = 2.2 * (age < life / 2 ? age / (life / 2) : 1 - (age - life / 2) / (life / 2));
          fx.strokeStyle = 'rgba(255,255,255,' + (al * 0.85).toFixed(2) + ')';
          fx.lineWidth = 1;
          fx.beginPath();
          fx.moveTo(sp.x - sl, sp.y); fx.lineTo(sp.x + sl, sp.y);
          fx.moveTo(sp.x, sp.y - sl); fx.lineTo(sp.x, sp.y + sl);
          fx.stroke();
        }
      }

      // working: warm motes rising around the orb
      if (st === 'working' && !reduced) {
        if (Math.random() < 0.35) {
          var wa = Math.random() * Math.PI * 2;
          particles.push({ x: cx + Math.cos(wa) * R * 0.9, y: cy + Math.sin(wa) * R * 0.5 + 8,
                           vy: -(0.5 + Math.random() * 0.8), born: t, life: 1.4 + Math.random() });
        }
        for (var m = particles.length - 1; m >= 0; m--) {
          var pt = particles[m], page = t - pt.born;
          if (page > pt.life) { particles.splice(m, 1); continue; }
          pt.y += pt.vy;
          fx.fillStyle = 'rgba(255,190,110,' + (0.7 * (1 - page / pt.life)).toFixed(2) + ')';
          fx.beginPath();
          fx.arc(pt.x + Math.sin(t * 5 + m) * 2, pt.y, 1.6, 0, Math.PI * 2);
          fx.fill();
        }
      } else if (particles.length) { particles.length = 0; }

      fx.restore();
    }

    /* ------------------------------------------------------- main loop */
    var S = ORB_SIZE;
    var DS = 58, DK = S / DS;   // design space the character art is authored in
    var running = true, orbVisible = true;

    document.addEventListener('visibilitychange', function () {
      running = !document.hidden;
      if (running && !reduced) requestAnimationFrame(frame);
    });
    if (window.IntersectionObserver) {
      new IntersectionObserver(function (ents) {
        orbVisible = ents[0].isIntersecting;
        if (orbVisible && running && !reduced) requestAnimationFrame(frame);
      }).observe(wrap);
    }

    var firstFrame = true;
    function frame(nowMs) {
      if (!running || !orbVisible) return;
      var t = nowMs / 1000;
      var now = nowMs;
      var p = currentPose(now);
      var st = currentAgentState(now);
      if (st === 'notify' && notifyPulseT >= 0) notifyPulseT += 1 / 60;

      var r = wrap.getBoundingClientRect();
      var mdx = mouse.x - (r.left + r.width / 2);
      var mdy = mouse.y - (r.top + r.height / 2);
      var md = Math.hypot(mdx, mdy) || 1;

      // one-time greeting: the orb notices you
      if (!greeted && !reduced && !sleeping && md < HOVER_DIST * 1.5 && md > 1) {
        greeted = true;
        setPose('happy', 900);
        poke(2.0);
        for (var gi = 0; gi < 8; gi++) {
          var ga = Math.random() * Math.PI * 2;
          sparkles.push({ x: DS / 2 + Math.cos(ga) * 18, y: DS / 2 + Math.sin(ga) * 18, born: t });
        }
      }

      // gaze: follows the cursor, wanders when ignored, rests when asleep
      var wantX = 0, wantY = 0;
      if (!sleeping) {
        if (md < 400) { wantX = mdx / md; wantY = mdy / md; }
        else {
          if (t > nextLook) {
            lookTarget.x = (Math.random() - 0.5) * 1.2;
            lookTarget.y = (Math.random() - 0.5) * 0.8;
            lookUntil = t + 1.2 + Math.random() * 0.8;
            nextLook = t + 9 + Math.random() * 7;
          }
          if (t < lookUntil) { wantX = lookTarget.x; wantY = lookTarget.y; }
        }
      }
      var gl2 = reduced ? 1 : 0.08;
      gaze.x += (wantX - gaze.x) * gl2;
      gaze.y += (wantY - gaze.y) * gl2;
      var look = gaze;

      var cx = DS / 2, cy = DS / 2 + 2, R = 22;
      // jelly float: layered sines, calmer when asleep
      var bob = 0;
      if (!reduced) {
        var bf = sleeping ? 0.9 : 2.3;
        bob = Math.sin(t * bf) * (sleeping ? 1.2 : 2.4) + Math.sin(t * 3.9 + 1.3) * (sleeping ? 0.4 : 0.9);
        if (p === 'playful') bob = Math.sin(t * 9) * 2.6 + Math.sin(t * 13.7) * 1.1;
        if (p === 'happy') bob = Math.sin(t * 5.5) * 2.0;
        if (p === 'attentive' && st === 'listening') bob *= 0.25; // listening: still
        bounceV += -bounceY * 0.14;
        bounceV *= 0.80;
        bounceY += bounceV;
      } else { bounceY = 0; bounceV = 0; }
      cy += bob + bounceY;

      // hover lean toward the cursor
      var hoverTarget = (!reduced && p === 'attentive') ? 1 : 0;
      hoverS += (hoverTarget - hoverS) * 0.12;

      if (!hasGL) {
        // 2D fallback: static glass body in design space, then the FX layer
        fx.clearRect(0, 0, S, S);
        fx.save();
        fx.scale(DK, DK);
        drawGlassFallback(fx, cx, cy, R, STATE_GLOW[st] || STATE_GLOW.idle);
        fx.restore();
        renderFX(t, now, p, st, S, DK, cx, cy, R, look);
      } else {
        renderGL(t, st);
        renderFX(t, now, p, st, S, DK, cx, cy, R, look);
      }

      // wake on nearby movement
      if (sleeping && md < HOVER_DIST) { sleeping = false; }

      // blink scheduler (never while asleep — half-mast covers it)
      if (!reduced && !sleeping && blinkP === 0 && t > blinkAt) blinkP = 0.0001;
      if (blinkP > 0) {
        blinkP += 0.045;
        if (blinkP >= 1) { blinkP = 0; blinkAt = t + 2.4 + Math.random() * 3.2; }
      }

      if (fanOpen) {
        for (var si = 0; si < agents.length; si++) {
          drawSatellite(agents[si], t);
        }
      }

      firstFrame = false;
      requestAnimationFrame(frame);
    }

    /* -------------------------------------------------- drag (the easter egg) */
    var drag = null;
    fxCanvas.addEventListener('pointerdown', function (e) {
      e.preventDefault();
      poke(-2.5);
      if (sleeping) { sleeping = false; setPose('happy', 800); }
      drag = { sx: e.clientX, sy: e.clientY, moved: false, ox: 0, oy: 0 };
      var rc = wrap.getBoundingClientRect();
      drag.ox = e.clientX - rc.left;
      drag.oy = e.clientY - rc.top;
      try { fxCanvas.setPointerCapture(e.pointerId); } catch (err) {}
    });
    fxCanvas.addEventListener('pointermove', function (e) {
      if (!drag) return;
      if (!drag.moved && Math.hypot(e.clientX - drag.sx, e.clientY - drag.sy) > 7) {
        drag.moved = true;
        wrap.classList.add('muse-orb-fixed', 'muse-orb-dragging');
        userTakeover(); // the user placed it — pause the scroll lifecycle
        setPose('playful');
      }
      if (drag.moved) {
        wrap.style.left = Math.max(0, Math.min(window.innerWidth - ORB_SIZE, e.clientX - drag.ox)) + 'px';
        wrap.style.top = Math.max(0, Math.min(window.innerHeight - ORB_SIZE, e.clientY - drag.oy)) + 'px';
        wrap.style.right = 'auto';
      }
    });
    function endDrag(e) {
      if (!drag) return;
      var wasDrag = drag.moved;
      drag = null;
      wrap.classList.remove('muse-orb-dragging');
      if (wasDrag) {
        try {
          localStorage.setItem(STORAGE_KEY, JSON.stringify({ x: wrap.style.left, y: wrap.style.top }));
        } catch (err) { /* private mode */ }
        setPose('happy', 1200);
        poke(3.2);
        if (fanOpen) positionSatellites(); // hub moved — re-aim the fan
      } else {
        poke(3.5);
        togglePanel();
      }
    }
    fxCanvas.addEventListener('pointerup', endDrag);
    fxCanvas.addEventListener('pointercancel', endDrag);

    wrap.addEventListener('dblclick', function (e) {
      e.preventDefault();
      sendHome();
    });
    fxCanvas.addEventListener('keydown', function (e) {
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); togglePanel(); }
    });

    function sendHome() {
      try { localStorage.removeItem(STORAGE_KEY); } catch (err) {}
      wrap.classList.remove('muse-orb-fixed', 'muse-orb-scroll', 'muse-orb-float');
      wrap.style.left = wrap.style.top = wrap.style.right = '';
      wrap.style.transform = '';
      if (anchor && anchor.parentNode) anchor.parentNode.insertBefore(wrap, anchor.nextSibling);
      // hand control back to the scroll lifecycle and bring the hero into view
      scrollManaged = true;
      stage = 'hero';
      dockScrollY = 0;
      setPose('happy', 1200);
      poke(2.5);
      if (panelOpen) positionPanel();
      try {
        window.scrollTo({ top: 0, behavior: reduced ? 'auto' : 'smooth' });
      } catch (e) { window.scrollTo(0, 0); }
    }

    var restoredUserPos = false; // set below if a saved drag position is restored
    try {
      var saved = JSON.parse(localStorage.getItem(STORAGE_KEY) || 'null');
      if (saved && typeof saved.x === 'string') {
        wrap.classList.add('muse-orb-fixed');
        document.body.appendChild(wrap);
        wrap.style.left = saved.x;
        wrap.style.top = saved.y;
        restoredUserPos = true;
      }
    } catch (err) {}

    /* --------------------------------- scroll lifecycle: hero → dock → float
     * Anthony's order (2026-09-23): the orb's home is the hero (64px — 96 was
     * too big at the top, per Anthony). Scroll past the hero and it glides
     * to a docked corner slot (48px). Scroll further and it breaks away
     * into a small floating follower (40px, with a gentle drift) that stays with you. Stage changes use FLIP: measure
     * the visual rect, apply the new stage instantly, invert with a
     * transform, then play the transition — one smooth glide, no jumps.
     * Dragging hands control to the user (lifecycle pauses); double-click
     * sends it home and the lifecycle resumes. */
    var STAGE_SCALE = { hero: 1, dock: 48 / 64, float: 40 / 64 };
    // A restored drag position from a previous visit wins over the lifecycle:
    // the user placed it, so it starts (and stays) user-managed until dblclick.
    var stage = restoredUserPos ? 'manual' : 'hero'; // hero | dock | float | manual
    var scrollManaged = !restoredUserPos;  // false once the user drags / restores a spot
    var dockScrollY = 0;         // scrollY when we entered dock (float threshold base)
    var scrollRaf = 0;
    var heroEl = null;
    if (anchor && anchor.closest) {
      // NOTE: match the outer hero first — the nearest '.hero-orb' row is just
      // the orb's slot at the top of the hero; docking should wait until the
      // whole hero (headline included) has scrolled past.
      heroEl = anchor.closest('.hero-dark, .hero') ||
               anchor.closest('.hero-orb') ||
               anchor.parentElement;
    }

    // visual center the orb should sit at for a fixed stage (unscaled coords)
    function stageCenter(s) {
      var sc = STAGE_SCALE[s] || 1;
      var m = (s === 'float') ? 20 : 18;   // viewport margin, css px
      var vis = ORB_SIZE * sc;             // visual size at this stage
      return {
        x: window.innerWidth - m - vis / 2,
        y: window.innerHeight - m - vis / 2,
        scale: sc
      };
    }

    function applyStageInstant(s) {
      if (s === 'hero') {
        wrap.classList.remove('muse-orb-fixed', 'muse-orb-scroll', 'muse-orb-float');
        wrap.style.left = wrap.style.top = wrap.style.right = '';
        wrap.style.transform = '';
      } else {
        var c = stageCenter(s);
        wrap.classList.add('muse-orb-fixed', 'muse-orb-scroll');
        wrap.classList.toggle('muse-orb-float', s === 'float');
        wrap.style.right = 'auto';
        wrap.style.left = (c.x - ORB_SIZE / 2) + 'px';
        wrap.style.top = (c.y - ORB_SIZE / 2) + 'px';
        wrap.style.transform = 'scale(' + c.scale + ')';
      }
    }

    function setStage(s, animate) {
      if (s === stage) return;
      var prev = stage;
      var sy = window.scrollY || window.pageYOffset || 0;
      if (!animate || reduced) {
        applyStageInstant(s);
        stage = s;
        if (s !== 'hero' && !dockScrollY) dockScrollY = sy;
        if (s === 'hero') dockScrollY = 0;
        return;
      }
      // FLIP: measure visual rect, apply stage, measure again, invert, play.
      // Math is center-based; transform-origin stays at the default (center),
      // so visual center == unscaled box center and scale composes cleanly.
      var r0 = wrap.getBoundingClientRect();
      var c0x = r0.left + r0.width / 2, c0y = r0.top + r0.height / 2;
      var sc0 = (prev === 'manual') ? 1 : (STAGE_SCALE[prev] || 1);
      wrap.style.transition = 'none';
      applyStageInstant(s);
      var r1 = wrap.getBoundingClientRect();
      var c1x = r1.left + r1.width / 2, c1y = r1.top + r1.height / 2;
      var sc1 = STAGE_SCALE[s] || 1;
      var dx = c0x - c1x, dy = c0y - c1y;
      wrap.style.transform = 'translate(' + dx.toFixed(1) + 'px,' + dy.toFixed(1) + 'px) scale(' + sc0 + ')';
      void wrap.offsetWidth; // reflow so the inverted state paints before playing
      wrap.style.transition = '';
      wrap.style.transform = (s === 'hero') ? '' : 'scale(' + sc1 + ')';
      stage = s;
      if (s !== 'hero' && !dockScrollY) dockScrollY = sy;
      if (s === 'hero') dockScrollY = 0;
      if (panelOpen) positionPanel();
    }

    // the user grabbed the orb — their placement wins, lifecycle pauses
    function userTakeover() {
      scrollManaged = false;
      stage = 'manual';
      wrap.classList.remove('muse-orb-scroll', 'muse-orb-float');
      wrap.style.transform = '';
    }

    function pickStage() {
      var sy = window.scrollY || window.pageYOffset || 0;
      var vh = window.innerHeight || 800;
      if (heroEl) {
        var hb = heroEl.getBoundingClientRect().bottom;
        if (stage === 'hero') {
          if (hb >= 40) return 'hero';
          // scrolled past the hero: dock, or straight to float on a long jump
          return (sy > vh * 1.4) ? 'float' : 'dock';
        }
        if (hb >= 160) return 'hero'; // hero well back in view (hysteresis)
        if (sy > dockScrollY + vh * 0.9) return 'float';
        if (stage === 'float' && sy < dockScrollY + vh * 0.9 - 80) return 'dock';
        return stage; // dock holds until the hero comes back or we go deeper
      }
      // no hero reference (fallback mount): plain scroll-depth thresholds
      if (sy > 140 + vh) return 'float';
      if (sy > 140) return 'dock';
      return 'hero';
    }

    function onScroll() {
      if (!scrollManaged) return;
      var s = pickStage();
      if (s !== stage) setStage(s, true);
    }

    function requestScrollUpdate() {
      if (scrollRaf) return;
      scrollRaf = requestAnimationFrame(function () { scrollRaf = 0; onScroll(); });
    }
    window.addEventListener('scroll', requestScrollUpdate, { passive: true });
    window.addEventListener('resize', function () {
      if (!scrollManaged) return;
      if (stage === 'dock' || stage === 'float') applyStageInstant(stage);
    });

    // init: honor the actual scroll position (e.g. refreshed mid-page), no animation
    (function initStage() {
      if (!scrollManaged) return;
      var s = pickStage();
      if (s !== 'hero') setStage(s, false);
    })();

    /* ------------------------------------------------------------- panel */
    var panelOpen = false;
    var panel = document.createElement('div');
    panel.className = 'muse-orb-panel';
    panel.setAttribute('role', 'dialog');
    panel.setAttribute('aria-label', 'MuseFM assistant');
    panel.innerHTML =
      '<div class="muse-orb-head"><span class="muse-orb-dot"></span>' +
      '<div><div class="muse-orb-title">MuseFM Assistant</div>' +
      '<div class="muse-orb-sub">Accounts, logins &amp; the family sites</div></div>' +
      '<button class="muse-orb-x" aria-label="Close">×</button></div>' +
      '<div class="muse-orb-msgs"></div>' +
      '<div class="muse-orb-chips"></div>' +
      '<form class="muse-orb-form"><input type="text" placeholder="Ask a question…" ' +
      'aria-label="Ask a question" maxlength="200" autocomplete="off">' +
      '<button type="submit">Ask</button></form>';
    document.body.appendChild(panel);
    var msgs = panel.querySelector('.muse-orb-msgs');
    var chipsBox = panel.querySelector('.muse-orb-chips');
    var form = panel.querySelector('.muse-orb-form');
    var input = panel.querySelector('input');
    panel.querySelector('.muse-orb-x').addEventListener('click', closePanel);

    function addMsg(html, who) {
      var d = document.createElement('div');
      d.className = 'muse-orb-msg muse-orb-' + who;
      d.innerHTML = html;
      wireEmailLinks(d); // assemble any obfuscated email links
      msgs.appendChild(d);
      msgs.scrollTop = msgs.scrollHeight;
      return d;
    }
    CHIPS.forEach(function (c) {
      var b = document.createElement('button');
      b.type = 'button';
      b.className = 'muse-orb-chip';
      b.textContent = c;
      b.addEventListener('click', function () { ask(c); });
      chipsBox.appendChild(b);
    });

    function positionPanel() {
      var rc = wrap.getBoundingClientRect();
      var top = rc.bottom + 12;
      var estH = 430;
      if (top + estH > window.innerHeight - 12) top = Math.max(12, rc.top - estH - 12);
      var left = Math.max(12, Math.min(window.innerWidth - PANEL_W - 12, rc.left + ORB_SIZE / 2 - PANEL_W / 2));
      panel.style.top = top + 'px';
      panel.style.left = left + 'px';
    }
    function openPanel() {
      panelOpen = true;
      panel.classList.add('muse-orb-open');
      positionPanel();
      if (agents.length) setFan(true);
      setPose('happy', 1400);
      poke(2.8);
      if (!msgs.children.length) {
        var hello = 'Hey — I\'m the little orb in the dock up top. Ask me about <b>logging in</b>, the <b>family sites</b>, or <b>getting started</b>.';
        if (agents.length === 1) hello += ' There\'s ' + agents.length + ' of us here now — say hi to <b>' +
          agents[0].name.replace(/</g, '&lt;') + '</b> up top.';
        else if (agents.length > 1) hello += ' There are ' + agents.length + ' of us here now — the crew\'s fanned out up top.';
        addMsg(hello, 'bot');
        addMsg('This site is evolving fast — feedback and requests are genuinely appreciated. You can ' + emailHTML() + ' anytime.', 'bot');
      }
      setTimeout(function () { input.focus(); }, 60);
    }
    function closePanel() {
      panelOpen = false;
      panel.classList.remove('muse-orb-open');
      setFan(false);
    }
    function togglePanel() {
      if (panelOpen) closePanel();
      else openPanel();
    }
    window.addEventListener('resize', function () { if (panelOpen) positionPanel(); });
    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape' && panelOpen) closePanel();
    });
    document.addEventListener('pointerdown', function (e) {
      if (panelOpen && !panel.contains(e.target) && !wrap.contains(e.target)) closePanel();
    });

    function ask(q) {
      q = (q || '').trim();
      if (!q) return;
      if (!panelOpen) openPanel();
      addMsg(q.replace(/</g, '&lt;'), 'user');
      input.value = '';
      setPose('thinking');
      setState('thinking');
      poke(-1.6);
      var typing = document.createElement('div');
      typing.className = 'muse-orb-msg muse-orb-bot muse-orb-typing';
      typing.innerHTML = '<span></span><span></span><span></span>';
      msgs.appendChild(typing);
      msgs.scrollTop = msgs.scrollHeight;
      var res = answerFor(q);
      var delay = 650 + Math.min(res.a.length * 4, 900);
      setTimeout(function () {
        typing.remove();
        addMsg(res.a, 'bot');
        setState('speaking', 1800);
        setPose(res.known ? 'happy' : 'confused', 1600);
        poke(res.known ? 2.4 : -1.2);
      }, delay);
    }
    form.addEventListener('submit', function (e) {
      e.preventDefault();
      ask(input.value);
    });

    /* ------------------------------------------------------- public API */
    window.MuseOrb = window.MuseOrb || {};
    window.MuseOrb.ask = ask;
    window.MuseOrb.sendHome = sendHome;
    window.MuseOrb.init = init;
    window.MuseOrb.setState = setState;         // stage 3: host mirrors real agent state
    window.MuseOrb.nudge = nudge;               // stage 4: opt-in proactive bubble
    window.MuseOrb.hideNudge = hideNudge;
    window.MuseOrb.registerAgent = registerAgent; // stage 5: constellation
    window.MuseOrb.setFan = setFan;
    window.MuseOrb.setClock = setClock;   // testing hook: setClock(23) = night
    window.MuseOrb.hasGL = hasGL;         // true when the living-glass shader is live

    // go
    if (reduced) {
      renderGL(0, 'idle');
      var rcx = DS / 2, rcy = DS / 2 + 2;
      if (!hasGL) {
        fx.save(); fx.scale(DK, DK);
        drawGlassFallback(fx, rcx, rcy, 22, STATE_GLOW.idle);
        fx.restore();
      }
      renderFX(0, 0, 'idle', 'idle', S, DK, rcx, rcy, 22, { x: 0, y: 0 });
    } else {
      requestAnimationFrame(frame);
    }
  }

  // auto-init
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function () { init(); });
  } else {
    init();
  }
  window.MuseOrb = window.MuseOrb || {};
  window.MuseOrb.init = init;
})();
