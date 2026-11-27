(function () {
  'use strict';
  var $ = function (id) { return document.getElementById(id); };
  var KEY_STORE = 'kb_key_v1';

  // ---- 起動: 平文データならそのまま、暗号化データならパスワードで復号 ----
  function b64(s) { return Uint8Array.from(atob(s), function (c) { return c.charCodeAt(0); }); }
  function hex(u8) { return Array.prototype.map.call(u8, function (b) { return ('0' + b.toString(16)).slice(-2); }).join(''); }
  function unhex(h) { return new Uint8Array(h.match(/../g).map(function (x) { return parseInt(x, 16); })); }
  function deriveRaw(pw, E) {
    return crypto.subtle.importKey('raw', new TextEncoder().encode(pw), 'PBKDF2', false, ['deriveBits'])
      .then(function (k) {
        return crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: b64(E.salt), iterations: E.iter }, k, 256);
      }).then(function (bits) { return new Uint8Array(bits); });
  }
  function decrypt(raw, E) {
    return crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['decrypt']).then(function (k) {
      return crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64(E.iv) }, k, b64(E.ct));
    }).then(function (buf) {
      var ds = new Blob([buf]).stream().pipeThrough(new DecompressionStream('gzip'));
      return new Response(ds).text();
    }).then(JSON.parse);
  }
  function storeGet() { try { return localStorage.getItem(KEY_STORE); } catch (e) { return null; } }
  function storeSet(v) { try { if (v) localStorage.setItem(KEY_STORE, v); else localStorage.removeItem(KEY_STORE); } catch (e) {} }
  window.kbLock = function () { storeSet(null); location.hash = ''; location.reload(); };

  function boot() {
    if (window.KB_DATA) { $('lock-view').hidden = true; return start(window.KB_DATA); }
    var E = window.KB_ENC;
    if (!E) { $('lock-msg').textContent = 'データが見つかりません'; return; }
    if (!(window.crypto && crypto.subtle && window.DecompressionStream)) {
      $('lock-msg').textContent = 'この端末のブラウザは暗号化データの復号に対応していません（iPadOS 16.4 以降が必要です）';
      return;
    }
    var saved = storeGet() || '';
    var ok = function (raw, D) {
      storeSet(E.salt + ':' + hex(raw)); // salt が変わる（再暗号化）と自動的に無効
      $('lock-view').hidden = true;
      start(D);
    };
    if (saved.indexOf(E.salt + ':') === 0) {
      var raw = unhex(saved.slice(E.salt.length + 1));
      decrypt(raw, E).then(function (D) { ok(raw, D); }, function () { storeSet(null); showLock(E, ok); });
    } else showLock(E, ok);
  }
  function showLock(E, ok) {
    var form = $('lock-form'), pw = $('lock-pw'), msg = $('lock-msg'), btn = $('lock-btn');
    $('lock-view').hidden = false; $('search-view').hidden = true;
    pw.focus();
    form.onsubmit = function (e) {
      e.preventDefault();
      if (!pw.value) return;
      btn.disabled = true; msg.textContent = '確認中…';
      deriveRaw(pw.value, E).then(function (raw) {
        return decrypt(raw, E).then(function (D) { pw.value = ''; msg.textContent = ''; ok(raw, D); });
      }).catch(function () {
        msg.textContent = 'パスワードが違います';
        btn.disabled = false; pw.select();
      });
    };
  }

  function start(D) {
  var SRC = {}; D.sources.forEach(function (s) { SRC[s.id] = s; });

  // ---- 正規化: 全角半角(NFKC)・大文字小文字・カタカナ→ひらがな・空白除去 ----
  function norm(s) {
    s = String(s || '').normalize('NFKC').toLowerCase();
    s = s.replace(/[ァ-ヶ]/g, function (c) { return String.fromCharCode(c.charCodeAt(0) - 0x60); });
    return s.replace(/[\s　]+/g, '');
  }
  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }
  // 表示用ハイライト: 原文1文字ずつ正規化して位置対応をとる
  function hl(text, terms) {
    text = String(text || '');
    if (!terms.length) return esc(text);
    var chars = Array.from(text), nchars = chars.map(function (c) { return norm(c); });
    var joined = '', map = [];
    nchars.forEach(function (n, i) { for (var k = 0; k < n.length; k++) { joined += n[k]; map.push(i); } });
    var on = new Array(chars.length).fill(false);
    terms.forEach(function (t) {
      var p = 0;
      while (t && (p = joined.indexOf(t, p)) !== -1) {
        for (var k = p; k < p + t.length; k++) on[map[k]] = true;
        p += t.length;
      }
    });
    var out = '', open = false;
    chars.forEach(function (c, i) {
      if (on[i] && !open) { out += '<mark>'; open = true; }
      if (!on[i] && open) { out += '</mark>'; open = false; }
      out += esc(c);
    });
    return out + (open ? '</mark>' : '');
  }

  // ---- 表示ヘルパ ----
  function valueText(r) {
    var u = r.unit || '';
    if (r.min && r.max) return r.min + '〜' + r.max + u;
    if (r.min && r.std) return r.std + u + '（' + r.min + u + '以上）';
    if (r.max && r.std) return r.std + u + '（' + r.max + u + '以下）';
    if (r.min) return r.min + u + ' 以上';
    if (r.max) return r.max + u + ' 以下';
    if (r.std) return r.std + u + ' 程度';
    return '';
  }
  // 頁の呼び方: 書籍は「p.150」、解説資料（source.json の pageLabel）は「解説3」
  function pgLab(src, p) { var s = SRC[src]; return (s && s.pageLabel ? s.pageLabel : 'p.') + p; }
  function pgList(r) { return r.pages.map(function (p) { return pgLab(r.src, p); }).join('/'); }
  function isOcr(src) { var s = SRC[src]; return !(s && s.textKind); }
  function cite(r) {
    var s = SRC[r.src];
    return (s ? s.short : r.src) + ' ' + pgList(r) + (r.fig ? ' ' + r.fig : '');
  }
  function citeLong(r) {
    var s = SRC[r.src], v = valueText(r) || r.note;
    return r.item + '（' + r.cons + '・' + r.part + '）' + r.vtype + ': ' + v +
      (valueText(r) && r.note ? '［' + r.note + '］' : '') +
      ' — 出典: ' + (s ? s.title : r.src) + ' ' + pgList(r) + (r.fig ? '、' + r.fig : '') +
      '（原文の扱い: ' + r.wording + '）';
  }
  function badge(r) {
    return r.verified === '原本確認済' || r.verified === '規格原文確認'
      ? '<span class="badge ok">原本確認済</span>'
      : '<span class="badge ocr">' + esc(r.verified || 'OCR') + '</span>';
  }
  function toast(msg) {
    var t = $('toast'); t.textContent = msg; t.hidden = false;
    clearTimeout(toast.tm); toast.tm = setTimeout(function () { t.hidden = true; }, 1600);
  }
  function copy(text) {
    if (window.Android && Android.copy) { Android.copy(text); toast('コピーしました'); return; }
    if (navigator.clipboard) navigator.clipboard.writeText(text).then(function () { toast('コピーしました'); },
      function () { fallback(); });
    else fallback();
    function fallback() {
      var ta = document.createElement('textarea'); ta.value = text; document.body.appendChild(ta);
      ta.select(); try { document.execCommand('copy'); toast('コピーしました'); } catch (e) { toast('コピーできませんでした'); }
      ta.remove();
    }
  }

  // ---- 索引 ----
  D.records.forEach(function (r) {
    var sm = r.refs.map(function (k) { var x = D.summaries[k]; return x ? [x.cls, x.part, x.item, x.value].join(' ') : ''; });
    r._hi = norm(r.item);
    r._hp = norm(r.part + ' ' + r.cons + ' ' + r.vtype);
    r._ho = norm([r.cat, r.note, r.wording, r.fig, r.kbid, valueText(r), sm.join(' '), (SRC[r.src] || {}).short,
      r.pages.map(function (p) { return 'p' + p; }).join(' ')].join(' '));
  });
  D.pages.forEach(function (p) { p._n = norm(p.text); });
  var PAGE = {}; D.pages.forEach(function (p) { if (p.book != null) PAGE[p.src + ':' + p.book] = p; });
  var REC = {}; D.records.forEach(function (r) { REC[r.id] = r; });

  // ---- フィルタUI ----
  var state = { q: '', cat: '', cons: '', vtype: '' };
  function uniq(key) {
    var c = {}; D.records.forEach(function (r) { if (r[key]) c[r[key]] = (c[r[key]] || 0) + 1; });
    return Object.keys(c).sort(function (a, b) { return c[b] - c[a] || a.localeCompare(b, 'ja'); });
  }
  function fillSelect(el, label, vals) {
    el.innerHTML = '<option value="">' + label + '（すべて）</option>' +
      vals.map(function (v) { return '<option>' + esc(v) + '</option>'; }).join('');
  }
  var cats = uniq('cat');
  $('cat-chips').innerHTML = ['すべて'].concat(cats).map(function (c, i) {
    return '<button class="chip" data-v="' + (i ? esc(c) : '') + '" aria-pressed="' + (i ? 'false' : 'true') + '">' + esc(c) + '</button>';
  }).join('');
  fillSelect($('cons'), '主材・構法', uniq('cons'));
  fillSelect($('vtype'), '値種別', uniq('vtype'));

  $('cat-chips').addEventListener('click', function (e) {
    var b = e.target.closest('.chip'); if (!b) return;
    state.cat = b.dataset.v;
    Array.prototype.forEach.call(this.children, function (x) { x.setAttribute('aria-pressed', String(x === b)); });
    render();
  });
  $('cons').addEventListener('change', function () { state.cons = this.value; render(); });
  $('vtype').addEventListener('change', function () { state.vtype = this.value; render(); });
  var tm;
  $('q').addEventListener('input', function () {
    $('clear').hidden = !this.value;
    clearTimeout(tm); tm = setTimeout(function () { state.q = $('q').value; render(); saveState(); }, 120);
  });
  $('q').addEventListener('keydown', function (e) { if (e.key === 'Enter') this.blur(); });
  $('clear').addEventListener('click', function () { $('q').value = ''; this.hidden = true; state.q = ''; render(); $('q').focus(); });

  function saveState() { try { localStorage.setItem('q', state.q); } catch (e) {} }

  // ---- 検索 ----
  function terms() {
    return String(state.q).normalize('NFKC').split(/[\s　]+/).map(norm).filter(Boolean);
  }
  function search() {
    var ts = terms();
    var rs = D.records.filter(function (r) {
      return (!state.cat || r.cat === state.cat) && (!state.cons || r.cons === state.cons) &&
        (!state.vtype || r.vtype === state.vtype);
    }).map(function (r) {
      var score = 0;
      for (var i = 0; i < ts.length; i++) {
        var t = ts[i], s = 0;
        if (r._hi.indexOf(t) !== -1) s = 3; else if (r._hp.indexOf(t) !== -1) s = 2; else if (r._ho.indexOf(t) !== -1) s = 1;
        if (!s) return null;
        score += s;
      }
      return { r: r, s: score };
    }).filter(Boolean);
    rs.sort(function (a, b) {
      return b.s - a.s || a.r.item.localeCompare(b.r.item, 'ja') || a.r.pages[0] - b.r.pages[0];
    });
    return { ts: ts, rs: rs.map(function (x) { return x.r; }) };
  }
  function snippet(text, ts) {
    var n = text.normalize('NFKC'), first = -1;
    ts.forEach(function (t) {
      var i = norm(n).indexOf(t);
      if (i !== -1 && (first === -1 || i < first)) first = i;
    });
    // 正規化後位置は空白除去で前にずれるため、近傍を広めに切り出す
    var lines = text.split('\n'), hit = lines.filter(function (l) {
      var nl = norm(l); return ts.some(function (t) { return nl.indexOf(t) !== -1; });
    });
    return hit.slice(0, 2).map(function (l) { return l.length > 90 ? l.slice(0, 90) + '…' : l; }).join(' ／ ');
  }

  function render() {
    var res = search(), ts = res.ts, rs = res.rs;
    $('count').textContent = rs.length + ' 件' + (ts.length || state.cat || state.cons || state.vtype ? '' : '（全件）');
    $('results').innerHTML = rs.map(function (r) {
      var v = valueText(r);
      return '<li class="card" data-id="' + esc(r.id) + '">' +
        '<div class="head"><span class="item">' + hl(r.item, ts) + '</span><span class="vtype">' + esc(r.vtype) + '</span></div>' +
        '<div class="ctx">' + hl(r.cons, ts) + ' ／ ' + hl(r.part, ts) + '</div>' +
        (v ? '<div class="value">' + esc(v) + '</div>' : '<div class="value text">' + hl(r.note, ts) + '</div>') +
        (v && r.note ? '<div class="ctx">' + hl(r.note, ts) + '</div>' : '') +
        '<div class="meta"><span class="badge w">' + esc(r.wording) + '</span>' + badge(r) +
        '<span class="cite">' + esc(cite(r)) + '</span></div></li>';
    }).join('');

    // 原文のみヒット: レコードの頁に含まれない頁
    var ph = [];
    if (ts.length) {
      var recPages = {};
      rs.forEach(function (r) { r.pages.forEach(function (p) { recPages[r.src + ':' + p] = 1; }); });
      ph = D.pages.filter(function (p) {
        if (p.book != null && recPages[p.src + ':' + p.book]) return false;
        return ts.every(function (t) { return p._n.indexOf(t) !== -1; });
      }).slice(0, 30);
    }
    $('page-hits').hidden = !ph.length;
    $('page-list').innerHTML = ph.map(function (p) {
      var label = p.book != null ? SRC[p.src].short + ' ' + pgLab(p.src, p.book) : SRC[p.src].short + ' PDF p.' + p.pdf;
      return '<li data-pg="' + esc(p.src + ':' + (p.book != null ? p.book : 'pdf' + p.pdf)) + '"><div class="pg">' + esc(label) + '</div>' +
        hl(snippet(p.text, ts), ts) + '</li>';
    }).join('');

    // 欠落頁の注記
    var miss = [];
    D.sources.forEach(function (s) {
      var hitTopic = (s.missingTopics || []).some(function (t) {
        var nt = norm(t); return ts.some(function (q) { return nt.indexOf(q) !== -1 || q.indexOf(nt) !== -1; });
      });
      if (hitTopic && s.missingPages && s.missingPages.length) miss.push(s.short + ' は本文' + s.missingPages.map(function (r) { return 'p.' + r[0] + '〜' + r[1]; }).join('、') +
        ' がスキャン欠落のため未収録です（谷どい・突起物廻り・屋根上付属物 等）。原本で確認してください。');
      (s.absentTopics || []).forEach(function (t) {
        var nt = norm(t);
        if (ts.some(function (q) { return q.length > 1 && nt.indexOf(q) !== -1; }))
          miss.push(s.short + ' には「' + t + '」の記載がありません。根拠はメーカー施工要領書や自社標準で示してください。');
      });
    });
    $('notice').hidden = !miss.length;
    $('notice').textContent = miss.join(' ');
  }
  $('results').addEventListener('click', function (e) {
    var c = e.target.closest('.card'); if (c) location.hash = '#/r/' + encodeURIComponent(c.dataset.id);
  });
  $('page-list').addEventListener('click', function (e) {
    var c = e.target.closest('li'); if (c) location.hash = '#/p/' + encodeURIComponent(c.dataset.pg);
  });

  $('foot').innerHTML = D.sources.map(function (s) {
    return '<div><b>' + esc(s.title) + '</b><br>' + esc(s.note) +
      (s.missingPages && s.missingPages.length ? '<br>欠落頁: ' +
        s.missingPages.map(function (r) { return 'p.' + r[0] + '〜' + r[1]; }).join('、') : '') +
      (s.absentTopics && s.absentTopics.length ? '<br>記載なし（確認済）: ' + esc(s.absentTopics.join('、')) : '') + '</div>';
  }).join('') + '<div style="margin-top:8px">収録 ' + D.records.length + ' 件 ／ 原文 ' + D.pages.length + ' 頁</div>';

  // ---- 詳細 ----
  function showDetail(id) {
    var r = REC[id]; if (!r) return go('');
    var ts = terms(), v = valueText(r), s = SRC[r.src];
    var refs = r.refs.map(function (k) { return D.summaries[k]; }).filter(Boolean);
    var related = D.records.filter(function (x) {
      return x !== r && x.src === r.src && x.pages.some(function (p) { return r.pages.indexOf(p) !== -1; });
    });
    var h = '<div class="panel">' +
      '<div class="ctx">' + esc(r.cat) + ' ／ ' + esc(r.vtype) + '</div>' +
      '<div class="item" style="font-size:18px;font-weight:700">' + esc(r.item) + '</div>' +
      '<div class="ctx">' + esc(r.cons) + ' ／ ' + esc(r.part) + '</div>' +
      (v ? '<div class="value" style="font-size:26px">' + esc(v) + '</div>' : '<div class="value text">' + esc(r.note) + '</div>') +
      '<dl class="kv">' +
      '<dt>最小（以上）</dt><dd>' + esc(r.min ? r.min + r.unit : '—') + '</dd>' +
      '<dt>標準（程度）</dt><dd>' + esc(r.std ? r.std + r.unit : '—') + '</dd>' +
      '<dt>最大（以下）</dt><dd>' + esc(r.max ? r.max + r.unit : '—') + '</dd>' +
      '<dt>条件・備考</dt><dd>' + esc(r.note || '—') + '</dd>' +
      '<dt>原文の扱い</dt><dd>' + esc(r.wording) + '</dd>' +
      '<dt>出典</dt><dd>' + esc(s ? s.title : r.src) + '<br>' + (s && s.pageLabel ? '' : '本文 ') + esc(pgList(r)) + (r.fig ? '　' + esc(r.fig) : '') + '</dd>' +
      '<dt>照合</dt><dd>' + badge(r) + (r.verified === 'OCR' ? '　<span class="ctx">OCR抽出。原本で数値を確認してください</span>' :
        r.verified === '現場実務' ? '　<span class="ctx">一社の現場慣行（聞き取り）。教科書の推奨値ではありません</span>' :
        /^Web/.test(r.verified || '') ? '　<span class="ctx">Web資料。引用時は URL を添えてください</span>' : '') + '</dd>' +
      '<dt>ID</dt><dd>' + esc(r.kbid) + (r.refs.length ? '（元: ' + esc(r.refs.map(function (k) { return k.split(':')[1]; }).join('、')) + '）' : '') + '</dd>' +
      '</dl>' +
      '<div class="btns"><button class="btn primary" id="cp-short">出典をコピー</button>' +
      '<button class="btn" id="cp-long">値＋出典をコピー</button></div></div>';
    if (refs.length) {
      h += '<h2>原典の記述（推奨値一覧）</h2><div class="panel">' + refs.map(function (x) {
        return '<div><span class="ctx">' + esc(x.cls) + ' ／ ' + esc(x.part) + '</span><br><b>' + esc(x.item) + '</b>：' + esc(x.value) + '</div>';
      }).join('<hr style="border:0;border-top:1px solid var(--line)">') + '</div>';
    }
    h += '<h2>' + (isOcr(r.src) ? '原文（OCR）' : '解説本文') + '</h2><div class="btns" style="margin-top:0">' + r.pages.map(function (p) {
      return PAGE[r.src + ':' + p]
        ? '<button class="btn" data-pg="' + esc(r.src + ':' + p) + '">' + esc(pgLab(r.src, p)) + ' を開く</button>'
        : '<span class="ctx">' + esc(pgLab(r.src, p)) + ' は原文データなし</span>';
    }).join('') + '</div>';
    if (related.length) {
      h += '<h2>同じ頁の項目</h2><ul class="cards related">' + related.map(function (x) {
        return '<li class="card" data-id="' + esc(x.id) + '"><div class="head"><span class="item">' + esc(x.item) +
          '</span><span class="vtype">' + esc(x.vtype) + '</span></div><div class="ctx">' + esc(x.part) + '　' +
          esc(valueText(x) || x.note) + '</div></li>';
      }).join('') + '</ul>';
    }
    var el = $('detail-view'); el.innerHTML = h;
    $('cp-short').onclick = function () { copy(cite(r)); };
    $('cp-long').onclick = function () { copy(citeLong(r)); };
    el.onclick = function (e) {
      var b = e.target.closest('[data-pg]'); if (b) { location.hash = '#/p/' + encodeURIComponent(b.dataset.pg); return; }
      var c = e.target.closest('.card'); if (c) location.hash = '#/r/' + encodeURIComponent(c.dataset.id);
    };
    return r.item;
  }

  // ---- 原文頁 ----
  function showPage(key) {
    var i = key.lastIndexOf(':'), src = key.slice(0, i), pg = key.slice(i + 1), p;
    if (pg.indexOf('pdf') === 0) p = D.pages.filter(function (x) { return x.src === src && x.pdf === +pg.slice(3); })[0];
    else p = PAGE[src + ':' + pg];
    if (!p) return go('');
    var idx = D.pages.indexOf(p), prev = D.pages[idx - 1], next = D.pages[idx + 1];
    function key2(x) { return x && x.src === src ? x.src + ':' + (x.book != null ? x.book : 'pdf' + x.pdf) : ''; }
    function lab(x) { return x.book != null ? pgLab(x.src, x.book) : 'PDF p.' + x.pdf; }
    var recs = p.book != null ? D.records.filter(function (r) { return r.src === src && r.pages.indexOf(p.book) !== -1; }) : [];
    var h = '<div class="ctx">' + esc(SRC[src].title) + (isOcr(src) ? '　（PDF p.' + p.pdf + '）' : '') + '</div>' +
      (isOcr(src) ? '<div class="ctx" style="margin:4px 0 8px">OCRのため数値・記号に誤読があり得ます。図表は文字化けしています。</div>' : '<div style="height:8px"></div>') +
      '<div class="pager">' +
      (key2(prev) ? '<button class="btn" data-pg="' + esc(key2(prev)) + '">← ' + esc(lab(prev)) + '</button>' : '<span></span>') +
      (key2(next) ? '<button class="btn" data-pg="' + esc(key2(next)) + '">' + esc(lab(next)) + ' →</button>' : '<span></span>') +
      '</div><pre class="ocr">' + hl(p.text, terms()) + '</pre>';
    if (recs.length) {
      h += '<h2>' + (isOcr(src) ? 'この頁' : 'この項') + 'の収録項目</h2><ul class="cards">' + recs.map(function (x) {
        return '<li class="card" data-id="' + esc(x.id) + '"><div class="head"><span class="item">' + esc(x.item) +
          '</span><span class="vtype">' + esc(x.vtype) + '</span></div><div class="ctx">' + esc(x.part) + '　' +
          esc(valueText(x) || x.note) + '</div></li>';
      }).join('') + '</ul>';
    }
    var el = $('page-view'); el.innerHTML = h;
    el.onclick = function (e) {
      var b = e.target.closest('[data-pg]'); if (b) { location.replace('#/p/' + encodeURIComponent(b.dataset.pg)); return; }
      var c = e.target.closest('.card'); if (c) location.hash = '#/r/' + encodeURIComponent(c.dataset.id);
    };
    return SRC[src].short + ' ' + lab(p);
  }

  // ---- ルーティング ----
  function go(h) { location.hash = h; }
  var scrollY = 0;
  function route() {
    var h = location.hash.replace(/^#/, ''), m, title = '板金推奨値';
    var views = { s: $('search-view'), d: $('detail-view'), p: $('page-view') }, show = 's';
    if ((m = h.match(/^\/r\/(.+)$/))) { title = showDetail(decodeURIComponent(m[1])) || title; show = 'd'; }
    else if ((m = h.match(/^\/p\/(.+)$/))) { title = showPage(decodeURIComponent(m[1])) || title; show = 'p'; }
    if (views.s.hidden === false && show !== 's') scrollY = window.scrollY;
    Object.keys(views).forEach(function (k) { views[k].hidden = k !== show; });
    $('back').hidden = show === 's';
    $('title').textContent = title;
    window.scrollTo(0, show === 's' ? scrollY : 0);
  }
  $('back').addEventListener('click', function () { history.back(); });
  window.addEventListener('hashchange', route);
  // Android の戻るボタンから呼ばれる。戻れたら true
  window.kbBack = function () {
    if (location.hash && location.hash !== '#') { history.back(); return true; }
    return false;
  };

  if (window.KB_ENC) {
    var lk = document.createElement('div');
    lk.style.marginTop = '10px';
    lk.innerHTML = '<button class="btn" id="relock">パスワードを消去してロック</button>';
    $('foot').appendChild(lk);
    $('relock').onclick = function () { window.kbLock(); };
  }
  try { var q0 = localStorage.getItem('q'); if (q0) { $('q').value = q0; state.q = q0; $('clear').hidden = false; } } catch (e) {}
  $('search-view').hidden = false;
  render();
  route();
  }

  if ('serviceWorker' in navigator && location.protocol === 'https:' && !window.Android) {
    navigator.serviceWorker.register('sw.js').catch(function () {});
  }
  boot();
})();
