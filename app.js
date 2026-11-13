(() => {
  const CFG = window.DEBIN_CONFIG || {};
  const GH = CFG.GITHUB || {};
  const IS_GITHUB_READY = Boolean(GH.owner && GH.owner !== "YOUR_GITHUB_USERNAME" && GH.repo);

  const LS_TOKEN = "debin_gh_token";
  const LS_SESSION = "debin_user_session";
  const LS_LOCAL_POSTS = "debin_local_posts";
  const LS_LOCAL_USERS = "debin_local_users";
  const LS_OPTIMISTIC_POSTS = "debin_optimistic_posts";

  const TAB_TITLES = {
    all: "Весь архив (Главная)",
    thoughts: "Мысли класса",
    quotes: "Золотые цитаты",
    video: "Видеоархив",
    books: "Библиотека и летописи",
    photos: "Фотоальбом посёлка"
  };

  const TYPE_ICONS = {
    thoughts: `<svg viewBox="0 0 40 40"><path d="M9 10h22v15H17l-6 5v-5H9V10zm4 5v2h14v-2H13zm0 4v2h10v-2H13z"/></svg>`,
    quotes: `<svg viewBox="0 0 40 40"><path d="M10 22c0-5 3-9 8-11l2 3c-3 1.5-4.5 3.5-5 6h4v9H10v-7zm13 0c0-5 3-9 8-11l2 3c-3 1.5-4.5 3.5-5 6h4v9h-9v-7z"/></svg>`,
    video: `<svg viewBox="0 0 40 40"><path fill-rule="evenodd" d="m31.01 12.07c0 .41-.28.68-.71.68h-1.27c-.42 0-.71-.27-.71-.68v-.68c0-.41.28-.68.71-.68h1.27c.42 0 .71.27.71.68zm-4.09 5.95c0 .54-.42.95-.99.95h-11.58c-.56 0-.99-.41-.99-.95v-6.92c0-.54.42-.95.99-.95h11.58c.56 0 .99.41.99.95zm5.08-10.02h-28.1v24h28.1v-24z"/></svg>`,
    books: `<svg viewBox="0 0 40 40"><path d="m10.33 11h6.91c.89 0 1.58.31 2.1.92v14.43h-.65c-.14-.12-.35-.24-.63-.37-.27-.13-.52-.22-.74-.28l-.3-.11h-5.7c-.31 0-.56-.06-.75-.18-.07-.06-.13-.14-.16-.25-.04-.11-.06-.2-.07-.29v-13.87zm19.18 0v13.6c-.07.34-.22.59-.45.77-.07.06-.17.11-.3.14-.13.04-.25.06-.34.07h-5.6c-.96.26-1.51.52-1.65.76h-.66v-14.43c.51-.61 1.21-.92 2.08-.92h6.92z"/></svg>`,
    photos: `<svg viewBox="0 0 40 40"><path fill-rule="evenodd" d="m20.82 15.38c0 1.11-.88 1.89-1.86 1.89s-1.97-.89-1.97-1.89c0-1 .88-1.89 1.97-1.89.99 0 1.86.89 1.86 1.89zm-5.92-3.79h15.45v6.01l-1.97-3.34-2.63 6.35-2.19-2.67-6.14 5.12h-2.52zm-1.75-1.67v14.92h18.85v-14.92z"/></svg>`
  };

  let state = {
    posts: [],
    users: [],
    currentTab: "all",
    searchQuery: "",
    authMode: "login",
    currentUser: null,
    sessionMedia: {} // временные превью только что загруженных картинок/видео
  };

  // ====== КРИПТОГРАФИЯ (ЧИСТЫЙ SHA-256, РАБОТАЕТ ВЕЗДЕ ДАЖЕ НА file://) ======
  const K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ];

  function rotr(x, n) { return (x >>> n) | (x << (32 - n)); }

  function sha256Bytes(msgBytes) {
    const H = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    const bitLen = msgBytes.length * 8;
    const paddedLen = Math.ceil((msgBytes.length + 9) / 64) * 64;
    const padded = new Uint8Array(paddedLen);
    padded.set(msgBytes);
    padded[msgBytes.length] = 0x80;
    const view = new DataView(padded.buffer);
    view.setUint32(paddedLen - 8, Math.floor(bitLen / 0x100000000), false);
    view.setUint32(paddedLen - 4, bitLen >>> 0, false);

    const w = new Int32Array(64);
    for (let offset = 0; offset < paddedLen; offset += 64) {
      for (let i = 0; i < 16; i++) w[i] = view.getInt32(offset + i * 4, false);
      for (let i = 16; i < 64; i++) {
        const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
        const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
      }
      let [a, b, c, d, e, f, g, h] = H;
      for (let i = 0; i < 64; i++) {
        const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        const ch = (e & f) ^ ((~e) & g);
        const temp1 = (h + S1 + ch + K[i] + w[i]) | 0;
        const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        const maj = (a & b) ^ (a & c) ^ (b & c);
        const temp2 = (S0 + maj) | 0;
        h = g; g = f; f = e; e = (d + temp1) | 0;
        d = c; c = b; b = a; a = (temp1 + temp2) | 0;
      }
      H[0] = (H[0] + a) | 0; H[1] = (H[1] + b) | 0; H[2] = (H[2] + c) | 0; H[3] = (H[3] + d) | 0;
      H[4] = (H[4] + e) | 0; H[5] = (H[5] + f) | 0; H[6] = (H[6] + g) | 0; H[7] = (H[7] + h) | 0;
    }

    const out = new Uint8Array(32);
    const outView = new DataView(out.buffer);
    for (let i = 0; i < 8; i++) outView.setInt32(i * 4, H[i], false);
    return out;
  }

  function sha256Hex(str) {
    const bytes = sha256Bytes(new TextEncoder().encode(str));
    return [...bytes].map(b => b.toString(16).padStart(2, "0")).join("");
  }

  function concatBytes(a, b) {
    const res = new Uint8Array(a.length + b.length);
    res.set(a, 0);
    res.set(b, a.length);
    return res;
  }

  function bytesToBase64(bytes) {
    let bin = "";
    const chunk = 0x8000;
    for (let i = 0; i < bytes.length; i += chunk) {
      bin += String.fromCharCode(...bytes.subarray(i, i + chunk));
    }
    return btoa(bin);
  }

  function base64ToBytes(b64) {
    const bin = atob(b64.replace(/\s+/g, ""));
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  }

  function decryptToken(encryptedB64, passphrase) {
    if (!encryptedB64 || !passphrase) return null;
    try {
      const raw = base64ToBytes(encryptedB64);
      if (raw.length < 10) return null;
      const salt = raw.slice(0, 8);
      const ct = raw.slice(8);
      const key = sha256Bytes(concatBytes(new TextEncoder().encode(passphrase.trim()), salt));
      const pad = new Uint8Array(Math.ceil(ct.length / 32) * 32);
      for (let counter = 0; counter * 32 < ct.length; counter++) {
        const cBytes = new Uint8Array([
          (counter >>> 24) & 0xff, (counter >>> 16) & 0xff, (counter >>> 8) & 0xff, counter & 0xff
        ]);
        pad.set(sha256Bytes(concatBytes(key, cBytes)), counter * 32);
      }
      const pt = new Uint8Array(ct.length);
      for (let i = 0; i < ct.length; i++) pt[i] = ct[i] ^ pad[i];
      const text = new TextDecoder().decode(pt);
      return text.startsWith("DEBIN_OK:") ? text.slice(9) : null;
    } catch {
      return null;
    }
  }

  // ====== УТИЛИТЫ ======
  function esc(str) {
    return String(str ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function isDevMode() {
    const q = new URLSearchParams(window.location.search);
    if (q.has("dev")) return true;
    return /(?:^|[?&#/])dev(?:$|[=&])/i.test(window.location.hash);
  }

  function formatDate(iso) {
    if (!iso) return "";
    const d = new Date(iso);
    if (isNaN(d.getTime())) return iso;
    return d.toLocaleDateString("ru-RU", { day: "2-digit", month: "2-digit", year: "numeric" });
  }

  function getUnlockedToken() {
    return localStorage.getItem(LS_TOKEN) || "";
  }

  function extractYouTubeId(url) {
    if (!url) return null;
    const m = url.match(/(?:youtube\.com\/(?:watch\?v=|embed\/|shorts\/)|youtu\.be\/)([A-Za-z0-9_-]{6,})/);
    return m ? m[1] : null;
  }

  // ====== GITHUB REST API ======
  function apiUrl(path) {
    return `https://api.github.com/repos/${GH.owner}/${GH.repo}/contents/${path}`;
  }

  async function ghGetFile(path) {
    const headers = { "Accept": "application/vnd.github+json" };
    const token = getUnlockedToken();
    if (token) headers["Authorization"] = `Bearer ${token}`;
    const res = await fetch(`${apiUrl(path)}?ref=${GH.branch || "main"}&t=${Date.now()}`, {
      headers,
      cache: "no-store"
    });
    if (!res.ok) throw new Error(`GitHub GET ${path}: ${res.status}`);
    const json = await res.json();
    const content = new TextDecoder().decode(base64ToBytes(json.content));
    return { sha: json.sha, data: JSON.parse(content) };
  }

  async function ghPutRaw(path, base64Content, message, sha = null) {
    const token = getUnlockedToken();
    if (!token) throw new Error("Не введено кодовое слово класса для доступа к GitHub.");
    const body = {
      message,
      content: base64Content,
      branch: GH.branch || "main"
    };
    if (sha) body.sha = sha;

    const res = await fetch(apiUrl(path), {
      method: "PUT",
      headers: {
        "Authorization": `Bearer ${token}`,
        "Accept": "application/vnd.github+json",
        "Content-Type": "application/json"
      },
      body: JSON.stringify(body)
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      const e = new Error(err.message || `GitHub PUT ${res.status}`);
      e.status = res.status;
      throw e;
    }
    return res.json();
  }

  async function ghUpdateJson(path, mutator, commitMessage) {
    for (let attempt = 0; attempt < 2; attempt++) {
      let sha = null;
      let current = [];
      try {
        const fetched = await ghGetFile(path);
        sha = fetched.sha;
        current = fetched.data;
      } catch (e) {
        if (!String(e.message).includes("404")) throw e;
      }
      const next = mutator(Array.isArray(current) ? current : []);
      const b64 = bytesToBase64(new TextEncoder().encode(JSON.stringify(next, null, 2)));
      try {
        await ghPutRaw(path, b64, commitMessage, sha);
        return next;
      } catch (e) {
        if (e.status === 409 && attempt === 0) continue; // кто-то пушнул в ту же секунду -> ретрай
        throw e;
      }
    }
  }

  // Сжатие фото через canvas, чтобы не засирать репо 10МБ фотками
  async function compressImageIfNeeded(file) {
    if (!file.type.startsWith("image/") || file.size < 900 * 1024) {
      return new Uint8Array(await file.arrayBuffer());
    }
    return new Promise((resolve) => {
      const img = new Image();
      img.onload = () => {
        const maxSide = 1600;
        let { width, height } = img;
        if (width > maxSide || height > maxSide) {
          const ratio = Math.min(maxSide / width, maxSide / height);
          width = Math.round(width * ratio);
          height = Math.round(height * ratio);
        }
        const canvas = document.createElement("canvas");
        canvas.width = width;
        canvas.height = height;
        canvas.getContext("2d").drawImage(img, 0, 0, width, height);
        canvas.toBlob(async (blob) => {
          resolve(new Uint8Array(await blob.arrayBuffer()));
        }, "image/jpeg", 0.85);
      };
      img.src = URL.createObjectURL(file);
    });
  }

  // ====== ЗАГРУЗКА ДАННЫХ ======
  async function loadData() {
    let posts = [];
    let users = [];

    if (IS_GITHUB_READY) {
      // Сначала пробуем напрямую через API (без кэша GitHub Pages), потом фоллбек на локальный JSON
      try {
        const [pRes, uRes] = await Promise.all([ghGetFile("data/posts.json"), ghGetFile("data/users.json")]);
        posts = pRes.data;
        users = uRes.data;
      } catch {
        const [pLoc, uLoc] = await Promise.all([
          fetch(`./data/posts.json?t=${Date.now()}`).then(r => r.json()).catch(() => []),
          fetch(`./data/users.json?t=${Date.now()}`).then(r => r.json()).catch(() => [])
        ]);
        posts = pLoc;
        users = uLoc;
      }

      // Оптимистичный кэш свежих постов на 2 минуты, пока CDN гитхаба просыпается
      const opt = JSON.parse(localStorage.getItem(LS_OPTIMISTIC_POSTS) || "[]")
        .filter(item => Date.now() - item._ts < 120000);
      localStorage.setItem(LS_OPTIMISTIC_POSTS, JSON.stringify(opt));
      const ids = new Set(posts.map(p => p.id));
      opt.forEach(item => { if (!ids.has(item.id)) posts.unshift(item); });
    } else {
      // Демо-режим (если config.js ещё не заполнен или открыли локально)
      try {
        const filePosts = await fetch("./data/posts.json").then(r => r.json());
        posts = JSON.parse(localStorage.getItem(LS_LOCAL_POSTS) || "null") || filePosts;
      } catch {
        posts = JSON.parse(localStorage.getItem(LS_LOCAL_POSTS) || "null") || getFallbackSamplePosts();
      }
      users = JSON.parse(localStorage.getItem(LS_LOCAL_USERS) || "[]");
    }

    state.posts = Array.isArray(posts) ? posts : [];
    state.users = Array.isArray(users) ? users : [];
  }

  function getFallbackSamplePosts() {
    return [
      {
        id: "book-9th-grade",
        type: "books",
        featured: true,
        title: "Хроника ушедшего после девятого",
        bookAuthor: "Выжившие 11-А",
        bookYear: "Том 1 (1 стр.)",
        author: "Miralys",
        createdAt: "2026-05-25T12:00:00Z",
        text: "Говорят, после девятого класса есть другая жизнь — шараги, стипендия, первые пары к девяти утра.\n\nНаш герой ушёл туда смело, пообещав «не теряться» и «заходить на переменах». На следующий день он пропал с радаров, как сигнал МТС за околицей посёлка.\n\nЭта книга состоит ровно из одной страницы, потому что больше мы о нём за эти два года так и не узнали. Помним. Гордимся. Ждём на выпускной.",
        tags: ["книга", "9-й класс", "лор"]
      }
    ];
  }

  // ====== РЕНДЕР ======
  function updateCounts() {
    const counts = { thoughts: 0, quotes: 0, video: 0, books: 0, photos: 0 };
    state.posts.forEach(p => { if (counts[p.type] !== undefined) counts[p.type]++; });
    Object.entries(counts).forEach(([k, v]) => {
      const el = document.getElementById(`count-${k}`);
      if (el) el.textContent = v;
    });

    const ann = document.getElementById("hero-announcements-list");
    const total = state.posts.length;
    const regCount = state.users.length;
    ann.innerHTML = `
      <li>Всего записей в архиве: <strong>${total}</strong></li>
      <li>Зарегано одноклассников: <strong>${regCount}</strong> / ${CFG.MAX_REGULAR_USERS || 5} (+ Создатель)</li>
      <li>Главная реликвия: книга на 1 стр. в разделе <strong>«Книги»</strong></li>
      <li>${IS_GITHUB_READY ? "Режим: <strong>GitHub Pages Live</strong>" : "Режим: <strong>Локальное превью</strong>"}</li>
    `;
  }

  function renderFeed() {
    const grid = document.getElementById("feed-grid");
    const empty = document.getElementById("empty-state");
    const titleEl = document.getElementById("feed-title");
    const statsEl = document.getElementById("feed-stats");

    titleEl.textContent = TAB_TITLES[state.currentTab] || "Архив";
    const q = state.searchQuery.trim().toLowerCase();

    const filtered = state.posts.filter(p => {
      if (state.currentTab !== "all" && p.type !== state.currentTab) return false;
      if (!q) return true;
      const haystack = [p.title, p.text, p.author, p.quoteAuthor, p.bookAuthor, ...(p.tags || [])]
        .join(" ").toLowerCase();
      return haystack.includes(q);
    });

    statsEl.textContent = `Найдено: ${filtered.length}`;
    if (!filtered.length) {
      grid.innerHTML = "";
      empty.classList.remove("hidden");
      return;
    }
    empty.classList.add("hidden");

    grid.innerHTML = filtered.map(post => {
      const isCol = Boolean(post.featured);
      let thumbHtml = "";
      if (post.type === "photos" && (post.mediaUrl || state.sessionMedia[post.id])) {
        const src = state.sessionMedia[post.id] || post.mediaUrl;
        const rawFallback = IS_GITHUB_READY && !src.startsWith("data:") && !src.startsWith("http")
          ? `https://raw.githubusercontent.com/${GH.owner}/${GH.repo}/${GH.branch || "main"}/${src.replace(/^\.\//, "")}`
          : "";
        thumbHtml = `<img src="${esc(src)}" alt="${esc(post.title)}" loading="lazy" ${rawFallback ? `onerror="if(!this.dataset.f){this.dataset.f=1;this.src='${esc(rawFallback)}';}"` : ""}>`;
      } else if (post.type === "video") {
        const ytId = extractYouTubeId(post.videoUrl);
        if (ytId) {
          thumbHtml = `<img src="https://img.youtube.com/vi/${esc(ytId)}/hqdefault.jpg" alt=""><span class="video-badge">▶</span>`;
        } else {
          thumbHtml = `<div class="tile-preview-text">${esc(post.text || "Видеозапись из архива")}</div><span class="video-badge">▶</span>`;
        }
      } else if (post.type === "books") {
        thumbHtml = `
          <div class="tile-thumb tile-preview-book" style="width:100%;height:100%;border:0;">
            <div class="book-spine-tag">${esc(post.bookYear || "Издание 1 стр.")}</div>
            <div class="book-cover-title">${esc(post.title)}</div>
          </div>`;
      } else if (post.type === "quotes") {
        thumbHtml = `<div class="tile-preview-text tile-preview-quote">«${esc(post.text)}»</div>`;
      } else {
        thumbHtml = `<div class="tile-preview-text">${esc(post.text || "Без описания")}</div>`;
      }

      const subMeta = post.type === "quotes" && post.quoteAuthor
        ? `© ${post.quoteAuthor}`
        : `Автор: ${post.author || "Анон"}`;

      return `
        <article class="tile ${isCol ? "tile-collection" : ""}" data-post-id="${esc(post.id)}">
          <div class="tile-thumb">${thumbHtml}</div>
          <div class="tile-body">
            <h3 class="tile-title">${esc(post.title)}</h3>
            <div class="tile-meta">${esc(subMeta)}</div>
          </div>
          <div class="tile-stats">
            <span class="tile-type-badge">${TYPE_ICONS[post.type] || ""} ${esc(labelForType(post.type))}</span>
            <span>${formatDate(post.createdAt)}</span>
          </div>
        </article>
      `;
    }).join("");
  }

  function labelForType(type) {
    return { thoughts: "Мысль", quotes: "Цитата", video: "Видео", books: "Книга", photos: "Фото" }[type] || type;
  }

  // ====== ПРОСМОТР ПОСТА И ЧИТАЛКА КНИГИ ======
  function openPostModal(postId) {
    const post = state.posts.find(p => p.id === postId);
    if (!post) return;

    const titleEl = document.getElementById("view-modal-title");
    const bodyEl = document.getElementById("view-modal-body");
    titleEl.textContent = post.title;

    let mainHtml = "";
    if (post.type === "books") {
      const pages = (post.text || "").split(/\n\s*---\s*\n/).map(s => s.trim()).filter(Boolean);
      if (!pages.length) pages.push("Пустая страница...");
      let pageIdx = 0;
      let fontSize = 1.65;

      mainHtml = `
        <div class="book-reader-wrap">
          <div class="book-reader-bar">
            <div><strong>${esc(post.title)}</strong> — ${esc(post.bookAuthor || post.author)}</div>
            <div class="book-reader-controls">
              <button class="reader-btn" id="br-prev">← Назад</button>
              <span id="br-page-num">Стр. 1 из ${pages.length}</span>
              <button class="reader-btn" id="br-next">Вперёд →</button>
              <button class="reader-btn" id="br-font-minus">A-</button>
              <button class="reader-btn" id="br-font-plus">A+</button>
              <button class="reader-btn" id="br-download">Скачать .txt</button>
            </div>
          </div>
          <div class="book-page-stage">
            <div class="book-sheet" id="br-sheet" style="font-size:${fontSize}rem;">
              <div class="book-sheet-header">
                <h4>${esc(post.title)}</h4>
                <div>${esc(post.bookAuthor || post.author)} • ${esc(post.bookYear || "Архивное издание")}</div>
              </div>
              <div id="br-content"></div>
              <div class="book-sheet-footer" id="br-footer">Страница 1</div>
            </div>
          </div>
        </div>`;

      bodyEl.innerHTML = mainHtml + buildMetaTable(post);

      const renderPage = () => {
        document.getElementById("br-content").textContent = pages[pageIdx];
        document.getElementById("br-page-num").textContent = `Стр. ${pageIdx + 1} из ${pages.length}`;
        document.getElementById("br-footer").textContent = `— ${pageIdx + 1} —`;
        document.getElementById("br-prev").disabled = pageIdx === 0;
        document.getElementById("br-next").disabled = pageIdx >= pages.length - 1;
      };
      renderPage();

      document.getElementById("br-prev").onclick = () => { if (pageIdx > 0) { pageIdx--; renderPage(); } };
      document.getElementById("br-next").onclick = () => { if (pageIdx < pages.length - 1) { pageIdx++; renderPage(); } };
      document.getElementById("br-font-minus").onclick = () => {
        fontSize = Math.max(1.2, fontSize - 0.15);
        document.getElementById("br-sheet").style.fontSize = `${fontSize}rem`;
      };
      document.getElementById("br-font-plus").onclick = () => {
        fontSize = Math.min(2.4, fontSize + 0.15);
        document.getElementById("br-sheet").style.fontSize = `${fontSize}rem`;
      };
      document.getElementById("br-download").onclick = () => {
        const blob = new Blob([`${post.title}\nАвтор: ${post.bookAuthor || post.author}\n\n${post.text}`], { type: "text/plain;charset=utf-8" });
        const a = document.createElement("a");
        a.href = URL.createObjectURL(blob);
        a.download = `${post.title.slice(0, 30)}.txt`;
        a.click();
      };
    } else if (post.type === "photos") {
      const src = state.sessionMedia[post.id] || post.mediaUrl || "";
      mainHtml = `
        ${src ? `<div class="detail-media"><img src="${esc(src)}" alt="${esc(post.title)}"></div>` : ""}
        ${post.text ? `<div class="detail-thought-box">${esc(post.text)}</div>` : ""}
      `;
      bodyEl.innerHTML = mainHtml + buildMetaTable(post);
    } else if (post.type === "video") {
      const src = state.sessionMedia[post.id] || post.mediaUrl || "";
      const ytId = extractYouTubeId(post.videoUrl);
      let mediaEl = "";
      if (ytId) {
        mediaEl = `<div class="detail-media"><iframe src="https://www.youtube.com/embed/${esc(ytId)}" allowfullscreen></iframe></div>`;
      } else if (src || post.videoUrl) {
        mediaEl = `<div class="detail-media"><video src="${esc(src || post.videoUrl)}" controls playsinline></video></div>`;
      }
      bodyEl.innerHTML = `${mediaEl}${post.text ? `<div class="detail-thought-box">${esc(post.text)}</div>` : ""}` + buildMetaTable(post);
    } else if (post.type === "quotes") {
      mainHtml = `
        <div class="detail-quote-box">
          «${esc(post.text)}»
          ${post.quoteAuthor ? `<div class="detail-quote-author">— ${esc(post.quoteAuthor)}</div>` : ""}
        </div>`;
      bodyEl.innerHTML = mainHtml + buildMetaTable(post);
    } else {
      mainHtml = `<div class="detail-thought-box">${esc(post.text)}</div>`;
      bodyEl.innerHTML = mainHtml + buildMetaTable(post);
    }

    const delBtn = document.getElementById("view-delete-btn");
    if (delBtn) delBtn.onclick = () => deletePost(post.id);

    openModal("modal-view");
  }

  function buildMetaTable(post) {
    const canDelete = state.currentUser && (
      state.currentUser.isCreator ||
      state.currentUser.username.toLowerCase() === (post.author || "").toLowerCase()
    );
    return `
      <table class="detail-meta-table">
        <tr><td>Раздел</td><td>${esc(labelForType(post.type))}</td></tr>
        <tr><td>Опубликовал</td><td>${esc(post.author || "Аноним")}</td></tr>
        <tr><td>Дата архивации</td><td>${formatDate(post.createdAt)}</td></tr>
        ${post.tags && post.tags.length ? `<tr><td>Теги</td><td>${post.tags.map(t => `#${esc(t)}`).join(" ")}</td></tr>` : ""}
      </table>
      ${canDelete ? `<div style="margin-top:1.4rem;text-align:right;"><button id="view-delete-btn" class="btn-danger">Удалить из архива</button></div>` : ""}
    `;
  }

  async function deletePost(postId) {
    if (!confirm("Точно выпилить эту запись из архива?")) return;
    if (IS_GITHUB_READY) {
      await ghUpdateJson("data/posts.json", list => list.filter(p => p.id !== postId), `Delete post ${postId}`);
    } else {
      const next = state.posts.filter(p => p.id !== postId);
      localStorage.setItem(LS_LOCAL_POSTS, JSON.stringify(next));
    }
    state.posts = state.posts.filter(p => p.id !== postId);
    closeModal("modal-view");
    updateCounts();
    renderFeed();
  }

  // ====== АВТОРИЗАЦИЯ И ШИЗА С MIRALYS ======
  function updateAuthUI() {
    const lbl = document.getElementById("nav-auth-label");
    if (state.currentUser) {
      lbl.textContent = state.currentUser.isCreator ? `Miralys [Создатель]` : state.currentUser.username;
    } else {
      lbl.textContent = "Войти";
    }
    document.getElementById("dev-banner").classList.toggle("hidden", !isDevMode());
    document.getElementById("auth-dev-badge").classList.toggle("hidden", !isDevMode());
  }

  function syncAuthModalFields() {
    const isReg = state.authMode === "register";
    const needPhrase = isReg && IS_GITHUB_READY && Boolean(CFG.ENCRYPTED_TOKEN) && !getUnlockedToken();
    document.getElementById("auth-passphrase-wrap").classList.toggle("hidden", !needPhrase);
    document.getElementById("auth-submit-btn").textContent = isReg ? "Зарегистрироваться" : "Войти";
    document.getElementById("auth-error").classList.add("hidden");
  }

  async function handleAuthSubmit(e) {
    e.preventDefault();
    const errBox = document.getElementById("auth-error");
    errBox.classList.add("hidden");

    const usernameRaw = document.getElementById("auth-username").value.trim();
    const password = document.getElementById("auth-password").value;
    const passphrase = document.getElementById("auth-passphrase").value.trim();
    const lower = usernameRaw.toLowerCase();

    const showErr = (msg) => {
      errBox.textContent = msg;
      errBox.classList.remove("hidden");
    };

    if (!usernameRaw || !password) return showErr("Заполни имя и пароль.");

    // ГЛАВНЫЙ ПРИКОЛ С АККАУНТОМ MIRALYS
    if (lower === "miralys") {
      if (state.authMode === "register" || !isDevMode()) {
        // И при попытке зарегаться на Miralys/miralys, и при обычном входе без ?dev!
        return showErr("Аккаунт не зарегистрирован");
      }
      // Вход Создателя через ?dev:
      if (CFG.CREATOR_PASS_HASH) {
        const hash = sha256Hex("DEBIN_CREATOR:" + password);
        if (hash !== CFG.CREATOR_PASS_HASH) return showErr("Неверный ключ Создателя.");
      }
      state.currentUser = { username: "Miralys", isCreator: true };
      localStorage.setItem(LS_SESSION, JSON.stringify(state.currentUser));
      updateAuthUI();
      closeModal("modal-auth");
      return;
    }

    const passHash = sha256Hex("DEBIN_USER:" + lower + ":" + password);

    if (state.authMode === "login") {
      const found = state.users.find(u => u.username.toLowerCase() === lower);
      if (!found) return showErr("Аккаунт не зарегистрирован");
      if (found.passHash !== passHash) return showErr("Неверный пароль.");

      state.currentUser = { username: found.username, isCreator: false };
      localStorage.setItem(LS_SESSION, JSON.stringify(state.currentUser));
      updateAuthUI();
      closeModal("modal-auth");
      return;
    }

    // РЕГИСТРАЦИЯ ОБЫЧНОГО ОДНОКЛАССНИКА
    if (CFG.MAX_REGULAR_USERS && state.users.length >= CFG.MAX_REGULAR_USERS) {
      return showErr(`Все ${CFG.MAX_REGULAR_USERS} мест одноклассников уже заняты!`);
    }
    if (state.users.some(u => u.username.toLowerCase() === lower)) {
      return showErr("Такой ник уже занят кем-то из ваших.");
    }

    if (IS_GITHUB_READY && CFG.ENCRYPTED_TOKEN && !getUnlockedToken()) {
      const tok = decryptToken(CFG.ENCRYPTED_TOKEN, passphrase);
      if (!tok) return showErr("Неверное кодовое слово класса!");
      localStorage.setItem(LS_TOKEN, tok);
    }

    const newUser = {
      username: usernameRaw,
      passHash,
      createdAt: new Date().toISOString()
    };

    const btn = document.getElementById("auth-submit-btn");
    btn.disabled = true;
    btn.textContent = "Сохраняем на GitHub...";
    try {
      if (IS_GITHUB_READY) {
        state.users = await ghUpdateJson("data/users.json", list => [...list, newUser], `Register user ${usernameRaw}`);
      } else {
        state.users.push(newUser);
        localStorage.setItem(LS_LOCAL_USERS, JSON.stringify(state.users));
      }
      state.currentUser = { username: newUser.username, isCreator: false };
      localStorage.setItem(LS_SESSION, JSON.stringify(state.currentUser));
      updateAuthUI();
      updateCounts();
      closeModal("modal-auth");
    } catch (err) {
      showErr("Ошибка при пуше: " + err.message);
    } finally {
      btn.disabled = false;
      btn.textContent = "Зарегистрироваться";
    }
  }

  // ====== ПУБЛИКАЦИЯ ПОСТА ======
  function syncPublishFormFields() {
    const type = document.getElementById("pub-type").value;
    document.getElementById("pub-quote-group").classList.toggle("hidden", type !== "quotes");
    document.getElementById("pub-book-group").classList.toggle("hidden", type !== "books");
    document.getElementById("pub-file-group").classList.toggle("hidden", type !== "photos" && type !== "video");
    document.getElementById("pub-video-url-group").classList.toggle("hidden", type !== "video");

    const fileInput = document.getElementById("pub-file");
    if (type === "photos") {
      fileInput.accept = "image/*";
      document.getElementById("pub-file-label").textContent = "Загрузить фото (сожмётся автоматически)";
    } else if (type === "video") {
      fileInput.accept = "video/*";
      document.getElementById("pub-file-label").textContent = `Загрузить видеофайл (до ${CFG.MAX_UPLOAD_MB || 25} МБ)`;
    }

    const textLabels = {
      thoughts: "Текст мысли",
      quotes: "Сама цитата (без кавычек)",
      photos: "Подпись к фото (по желанию)",
      video: "Описание видео (по желанию)",
      books: "Текст книги (деление на страницы через строку ---)"
    };
    document.getElementById("pub-text-label").textContent = textLabels[type] || "Текст";

    const needPass = IS_GITHUB_READY && Boolean(CFG.ENCRYPTED_TOKEN) && !getUnlockedToken();
    document.getElementById("pub-passphrase-group").classList.toggle("hidden", !needPass);
  }

  async function handlePublishSubmit(e) {
    e.preventDefault();
    const errBox = document.getElementById("pub-error");
    const statusBox = document.getElementById("pub-status");
    const btn = document.getElementById("pub-submit-btn");
    errBox.classList.add("hidden");
    statusBox.classList.add("hidden");

    const showErr = (m) => { errBox.textContent = m; errBox.classList.remove("hidden"); };

    if (!state.currentUser) {
      closeModal("modal-publish");
      openModal("modal-auth");
      return;
    }

    if (IS_GITHUB_READY && CFG.ENCRYPTED_TOKEN && !getUnlockedToken()) {
      const phrase = document.getElementById("pub-passphrase").value.trim();
      const tok = decryptToken(CFG.ENCRYPTED_TOKEN, phrase);
      if (!tok) return showErr("Неверное кодовое слово класса!");
      localStorage.setItem(LS_TOKEN, tok);
    }

    const type = document.getElementById("pub-type").value;
    const title = document.getElementById("pub-title").value.trim();
    const text = document.getElementById("pub-text").value.trim();
    const quoteAuthor = document.getElementById("pub-quote-author").value.trim();
    const bookAuthor = document.getElementById("pub-book-author").value.trim();
    const bookYear = document.getElementById("pub-book-year").value.trim();
    const videoUrl = document.getElementById("pub-video-url").value.trim();
    const file = document.getElementById("pub-file").files[0];
    const tags = document.getElementById("pub-tags").value
      .split(",").map(s => s.trim()).filter(Boolean);

    if (!title) return showErr("Нужен заголовок!");
    if ((type === "thoughts" || type === "quotes" || type === "books") && !text) {
      return showErr("Напиши хоть пару слов!");
    }
    if (type === "photos" && !file) return showErr("Выбери фотографию!");
    if (type === "video" && !file && !videoUrl) return showErr("Выбери видеофайл или вставь ссылку!");

    const postId = `post-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    let mediaUrl = "";

    btn.disabled = true;
    try {
      if (file) {
        if (file.size > (CFG.MAX_UPLOAD_MB || 25) * 1024 * 1024 && type === "video") {
          throw new Error(`Файл больше ${CFG.MAX_UPLOAD_MB || 25} МБ. Залей на YouTube и вставь ссылку!`);
        }
        statusBox.textContent = "Обработка и загрузка файла...";
        statusBox.classList.remove("hidden");

        const bytes = type === "photos"
          ? await compressImageIfNeeded(file)
          : new Uint8Array(await file.arrayBuffer());

        const ext = (file.name.split(".").pop() || (type === "photos" ? "jpg" : "mp4")).toLowerCase().replace(/[^a-z0-9]/g, "");
        const filePath = `uploads/${postId}.${ext}`;

        // Сохраняем локальное превью в памяти, чтобы автор видел файл сразу
        const blobUrl = URL.createObjectURL(new Blob([bytes], { type: file.type || "application/octet-stream" }));
        state.sessionMedia[postId] = blobUrl;

        if (IS_GITHUB_READY) {
          await ghPutRaw(filePath, bytesToBase64(bytes), `Upload media ${postId}`);
          mediaUrl = `./${filePath}`;
        } else {
          // В локальном демо-режиме сохраняем DataURL (для мелких картинок)
          mediaUrl = bytes.length < 2 * 1024 * 1024
            ? `data:${file.type || "image/jpeg"};base64,${bytesToBase64(bytes)}`
            : blobUrl;
        }
      }

      const newPost = {
        id: postId,
        type,
        title,
        text,
        author: state.currentUser.username,
        createdAt: new Date().toISOString(),
        tags
      };
      if (type === "quotes" && quoteAuthor) newPost.quoteAuthor = quoteAuthor;
      if (type === "books") {
        newPost.bookAuthor = bookAuthor || state.currentUser.username;
        newPost.bookYear = bookYear || "1 стр.";
      }
      if (mediaUrl) newPost.mediaUrl = mediaUrl;
      if (videoUrl) newPost.videoUrl = videoUrl;

      statusBox.textContent = "Пушим запись в архив...";
      statusBox.classList.remove("hidden");

      if (IS_GITHUB_READY) {
        state.posts = await ghUpdateJson("data/posts.json", list => [newPost, ...list], `Add ${type}: ${title}`);
        const opt = JSON.parse(localStorage.getItem(LS_OPTIMISTIC_POSTS) || "[]");
        opt.unshift({ ...newPost, _ts: Date.now() });
        localStorage.setItem(LS_OPTIMISTIC_POSTS, JSON.stringify(opt));
      } else {
        state.posts.unshift(newPost);
        localStorage.setItem(LS_LOCAL_POSTS, JSON.stringify(state.posts));
      }

      document.getElementById("publish-form").reset();
      syncPublishFormFields();
      updateCounts();
      renderFeed();
      closeModal("modal-publish");
    } catch (err) {
      showErr("Не вышло запушить: " + err.message);
    } finally {
      btn.disabled = false;
    }
  }

  // ====== УЧАСТНИКИ ======
  function openUsersModal() {
    const listEl = document.getElementById("users-list");
    const postCountBy = {};
    state.posts.forEach(p => {
      const k = (p.author || "").toLowerCase();
      postCountBy[k] = (postCountBy[k] || 0) + 1;
    });

    // Мистический Miralys всегда первым, независимо от users.json!
    let html = `
      <div class="user-row creator-row">
        <div>
          <strong>Miralys</strong>
          <div class="muted-note" style="margin:0;">Постов: ${postCountBy["miralys"] || 0} • Статус: в системе (и вне её)</div>
        </div>
        <span class="badge-creator">Создатель</span>
      </div>
    `;

    state.users.forEach(u => {
      const cnt = postCountBy[u.username.toLowerCase()] || 0;
      html += `
        <div class="user-row">
          <div>
            <strong>${esc(u.username)}</strong>
            <div class="muted-note" style="margin:0;">Постов: ${cnt} • С нами с ${formatDate(u.createdAt)}</div>
          </div>
          <span class="badge-member">Выживший</span>
        </div>
      `;
    });

    listEl.innerHTML = html;

    const inviteBox = document.getElementById("invite-box");
    inviteBox.classList.toggle("hidden", !getUnlockedToken() || !IS_GITHUB_READY);
    openModal("modal-users");
  }

  // ====== МОДАЛКИ И СОБЫТИЯ ======
  function openModal(id) { document.getElementById(id).classList.remove("hidden"); }
  function closeModal(id) { document.getElementById(id).classList.add("hidden"); }

  function setTab(tab) {
    state.currentTab = tab;
    document.querySelectorAll("[data-tab]").forEach(btn => {
      btn.classList.toggle("active", btn.dataset.tab === tab);
    });
    renderFeed();
  }

  function handleInviteHash() {
    const m = window.location.hash.match(/key=([^&]+)/);
    if (m && CFG.ENCRYPTED_TOKEN) {
      const phrase = decodeURIComponent(m[1]);
      const tok = decryptToken(CFG.ENCRYPTED_TOKEN, phrase);
      if (tok) {
        localStorage.setItem(LS_TOKEN, tok);
        history.replaceState(null, "", window.location.pathname + window.location.search);
      }
    }
  }

  async function init() {
    handleInviteHash();

    try {
      const saved = JSON.parse(localStorage.getItem(LS_SESSION) || "null");
      if (saved && saved.username) state.currentUser = saved;
    } catch {}

    updateAuthUI();
    await loadData();
    updateCounts();
    renderFeed();

    // Навигация и табы
    document.querySelectorAll("[data-tab]").forEach(btn => {
      btn.addEventListener("click", () => {
        setTab(btn.dataset.tab);
        document.querySelector(".media-menu").classList.remove("open");
      });
    });

    document.getElementById("mobile-menu-btn").addEventListener("click", () => {
      document.querySelector(".media-menu").classList.toggle("open");
    });

    // Поиск
    const searchInput = document.getElementById("search-input");
    const clearBtn = document.getElementById("search-clear-btn");
    document.getElementById("search-form").addEventListener("submit", (e) => {
      e.preventDefault();
      state.searchQuery = searchInput.value;
      renderFeed();
    });
    searchInput.addEventListener("input", () => {
      state.searchQuery = searchInput.value;
      clearBtn.classList.toggle("hidden", !searchInput.value);
      renderFeed();
    });
    clearBtn.addEventListener("click", () => {
      searchInput.value = "";
      state.searchQuery = "";
      clearBtn.classList.add("hidden");
      renderFeed();
    });

    // Клик по карточкам
    document.getElementById("feed-grid").addEventListener("click", (e) => {
      const card = e.target.closest(".tile");
      if (card) openPostModal(card.dataset.postId);
    });

    // Кнопка входа / выхода
    document.getElementById("nav-auth-btn").addEventListener("click", () => {
      if (state.currentUser) {
        if (confirm(`Выйти из аккаунта ${state.currentUser.username}?`)) {
          state.currentUser = null;
          localStorage.removeItem(LS_SESSION);
          updateAuthUI();
        }
      } else {
        syncAuthModalFields();
        openModal("modal-auth");
      }
    });

    // Вкладки вход / регистрация
    document.querySelectorAll("[data-auth-mode]").forEach(btn => {
      btn.addEventListener("click", () => {
        state.authMode = btn.dataset.authMode;
        document.querySelectorAll("[data-auth-mode]").forEach(b => b.classList.toggle("active", b === btn));
        syncAuthModalFields();
      });
    });

    document.getElementById("auth-form").addEventListener("submit", handleAuthSubmit);

    // Публикация
    const openPublish = () => {
      if (!state.currentUser) {
        syncAuthModalFields();
        openModal("modal-auth");
        return;
      }
      syncPublishFormFields();
      openModal("modal-publish");
    };
    document.getElementById("nav-publish-btn").addEventListener("click", openPublish);
    document.getElementById("hero-publish-cta").addEventListener("click", openPublish);
    document.getElementById("pub-type").addEventListener("change", syncPublishFormFields);
    document.getElementById("publish-form").addEventListener("submit", handlePublishSubmit);

    // Участники
    document.getElementById("nav-users-btn").addEventListener("click", openUsersModal);
    document.getElementById("subnav-users-link").addEventListener("click", openUsersModal);

    // Инвайт-ссылка (копирует ссылку с хешем)
    document.getElementById("copy-invite-btn").addEventListener("click", () => {
      const phrase = prompt("Введи кодовое слово класса, чтобы зашить его в одноразовую ссылку-приглашение:");
      if (!phrase) return;
      const link = `${window.location.origin}${window.location.pathname}#key=${encodeURIComponent(phrase)}`;
      navigator.clipboard?.writeText(link);
      alert("Ссылка скопирована! Кидай её в беседу вашим:\n" + link);
    });

    // Закрытие модалок
    document.querySelectorAll("[data-close]").forEach(btn => {
      btn.addEventListener("click", () => closeModal(btn.dataset.close));
    });
    document.querySelectorAll(".modal-backdrop").forEach(bg => {
      bg.addEventListener("click", (e) => {
        if (e.target === bg) bg.classList.add("hidden");
      });
    });
  }

  document.addEventListener("DOMContentLoaded", init);
})();