(() => {
  const CFG = window.DEBIN_CONFIG || {};
  const GH = CFG.GITHUB || {};
  const CLD = CFG.CLOUDINARY || {};
  const IS_GITHUB_READY = Boolean(GH.owner && GH.owner !== "YOUR_GITHUB_USERNAME" && GH.repo);
  const HAS_CLOUDINARY = Boolean(CLD.cloudName && CLD.uploadPreset);

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

  const LS_LOCAL_AVATARS = "debin_local_avatars";

  let state = {
    posts: [],
    users: [],
    tgStatus: {},
    avatars: {},
    presence: { users: {}, devPrefs: { showOnline: false, showLastSeen: false } },
    currentTab: "all",
    searchQuery: "",
    sortBy: "newest",
    filterAuthor: "",
    authMode: "login",
    currentUser: null,
    sessionMedia: {},
    selectedPhotoFiles: [],
    carouselMove: null,
    replyToComment: null,
    threadToggles: {},
    activeModalPostId: null,
    pushedPostHistory: false,
    pendingTgCode: ""
  };

  let ghWriteQueue = Promise.resolve();
  function enqueueGhWrite(task) {
    const run = ghWriteQueue.then(task, task);
    ghWriteQueue = run.catch(() => {});
    return run;
  }

  // ====== КРИПТОГРАФИЯ (ЧИСТЫЙ SHA-256) ======
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

  function blobToBase64(blob) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => {
        const res = String(reader.result || "");
        const idx = res.indexOf(",");
        resolve(idx >= 0 ? res.slice(idx + 1) : res);
      };
      reader.onerror = () => reject(new Error("Не удалось прочитать файл с устройства"));
      reader.readAsDataURL(blob);
    });
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

  // ====== УТИЛИТЫ И ССЫЛКИ НА ПОСТЫ / КОММЕНТЫ ======
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

  function isCreatorUser() {
    return Boolean(state.currentUser && state.currentUser.isCreator && state.currentUser.username.toLowerCase() === "miralys");
  }

  function toLocalInputValue(iso) {
    const d = iso ? new Date(iso) : new Date();
    if (isNaN(d.getTime())) return "";
    const pad = (n) => String(n).padStart(2, "0");
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
  }

  function getPostIdFromUrl() {
    const q = new URLSearchParams(window.location.search);
    if (q.get("post")) return q.get("post");
    const hash = window.location.hash.replace(/^#/, "");
    if (!hash) return "";
    const hp = new URLSearchParams(hash);
    if (hp.get("post")) return hp.get("post");
    const m = hash.match(/(?:^|&)post=([^&]+)/);
    return m ? decodeURIComponent(m[1]) : "";
  }

  function getCommentIdFromUrl() {
    const q = new URLSearchParams(window.location.search);
    if (q.get("comment")) return q.get("comment");
    const hash = window.location.hash.replace(/^#/, "");
    if (!hash) return "";
    const hp = new URLSearchParams(hash);
    if (hp.get("comment")) return hp.get("comment");
    const m = hash.match(/(?:^|&)comment=([^&]+)/);
    return m ? decodeURIComponent(m[1]) : "";
  }

  function buildPostShareUrl(postId) {
    const base = window.location.href.split(/[?#]/)[0];
    return `${base}#post=${encodeURIComponent(postId)}`;
  }

  function formatDate(iso) {
    if (!iso) return "";
    const d = new Date(iso);
    if (isNaN(d.getTime())) return iso;
    return d.toLocaleDateString("ru-RU", { day: "2-digit", month: "2-digit", year: "numeric" });
  }

  function formatDateTime(iso) {
    if (!iso) return "";
    const d = new Date(iso);
    if (isNaN(d.getTime())) return iso;
    return d.toLocaleString("ru-RU", { day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit" });
  }

  function saveUnlockedToken(tok) {
    localStorage.setItem(LS_TOKEN, tok);
    localStorage.setItem(LS_TOKEN + "_sig", (CFG.ENCRYPTED_TOKEN || "").slice(0, 16));
  }

  function clearUnlockedToken() {
    localStorage.removeItem(LS_TOKEN);
    localStorage.removeItem(LS_TOKEN + "_sig");
  }

  function getUnlockedToken() {
    const sig = localStorage.getItem(LS_TOKEN + "_sig");
    if (!CFG.ENCRYPTED_TOKEN || sig !== CFG.ENCRYPTED_TOKEN.slice(0, 16)) {
      clearUnlockedToken();
      return "";
    }
    return localStorage.getItem(LS_TOKEN) || "";
  }

  function extractYouTubeId(url) {
    if (!url) return null;
    const m = url.match(/(?:youtube\.com\/(?:watch\?v=|embed\/|shorts\/)|youtu\.be\/)([A-Za-z0-9_-]{6,})/);
    return m ? m[1] : null;
  }

  function setProgress(pct, label) {
    const wrap = document.getElementById("pub-progress-wrap");
    const bar = document.getElementById("pub-progress-bar");
    const txt = document.getElementById("pub-progress-text");
    if (!wrap) return;
    wrap.classList.remove("hidden");
    bar.style.width = `${Math.max(0, Math.min(100, pct))}%`;
    txt.textContent = label || `${pct}%`;
  }

  function hideProgress() {
    const wrap = document.getElementById("pub-progress-wrap");
    if (wrap) wrap.classList.add("hidden");
  }

  function ensureTokenInteractive() {
    if (!IS_GITHUB_READY || !CFG.ENCRYPTED_TOKEN || getUnlockedToken()) return true;
    const phrase = prompt("Напиши 0 (так надо, по-братски):");
    if (phrase === null) return false;
    const tok = decryptToken(CFG.ENCRYPTED_TOKEN, phrase);
    if (!tok) {
      alert("Братик, там же написано: напиши 0!");
      return false;
    }
    saveUnlockedToken(tok);
    return true;
  }

  function hasUserLiked(likesArr) {
    if (!state.currentUser || !Array.isArray(likesArr)) return false;
    const me = state.currentUser.username.toLowerCase();
    return likesArr.some(u => String(u).toLowerCase() === me);
  }

  function toggleUserInLikes(likesArr, username) {
    const list = Array.isArray(likesArr) ? likesArr : [];
    const me = username.toLowerCase();
    return list.some(u => String(u).toLowerCase() === me)
      ? list.filter(u => String(u).toLowerCase() !== me)
      : [...list, username];
  }

  // ====== МУЛЬТИ-ФОТО ПРЕВЬЮ В ФОРМЕ ======
  function ensurePhotoPreviewBox() {
    let box = document.getElementById("pub-files-preview");
    if (!box) {
      box = document.createElement("div");
      box.id = "pub-files-preview";
      box.className = "pub-files-preview hidden";
      document.getElementById("pub-file-group").appendChild(box);
    }
    return box;
  }

  function renderSelectedPhotosPreview() {
    const box = ensurePhotoPreviewBox();
    const type = document.getElementById("pub-type").value;
    if (type !== "photos" || !state.selectedPhotoFiles.length) {
      box.classList.add("hidden");
      box.innerHTML = "";
      return;
    }

    box.classList.remove("hidden");
    box.innerHTML = `
      <div class="pub-files-head">
        <span>Выбрано фото: <strong>${state.selectedPhotoFiles.length} шт.</strong> (можно ещё докинуть)</span>
        <button type="button" id="pub-files-clear" class="pub-files-clear">Очистить всё</button>
      </div>
      <div class="pub-files-grid">
        ${state.selectedPhotoFiles.map((f, idx) => `
          <div class="pub-mini-thumb">
            <img src="${esc(f._previewUrl)}" alt="">
            <button type="button" class="pub-mini-remove" data-rm-photo="${idx}" title="Убрать">✕</button>
          </div>
        `).join("")}
      </div>
    `;

    document.getElementById("pub-files-clear").onclick = () => clearSelectedPhotos();
    box.querySelectorAll("[data-rm-photo]").forEach(btn => {
      btn.onclick = () => {
        const idx = Number(btn.dataset.rmPhoto);
        const removed = state.selectedPhotoFiles.splice(idx, 1)[0];
        if (removed && removed._previewUrl) URL.revokeObjectURL(removed._previewUrl);
        renderSelectedPhotosPreview();
      };
    });
  }

  function clearSelectedPhotos() {
    state.selectedPhotoFiles.forEach(f => {
      if (f._previewUrl) URL.revokeObjectURL(f._previewUrl);
    });
    state.selectedPhotoFiles = [];
    const fileInput = document.getElementById("pub-file");
    if (fileInput) fileInput.value = "";
    renderSelectedPhotosPreview();
  }

  // ====== GITHUB & XHR ЗАГРУЗЧИК ======
  function apiUrl(path) {
    return `https://api.github.com/repos/${GH.owner}/${GH.repo}/contents/${path}`;
  }

  function ghBaseUrl() {
    return `https://api.github.com/repos/${GH.owner}/${GH.repo}`;
  }

  function xhrRequest(method, url, headers, body, onProgress) {
    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open(method, url, true);
      xhr.timeout = 240000;
      Object.entries(headers || {}).forEach(([k, v]) => xhr.setRequestHeader(k, v));

      if (onProgress && xhr.upload) {
        xhr.upload.onprogress = (e) => {
          if (e.lengthComputable) {
            onProgress(Math.round((e.loaded / e.total) * 100), e.loaded, e.total);
          }
        };
      }

      xhr.onload = () => {
        let data = {};
        try { data = JSON.parse(xhr.responseText || "{}"); } catch {}
        if (xhr.status >= 200 && xhr.status < 300) {
          resolve(data);
        } else {
          if (url.includes("api.github.com") && (xhr.status === 401 || xhr.status === 403)) {
            clearUnlockedToken();
          }
          const err = new Error(data.message || `HTTP ${xhr.status}`);
          err.status = xhr.status;
          reject(err);
        }
      };

      xhr.onerror = () => reject(new Error("Обрыв сети при отправке файла"));
      xhr.ontimeout = () => reject(new Error("Таймаут загрузки (файл тяжёлый для текущего интернета)"));
      xhr.send(body);
    });
  }

  async function ghGetFile(path, branchOverride = null) {
    const branch = branchOverride || GH.branch || "main";
    const headers = { "Accept": "application/vnd.github+json" };
    const token = getUnlockedToken();
    if (token) headers["Authorization"] = `Bearer ${token}`;
    const res = await fetch(`${apiUrl(path)}?ref=${branch}&t=${Date.now()}`, {
      headers,
      cache: "no-store"
    });
    if (!res.ok) throw new Error(`GitHub GET ${path}: ${res.status}`);
    const json = await res.json();
    const content = new TextDecoder().decode(base64ToBytes(json.content));
    return { sha: json.sha, data: JSON.parse(content) };
  }

  async function ghPutRaw(path, base64Content, message, sha = null, onProgress = null, branchOverride = null) {
    const token = getUnlockedToken();
    if (!token) throw new Error("Не введён братский 0 для доступа к архиву.");
    const branch = branchOverride || GH.branch || "main";
    const body = { message, content: base64Content, branch };
    if (sha) body.sha = sha;

    return xhrRequest(
      "PUT",
      apiUrl(path),
      {
        "Authorization": `Bearer ${token}`,
        "Accept": "application/vnd.github+json",
        "Content-Type": "application/json"
      },
      JSON.stringify(body),
      onProgress
    );
  }

  async function ghUploadViaGitBlobs(filesToUpload, commitMessage, onProgress) {
    const token = getUnlockedToken();
    if (!token) throw new Error("Не введён братский 0 для доступа к архиву.");
    const branch = GH.branch || "main";
    const headers = {
      "Authorization": `Bearer ${token}`,
      "Accept": "application/vnd.github+json",
      "Content-Type": "application/json"
    };

    const totalLen = filesToUpload.reduce((s, f) => s + f.base64.length, 0) || 1;
    let doneLen = 0;
    const uploadedBlobs = [];

    for (let i = 0; i < filesToUpload.length; i++) {
      const f = filesToUpload[i];
      const blobRes = await xhrRequest(
        "POST",
        `${ghBaseUrl()}/git/blobs`,
        headers,
        JSON.stringify({ content: f.base64, encoding: "base64" }),
        onProgress ? (pct, loaded, total) => {
          const overall = Math.round(((doneLen + (f.base64.length * pct / 100)) / totalLen) * 100);
          onProgress(overall, loaded, total, i + 1, filesToUpload.length);
        } : null
      );
      doneLen += f.base64.length;
      uploadedBlobs.push({ path: f.path, mode: "100644", type: "blob", sha: blobRes.sha });
    }

    setProgress(96, "Фиксируем файлы в ветке GitHub...");
    for (let attempt = 0; attempt < 3; attempt++) {
      const refRes = await fetch(`${ghBaseUrl()}/git/ref/heads/${branch}?t=${Date.now()}`, { headers, cache: "no-store" });
      if (!refRes.ok) throw new Error(`Git ref error: ${refRes.status}`);
      const refData = await refRes.json();
      const headSha = refData.object.sha;

      const commitRes = await fetch(`${ghBaseUrl()}/git/commits/${headSha}`, { headers, cache: "no-store" });
      if (!commitRes.ok) throw new Error(`Git commit error: ${commitRes.status}`);
      const commitData = await commitRes.json();

      const treeData = await xhrRequest(
        "POST",
        `${ghBaseUrl()}/git/trees`,
        headers,
        JSON.stringify({ base_tree: commitData.tree.sha, tree: uploadedBlobs })
      );

      const newCommit = await xhrRequest(
        "POST",
        `${ghBaseUrl()}/git/commits`,
        headers,
        JSON.stringify({ message: commitMessage, tree: treeData.sha, parents: [headSha] })
      );

      try {
        await xhrRequest(
          "PATCH",
          `${ghBaseUrl()}/git/refs/heads/${branch}`,
          headers,
          JSON.stringify({ sha: newCommit.sha, force: false })
        );
        return;
      } catch (e) {
        if ((e.status === 409 || e.status === 422) && attempt < 2) continue;
        throw e;
      }
    }
  }

  async function uploadVideoToCloudinary(file, onProgress) {
    const fd = new FormData();
    fd.append("file", file);
    fd.append("upload_preset", CLD.uploadPreset);
    const url = `https://api.cloudinary.com/v1_1/${CLD.cloudName}/video/upload`;
    const data = await xhrRequest("POST", url, {}, fd, onProgress);
    return {
      videoUrl: data.secure_url,
      thumbUrl: data.secure_url.replace(/\.[^.\/]+$/, ".jpg")
    };
  }

  async function ghDeleteFile(path, commitMessage) {
    const token = getUnlockedToken();
    if (!token) throw new Error("Нет токена для удаления файла.");

    const metaRes = await fetch(`${apiUrl(path)}?ref=${GH.branch || "main"}&t=${Date.now()}`, {
      headers: { "Authorization": `Bearer ${token}`, "Accept": "application/vnd.github+json" },
      cache: "no-store"
    });
    if (metaRes.status === 404) return;
    if (!metaRes.ok) throw new Error(`GitHub GET sha ${path}: ${metaRes.status}`);
    const meta = await metaRes.json();

    const delRes = await fetch(apiUrl(path), {
      method: "DELETE",
      headers: {
        "Authorization": `Bearer ${token}`,
        "Accept": "application/vnd.github+json",
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ message: commitMessage, sha: meta.sha, branch: GH.branch || "main" })
    });
    if (!delRes.ok) {
      if (delRes.status === 401 || delRes.status === 403) clearUnlockedToken();
      const err = await delRes.json().catch(() => ({}));
      throw new Error(err.message || `GitHub DELETE ${delRes.status}`);
    }
  }

  function ghUpdateJson(path, mutator, commitMessage, defaultVal = [], branchOverride = null) {
    return enqueueGhWrite(async () => {
      for (let attempt = 0; attempt < 3; attempt++) {
        let sha = null;
        let current = defaultVal;
        try {
          const fetched = await ghGetFile(path, branchOverride);
          sha = fetched.sha;
          current = fetched.data;
        } catch (e) {
          if (!String(e.message).includes("404")) throw e;
        }
        const next = mutator(current);
        const b64 = bytesToBase64(new TextEncoder().encode(JSON.stringify(next, null, 2)));
        try {
          await ghPutRaw(path, b64, commitMessage, sha, null, branchOverride);
          return next;
        } catch (e) {
          if (e.status === 409 && attempt < 2) continue;
          throw e;
        }
      }
    });
  }

  // ====== ОНЛАЙН / ОФФЛАЙН (ВЕТКА presence) ======
  async function loadPresence() {
    if (!IS_GITHUB_READY) return;
    try {
      const res = await ghGetFile("presence.json", "presence");
      if (res && res.data && typeof res.data === "object") {
        state.presence = {
          users: res.data.users || {},
          devPrefs: { showOnline: false, showLastSeen: false, ...(res.data.devPrefs || {}) }
        };
      }
    } catch {}
  }

  async function pingPresence(force = false) {
    if (!IS_GITHUB_READY || !state.currentUser || !getUnlockedToken()) return;
    if (!force && document.visibilityState !== "visible") return;

    const lower = state.currentUser.username.toLowerCase();
    const isMeCreator = isCreatorUser();
    if (isMeCreator) {
      await loadPresence();
      const dp = state.presence.devPrefs || {};
      if (!dp.showOnline && !dp.showLastSeen) return;
    }

    const lsKey = `debin_last_ping_${lower}`;
    const lastPing = Number(localStorage.getItem(lsKey) || 0);
    if (!force && Date.now() - lastPing < 180000) return;

    localStorage.setItem(lsKey, String(Date.now()));
    try {
      state.presence = await ghUpdateJson(
        "presence.json",
        (obj) => {
          const base = (obj && typeof obj === "object") ? obj : {};
          const users = { ...(base.users || {}) };
          const dp = { showOnline: false, showLastSeen: false, ...(base.devPrefs || {}) };
          if (isMeCreator && !dp.showOnline && !dp.showLastSeen) {
            delete users["miralys"];
          } else {
            users[lower] = { lastSeen: Date.now() };
          }
          return { users, devPrefs: dp };
        },
        `Ping ${lower}`,
        { users: {}, devPrefs: { showOnline: false, showLastSeen: false } },
        "presence"
      );
    } catch {}
  }

  function formatPresenceLine(username, fallbackText) {
    const lower = String(username || "").toLowerCase();
    const entry = state.presence && state.presence.users && state.presence.users[lower];
    const ts = entry ? Number(entry.lastSeen || 0) : 0;
    const isOnline = ts > 0 && (Date.now() - ts < 4 * 60 * 1000);

    if (lower === "miralys") {
      const dp = (state.presence && state.presence.devPrefs) || {};
      if (isOnline && dp.showOnline) return `<span class="status-online">🟢 Онлайн</span>`;
      if (ts > 0 && dp.showLastSeen) return `<span class="status-offline">${formatLastSeenTime(ts)}</span>`;
      if (isCreatorUser()) {
        return `<span class="status-offline">${esc(fallbackText)} (скрыт от всех)</span>`;
      }
      return `<span class="status-offline">${esc(fallbackText)}</span>`;
    }

    if (isOnline) return `<span class="status-online">🟢 Онлайн</span>`;
    if (ts > 0) return `<span class="status-offline">${formatLastSeenTime(ts)}</span>`;
    return `<span class="status-offline">${esc(fallbackText)}</span>`;
  }

  function formatLastSeenTime(ts) {
    const d = new Date(ts);
    const now = new Date();
    const pad = (n) => String(n).padStart(2, "0");
    const hm = `${pad(d.getHours())}:${pad(d.getMinutes())}`;
    const sameDay = d.toDateString() === now.toDateString();
    const yest = new Date(now.getFullYear(), now.getMonth(), now.getDate() - 1);
    const isYest = d.toDateString() === yest.toDateString();
    if (sameDay) return `Был(а) сегодня в ${hm}`;
    if (isYest) return `Был(а) вчера в ${hm}`;
    return `Был(а) ${pad(d.getDate())}.${pad(d.getMonth() + 1)} в ${hm}`;
  }

  async function processImageForUpload(file) {
    if (file.type === "image/gif") {
      return { blob: file, ext: "gif", mime: "image/gif" };
    }
    return new Promise((resolve, reject) => {
      const url = URL.createObjectURL(file);
      const img = new Image();
      img.onload = () => {
        URL.revokeObjectURL(url);
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

        const canWebp = canvas.toDataURL("image/webp").startsWith("data:image/webp");
        const mime = canWebp ? "image/webp" : "image/jpeg";
        const ext = canWebp ? "webp" : "jpg";
        canvas.toBlob((blob) => {
          if (!blob) return reject(new Error("Не удалось сжать фото"));
          resolve({ blob, ext, mime });
        }, mime, canWebp ? 0.82 : 0.85);
      };
      img.onerror = () => {
        URL.revokeObjectURL(url);
        reject(new Error("Браузер не смог прочитать картинку (если это HEIC с айфона — сделай скрин или выбери JPG)"));
      };
      img.src = url;
    });
  }

  async function extractVideoThumbnail(file) {
    return new Promise((resolve) => {
      const url = URL.createObjectURL(file);
      const video = document.createElement("video");
      video.muted = true;
      video.playsInline = true;
      video.preload = "auto";
      let done = false;

      const finish = (res) => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        URL.revokeObjectURL(url);
        resolve(res);
      };

      const timer = setTimeout(() => finish(null), 5000);

      const captureFrame = () => {
        if (!video.videoWidth || !video.videoHeight) return finish(null);
        const maxW = 640;
        let w = video.videoWidth;
        let h = video.videoHeight;
        if (w > maxW) {
          h = Math.round((h * maxW) / w);
          w = maxW;
        }
        const canvas = document.createElement("canvas");
        canvas.width = w;
        canvas.height = h;
        canvas.getContext("2d").drawImage(video, 0, 0, w, h);

        const canWebp = canvas.toDataURL("image/webp").startsWith("data:image/webp");
        const mime = canWebp ? "image/webp" : "image/jpeg";
        const ext = canWebp ? "webp" : "jpg";
        canvas.toBlob((blob) => {
          if (!blob) return finish(null);
          finish({ blob, ext, mime });
        }, mime, 0.75);
      };

      video.onloadedmetadata = () => {
        try {
          video.currentTime = video.duration && video.duration > 0.6 ? 0.5 : 0.1;
        } catch {
          captureFrame();
        }
      };
      video.onseeked = captureFrame;
      video.onerror = () => finish(null);
      video.src = url;
    });
  }

  // ====== ЗАГРУЗКА ДАННЫХ ======
  async function loadData() {
    let posts = [];
    let users = [];
    let tgStatus = {};
    let avatars = {};

    if (IS_GITHUB_READY) {
      let usedStaticFallback = false;
      try {
        const [pRes, uRes, tRes, aRes] = await Promise.all([
          ghGetFile("data/posts.json"),
          ghGetFile("data/users.json").catch(() => ({ data: [] })),
          ghGetFile("data/tg_status.json").catch(() => ({ data: {} })),
          ghGetFile("data/avatars.json").catch(() => ({ data: {} }))
        ]);
        posts = pRes.data;
        users = uRes.data;
        tgStatus = tRes.data || {};
        avatars = aRes.data || {};
      } catch {
        usedStaticFallback = true;
        const [pLoc, uLoc, tLoc, aLoc] = await Promise.all([
          fetch(`./data/posts.json?t=${Date.now()}`).then(r => r.json()).catch(() => []),
          fetch(`./data/users.json?t=${Date.now()}`).then(r => r.json()).catch(() => []),
          fetch(`./data/tg_status.json?t=${Date.now()}`).then(r => r.json()).catch(() => ({})),
          fetch(`./data/avatars.json?t=${Date.now()}`).then(r => r.json()).catch(() => ({}))
        ]);
        posts = pLoc;
        users = uLoc;
        tgStatus = tLoc || {};
        avatars = aLoc || {};
      }

      if (usedStaticFallback) {
        const opt = JSON.parse(localStorage.getItem(LS_OPTIMISTIC_POSTS) || "[]")
          .filter(item => Date.now() - item._ts < 180000);
        localStorage.setItem(LS_OPTIMISTIC_POSTS, JSON.stringify(opt));
        const mapById = new Map(posts.map(p => [p.id, p]));
        opt.forEach(item => {
          if (!mapById.has(item.id)) posts.unshift(item);
          else {
            const target = mapById.get(item.id);
            target.comments = item.comments || [];
            target.likes = item.likes || [];
          }
        });
      }
    } else {
      try {
        const filePosts = await fetch("./data/posts.json").then(r => r.json());
        posts = JSON.parse(localStorage.getItem(LS_LOCAL_POSTS) || "null") || filePosts;
      } catch {
        posts = JSON.parse(localStorage.getItem(LS_LOCAL_POSTS) || "null") || getFallbackSamplePosts();
      }
      users = JSON.parse(localStorage.getItem(LS_LOCAL_USERS) || "[]");
      avatars = JSON.parse(localStorage.getItem(LS_LOCAL_AVATARS) || "{}");
    }

    state.posts = Array.isArray(posts) ? posts : [];
    state.users = Array.isArray(users) ? users : [];
    state.tgStatus = (tgStatus && typeof tgStatus === "object") ? tgStatus : {};
    state.avatars = (avatars && typeof avatars === "object") ? avatars : {};
  }

  function getFallbackSamplePosts() {
    return [
      {
        id: "book-djan-2025",
        type: "books",
        featured: true,
        title: "Путь к успеху: от пожарного до кочегара (2 часть)",
        bookAuthor: "Джан (Артур Боярский)",
        bookYear: "2025 • 1 стр.",
        author: "Miralys",
        createdAt: "2025-10-05T12:00:00Z",
        text: "История успеха из 2025 года.",
        tags: ["книга", "Джан"]
      }
    ];
  }

  // ====== АВАТАРКИ ======
  const AVATAR_COLORS = ["#194880", "#31a481", "#d9534f", "#ee8950", "#4b64ff", "#6f42c1"];

  function getAvatarInfo(username) {
    const lower = String(username || "").trim().toLowerCase();
    const sess = state.sessionMedia["av_" + lower];
    const url = (state.avatars && state.avatars[lower]) || "";
    const src = sess || url;
    const fb = url ? mediaUrlWithFallback(url) : "";
    const isVideo = /\.(mp4|webm|mov)(\?|$)/i.test(url) || Boolean(state.sessionMedia["av_vid_" + lower]);
    return { src, fb, hasCustom: Boolean(src), isVideo };
  }

  function renderAvatarHtml(username, sizeClass = "av-sm", clickable = false) {
    const name = String(username || "?");
    const { src, fb, hasCustom, isVideo } = getAvatarInfo(name);
    if (hasCustom) {
      const clickAttr = clickable ? `data-zoom-avatar="${esc(name)}" title="Открыть аватар ${esc(name)}"` : "";
      const errAttr = fb ? `onerror="if(!this.dataset.f){this.dataset.f=1;this.src='${esc(fb)}';}"` : "";
      const mediaTag = isVideo
        ? `<video src="${esc(src)}" autoplay loop muted playsinline ${errAttr}></video>`
        : `<img src="${esc(src)}" alt="" ${errAttr}>`;
      return `<span class="user-avatar ${sizeClass} ${clickable ? "av-click" : ""}" ${clickAttr}>${mediaTag}</span>`;
    }
    let h = 0;
    for (let i = 0; i < name.length; i++) h = (h * 31 + name.charCodeAt(i)) | 0;
    const bg = AVATAR_COLORS[Math.abs(h) % AVATAR_COLORS.length];
    const letter = name.trim().charAt(0).toUpperCase() || "?";
    return `<span class="user-avatar ${sizeClass}" style="background:${bg};">${esc(letter)}</span>`;
  }

  function openAvatarLightbox(username) {
    const { src, fb, hasCustom, isVideo } = getAvatarInfo(username);
    if (!hasCustom) return;
    let modal = document.getElementById("modal-avatar-view");
    if (!modal) {
      modal = document.createElement("div");
      modal.id = "modal-avatar-view";
      modal.className = "modal-backdrop hidden";
      modal.innerHTML = `
        <div class="modal-box modal-sm">
          <div class="modal-head">
            <h3 id="av-lb-title">Аватар</h3>
            <button class="modal-close" data-close="modal-avatar-view">✕</button>
          </div>
          <div class="modal-body" id="av-lb-body"></div>
        </div>
      `;
      document.body.appendChild(modal);
      modal.querySelector("[data-close='modal-avatar-view']").addEventListener("click", () => closeModal("modal-avatar-view"));
      modal.addEventListener("click", (e) => { if (e.target === modal) closeModal("modal-avatar-view"); });
    }
    document.getElementById("av-lb-title").textContent = `Аватар: ${username}`;
    const errAttr = fb ? `onerror="if(!this.dataset.f){this.dataset.f=1;this.src='${esc(fb)}';}"` : "";
    document.getElementById("av-lb-body").innerHTML = isVideo
      ? `<video class="avatar-lightbox-img" src="${esc(src)}" autoplay loop muted playsinline controls ${errAttr}></video>`
      : `<img class="avatar-lightbox-img" src="${esc(src)}" alt="${esc(username)}" ${errAttr}>`;
    openModal("modal-avatar-view");
  }

  async function openAvatarCropper(file) {
    if (file.type === "image/gif" && file.size <= 5 * 1024 * 1024) {
      return { blob: file, ext: "gif", mime: "image/gif", isVideo: false };
    }
    if (file.type.startsWith("video/") || /\.(mp4|mov|webm)$/i.test(file.name)) {
      if (file.size > 6 * 1024 * 1024) {
        throw new Error("Видео-аватарка должна быть до 6 МБ (как короткая гифка из ТГ/ТТ)!");
      }
      const ext = (file.name.split(".").pop() || "mp4").toLowerCase().replace(/[^a-z0-9]/g, "");
      return { blob: file, ext: ext === "mov" ? "mp4" : ext, mime: file.type || "video/mp4", isVideo: true };
    }
    const url = URL.createObjectURL(file);
    const img = await new Promise((resolve, reject) => {
      const im = new Image();
      im.onload = () => resolve(im);
      im.onerror = () => {
        URL.revokeObjectURL(url);
        reject(new Error("Не удалось открыть картинку (если это HEIC с айфона — сделай скриншот или выбери JPG)"));
      };
      im.src = url;
    });

    return new Promise((resolve) => {
      let modal = document.getElementById("modal-avatar-crop");
      if (!modal) {
        modal = document.createElement("div");
        modal.id = "modal-avatar-crop";
        modal.className = "modal-backdrop hidden";
        modal.style.zIndex = "260";
        modal.innerHTML = `
          <div class="modal-box modal-sm">
            <div class="modal-head">
              <h3>Выбери область 1:1</h3>
              <button class="modal-close" id="crop-close-x">✕</button>
            </div>
            <div class="modal-body">
              <div class="crop-stage">
                <div class="muted-note" style="margin:0;text-align:center;">Двигай пальцем и зумируй ползунком</div>
                <canvas id="crop-canvas" class="crop-canvas" width="600" height="600"></canvas>
                <div class="crop-zoom-row">
                  <span>🔍</span>
                  <input type="range" id="crop-zoom" min="1" max="4" step="0.02" value="1">
                  <span id="crop-zoom-val">1.0×</span>
                </div>
                <div class="crop-actions">
                  <button type="button" id="crop-cancel-btn" class="btn-secondary" style="flex:1;">Отмена</button>
                  <button type="button" id="crop-ok-btn" class="btn-primary" style="flex:2;">Готово — поставить</button>
                </div>
              </div>
            </div>
          </div>
        `;
        document.body.appendChild(modal);
      }

      const canvas = document.getElementById("crop-canvas");
      const ctx = canvas.getContext("2d");
      const zoomSlider = document.getElementById("crop-zoom");
      const zoomVal = document.getElementById("crop-zoom-val");
      const VIEW = 600;
      const baseScale = Math.max(VIEW / img.width, VIEW / img.height);
      let zoom = 1.0, ox = 0, oy = 0;

      const draw = () => {
        const s = baseScale * zoom;
        const dw = img.width * s;
        const dh = img.height * s;
        const maxOx = Math.max(0, (dw - VIEW) / 2);
        const maxOy = Math.max(0, (dh - VIEW) / 2);
        ox = Math.max(-maxOx, Math.min(maxOx, ox));
        oy = Math.max(-maxOy, Math.min(maxOy, oy));
        const dx = (VIEW - dw) / 2 + ox;
        const dy = (VIEW - dh) / 2 + oy;

        ctx.clearRect(0, 0, VIEW, VIEW);
        ctx.drawImage(img, dx, dy, dw, dh);

        ctx.save();
        ctx.beginPath();
        ctx.rect(0, 0, VIEW, VIEW);
        ctx.arc(VIEW / 2, VIEW / 2, VIEW / 2 - 4, 0, Math.PI * 2, true);
        ctx.fillStyle = "rgba(0, 0, 0, 0.56)";
        ctx.fill("evenodd");
        ctx.beginPath();
        ctx.arc(VIEW / 2, VIEW / 2, VIEW / 2 - 4, 0, Math.PI * 2);
        ctx.strokeStyle = "rgba(255, 255, 255, 0.9)";
        ctx.lineWidth = 4;
        ctx.stroke();
        ctx.restore();

        zoomVal.textContent = `${zoom.toFixed(1)}×`;
      };

      zoomSlider.value = "1";
      draw();
      modal.classList.remove("hidden");

      const activePts = new Map();
      let lastDist = 0;
      const pinchDist = () => {
        const pts = [...activePts.values()];
        return pts.length >= 2 ? Math.hypot(pts[0].x - pts[1].x, pts[0].y - pts[1].y) : 0;
      };

      const onDown = (e) => {
        e.preventDefault();
        canvas.setPointerCapture(e.pointerId);
        activePts.set(e.pointerId, { x: e.clientX, y: e.clientY });
        if (activePts.size === 2) lastDist = pinchDist();
      };
      const onMove = (e) => {
        if (!activePts.has(e.pointerId)) return;
        const prev = activePts.get(e.pointerId);
        const curr = { x: e.clientX, y: e.clientY };
        const pxScale = VIEW / (canvas.getBoundingClientRect().width || VIEW);
        if (activePts.size === 1) {
          ox += (curr.x - prev.x) * pxScale;
          oy += (curr.y - prev.y) * pxScale;
          activePts.set(e.pointerId, curr);
          draw();
        } else if (activePts.size >= 2) {
          activePts.set(e.pointerId, curr);
          const d = pinchDist();
          if (lastDist > 0 && d > 0) {
            zoom = Math.max(1, Math.min(4, zoom * (d / lastDist)));
            zoomSlider.value = zoom.toFixed(2);
            draw();
          }
          lastDist = d;
        }
      };
      const onUp = (e) => {
        activePts.delete(e.pointerId);
        if (activePts.size < 2) lastDist = 0;
      };
      const onWheel = (e) => {
        e.preventDefault();
        zoom = Math.max(1, Math.min(4, zoom - e.deltaY * 0.002));
        zoomSlider.value = zoom.toFixed(2);
        draw();
      };
      const onSlider = () => {
        zoom = parseFloat(zoomSlider.value) || 1;
        draw();
      };

      let finished = false;
      const cleanup = () => {
        canvas.removeEventListener("pointerdown", onDown);
        canvas.removeEventListener("pointermove", onMove);
        canvas.removeEventListener("pointerup", onUp);
        canvas.removeEventListener("pointercancel", onUp);
        canvas.removeEventListener("wheel", onWheel);
        zoomSlider.removeEventListener("input", onSlider);
        document.removeEventListener("keydown", onEsc);
        modal.classList.add("hidden");
        URL.revokeObjectURL(url);
      };
      const finish = (val) => {
        if (finished) return;
        finished = true;
        cleanup();
        resolve(val);
      };
      const onEsc = (e) => { if (e.key === "Escape") finish(null); };

      canvas.addEventListener("pointerdown", onDown);
      canvas.addEventListener("pointermove", onMove);
      canvas.addEventListener("pointerup", onUp);
      canvas.addEventListener("pointercancel", onUp);
      canvas.addEventListener("wheel", onWheel, { passive: false });
      zoomSlider.addEventListener("input", onSlider);
      document.addEventListener("keydown", onEsc);

      document.getElementById("crop-close-x").onclick = () => finish(null);
      document.getElementById("crop-cancel-btn").onclick = () => finish(null);
      modal.onclick = (e) => { if (e.target === modal) finish(null); };

      document.getElementById("crop-ok-btn").onclick = () => {
        const s = baseScale * zoom;
        const dw = img.width * s;
        const dh = img.height * s;
        const dx = (VIEW - dw) / 2 + ox;
        const dy = (VIEW - dh) / 2 + oy;
        const srcX = Math.max(0, -dx / s);
        const srcY = Math.max(0, -dy / s);
        const srcSize = Math.min(img.width - srcX, img.height - srcY, VIEW / s);

        const out = document.createElement("canvas");
        out.width = 512;
        out.height = 512;
        out.getContext("2d").drawImage(img, srcX, srcY, srcSize, srcSize, 0, 0, 512, 512);
        const canWebp = out.toDataURL("image/webp").startsWith("data:image/webp");
        const mime = canWebp ? "image/webp" : "image/jpeg";
        const ext = canWebp ? "webp" : "jpg";
        out.toBlob((blob) => finish(blob ? { blob, ext, mime } : null), mime, 0.88);
      };
    });
  }

  // ====== УМНЫЙ ПОИСК И ФИЛЬТРЫ ======
  const EN_RU_MAP = {
    q:"й", w:"ц", e:"у", r:"к", t:"е", y:"н", u:"г", i:"ш", o:"щ", p:"з", "[":"х", "]":"ъ",
    a:"ф", s:"ы", d:"в", f:"а", g:"п", h:"р", j:"о", k:"л", l:"д", ";":"ж", "'":"э",
    z:"я", x:"ч", c:"с", v:"м", b:"и", n:"т", m:"ь", ",":"б", ".":"ю", "`":"е"
  };

  function enToRuLayout(str) {
    return String(str || "").toLowerCase().split("").map(ch => EN_RU_MAP[ch] || ch).join("");
  }

  function normSearchText(s) {
    return String(s || "")
      .toLowerCase()
      .replace(/ё/g, "е")
      .replace(/[^a-zа-я0-9\s]+/g, " ")
      .replace(/\s+/g, " ")
      .trim();
  }

  function editDistance(a, b, maxDist = 2) {
    const la = a.length, lb = b.length;
    if (Math.abs(la - lb) > maxDist) return maxDist + 1;
    let prev = Array.from({ length: lb + 1 }, (_, j) => j);
    for (let i = 1; i <= la; i++) {
      const curr = [i];
      let rowMin = i;
      for (let j = 1; j <= lb; j++) {
        const cost = a[i - 1] === b[j - 1] ? 0 : 1;
        const val = Math.min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost);
        curr.push(val);
        if (val < rowMin) rowMin = val;
      }
      if (rowMin > maxDist) return maxDist + 1;
      prev = curr;
    }
    return prev[lb];
  }

  function isTightSubseq(sub, word) {
    let si = 0, first = -1, last = -1;
    for (let wi = 0; wi < word.length && si < sub.length; wi++) {
      if (word[wi] === sub[si]) {
        if (first === -1) first = wi;
        last = wi;
        si++;
      }
    }
    return si === sub.length && (last - first + 1) <= sub.length + 3;
  }

  function scorePostMatch(post, rawQuery) {
    const qNorm = normSearchText(rawQuery);
    const qRu = normSearchText(enToRuLayout(rawQuery));
    const queries = qRu && qRu !== qNorm ? [qNorm, qRu] : [qNorm];

    const fields = [
      { text: normSearchText(post.title), weight: 3 },
      { text: normSearchText(post.author), weight: 2.5 },
      { text: normSearchText(post.quoteAuthor), weight: 2.5 },
      { text: normSearchText(post.bookAuthor), weight: 2 },
      { text: normSearchText((post.tags || []).join(" ")), weight: 2 },
      { text: normSearchText(post.text), weight: 1 }
    ];
    const hayWords = fields.map(f => f.text).join(" ").split(" ").filter(Boolean);

    let bestTotal = 0;
    for (const qStr of queries) {
      if (!qStr) continue;
      const tokens = qStr.split(" ").filter(Boolean);
      if (!tokens.length) continue;

      let total = 0;
      let allMatched = true;

      for (const tok of tokens) {
        const tokSquash = tok.replace(/(.)\1+/g, "$1");
        let tokScore = 0;

        for (const f of fields) {
          if (f.text && f.text.includes(tok)) {
            tokScore = Math.max(tokScore, 100 * f.weight);
          }
        }
        if (tokScore === 0) {
          const maxErr = tok.length >= 7 ? 2 : (tok.length >= 4 ? 1 : 0);
          for (const w of hayWords) {
            if (w.startsWith(tok)) {
              tokScore = Math.max(tokScore, 80);
            } else if (tokSquash.length >= 2 && w.replace(/(.)\1+/g, "$1").includes(tokSquash)) {
              tokScore = Math.max(tokScore, 75);
            } else if (maxErr > 0) {
              const dFull = editDistance(tok, w, maxErr);
              const dPref = w.length > tok.length ? editDistance(tok, w.slice(0, tok.length), maxErr) : 99;
              const d = Math.min(dFull, dPref);
              if (d <= maxErr) {
                tokScore = Math.max(tokScore, 55 - d * 15);
              }
            }
            if (tokScore === 0 && tok.length >= 4 && isTightSubseq(tok, w)) {
              tokScore = Math.max(tokScore, 22);
            }
          }
        }
        if (tokScore === 0) {
          allMatched = false;
          break;
        }
        total += tokScore;
      }
      if (allMatched) bestTotal = Math.max(bestTotal, total);
    }
    return bestTotal;
  }

  function ensureFeedControls() {
    if (document.getElementById("feed-controls")) return;
    const grid = document.getElementById("feed-grid");
    const bar = document.createElement("div");
    bar.id = "feed-controls";
    bar.className = "feed-controls";
    bar.innerHTML = `
      <div class="sort-pills">
        <button type="button" class="sort-pill active" data-sort="newest">Новое</button>
        <button type="button" class="sort-pill" data-sort="oldest">Старое</button>
        <button type="button" class="sort-pill" data-sort="likes">Топ лайков</button>
        <button type="button" class="sort-pill" data-sort="comments">Обсуждаемое</button>
      </div>
      <select id="filter-author" class="author-select" aria-label="Фильтр по автору">
        <option value="">Автор: Все</option>
      </select>
    `;
    grid.parentNode.insertBefore(bar, grid);

    bar.querySelectorAll("[data-sort]").forEach(btn => {
      btn.addEventListener("click", () => {
        state.sortBy = btn.dataset.sort;
        bar.querySelectorAll("[data-sort]").forEach(b => b.classList.toggle("active", b === btn));
        renderFeed();
      });
    });

    document.getElementById("filter-author").addEventListener("change", (e) => {
      state.filterAuthor = e.target.value;
      renderFeed();
    });
  }

  function syncFeedControls() {
    ensureFeedControls();
    const sel = document.getElementById("filter-author");
    if (!sel) return;
    const seen = new Map();
    state.posts.forEach(p => {
      const a = String(p.author || "").trim();
      if (a && !seen.has(a.toLowerCase())) seen.set(a.toLowerCase(), a);
    });
    const prevVal = state.filterAuthor;
    sel.innerHTML = `<option value="">Автор: Все</option>` +
      [...seen.entries()].map(([low, orig]) => `<option value="${esc(low)}">${esc(orig)}</option>`).join("");
    sel.value = seen.has(prevVal) ? prevVal : "";
    if (sel.value !== prevVal) state.filterAuthor = "";
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
      <li>Участников в системе: <strong>${regCount}</strong> (+ Создатель)</li>
      <li>Главная реликвия: книга на 1 стр. в разделе <strong>«Книги»</strong></li>
      <li>Вечное хранилище локального лора</li>
    `;
  }

  function mediaUrlWithFallback(src) {
    if (!IS_GITHUB_READY || !src || src.startsWith("data:") || src.startsWith("http") || src.startsWith("blob:")) {
      return "";
    }
    return `https://raw.githubusercontent.com/${GH.owner}/${GH.repo}/${GH.branch || "main"}/${src.replace(/^\.\//, "")}`;
  }

  function getPostImages(post) {
    const sessionVal = state.sessionMedia[post.id];
    const urls = Array.isArray(post.mediaUrls) && post.mediaUrls.length
      ? post.mediaUrls
      : (post.mediaUrl ? [post.mediaUrl] : []);

    const sArr = Array.isArray(sessionVal) ? sessionVal : (sessionVal ? [sessionVal] : []);
    const count = Math.max(sArr.length, urls.length);
    const out = [];
    for (let i = 0; i < count; i++) {
      const src = sArr[i] || urls[i];
      if (!src) continue;
      out.push({ src, fallback: mediaUrlWithFallback(urls[i] || src) });
    }
    return out;
  }

  function formatQuoteHtml(raw) {
    const t = String(raw || "").trim();
    const isDialogue = /(^|\n)\s*[-—–]\s*\S/.test(t) || /(^|\n)\s*[^\n:]{1,24}:\s/.test(t);
    const hasOuterQuotes = /^[«"„]/.test(t) && /[»"“]$/.test(t);
    if (isDialogue || hasOuterQuotes) return esc(t);
    return `«${esc(t)}»`;
  }

  function renderFeed() {
    const grid = document.getElementById("feed-grid");
    const empty = document.getElementById("empty-state");
    const titleEl = document.getElementById("feed-title");
    const statsEl = document.getElementById("feed-stats");

    syncFeedControls();
    titleEl.textContent = TAB_TITLES[state.currentTab] || "Архив";
    const q = state.searchQuery.trim();

    const scored = [];
    for (const p of state.posts) {
      if (state.currentTab !== "all" && p.type !== state.currentTab) continue;
      if (state.filterAuthor && String(p.author || "").trim().toLowerCase() !== state.filterAuthor) continue;
      if (q) {
        const sc = scorePostMatch(p, q);
        if (sc <= 0) continue;
        scored.push({ post: p, score: sc, tier: sc >= 100 ? 2 : 1 });
      } else {
        scored.push({ post: p, score: 0, tier: 2 });
      }
    }

    const postTs = (p) => Date.parse(p.createdAt) || 0;
    scored.sort((a, b) => {
      if (q && b.tier !== a.tier) return b.tier - a.tier;
      if (q && a.tier === 1 && state.sortBy === "newest" && b.score !== a.score) return b.score - a.score;
      if (!q && state.sortBy === "newest") {
        const bf = b.post.featured ? 1 : 0;
        const af = a.post.featured ? 1 : 0;
        if (bf !== af) return bf - af;
      }
      if (state.sortBy === "oldest") return postTs(a.post) - postTs(b.post);
      if (state.sortBy === "likes") {
        const dl = (b.post.likes?.length || 0) - (a.post.likes?.length || 0);
        return dl !== 0 ? dl : postTs(b.post) - postTs(a.post);
      }
      if (state.sortBy === "comments") {
        const dc = (b.post.comments?.length || 0) - (a.post.comments?.length || 0);
        return dc !== 0 ? dc : postTs(b.post) - postTs(a.post);
      }
      return postTs(b.post) - postTs(a.post);
    });

    const filtered = scored.map(x => x.post);

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
      if (post.type === "photos") {
        const imgs = getPostImages(post);
        if (imgs.length) {
          const first = imgs[0];
          const badge = imgs.length > 1 ? `<span class="photo-count-badge">📷 ${imgs.length}</span>` : "";
          thumbHtml = `<img src="${esc(first.src)}" alt="${esc(post.title)}" loading="lazy" ${first.fallback ? `onerror="if(!this.dataset.f){this.dataset.f=1;this.src='${esc(first.fallback)}';}"` : ""}>${badge}`;
        }
      } else if (post.type === "video") {
        const thumbSrc = state.sessionMedia[post.id + "_thumb"] || post.thumbUrl;
        const ytId = extractYouTubeId(post.videoUrl);
        if (thumbSrc) {
          const fb = mediaUrlWithFallback(thumbSrc);
          thumbHtml = `<img src="${esc(thumbSrc)}" alt="${esc(post.title)}" loading="lazy" ${fb ? `onerror="if(!this.dataset.f){this.dataset.f=1;this.src='${esc(fb)}';}"` : ""}><span class="video-badge">▶</span>`;
        } else if (ytId) {
          thumbHtml = `<img src="https://img.youtube.com/vi/${esc(ytId)}/hqdefault.jpg" alt=""><span class="video-badge">▶</span>`;
        } else if (state.sessionMedia[post.id] || post.mediaUrl || post.videoUrl) {
          const vSrc = state.sessionMedia[post.id] || post.mediaUrl || post.videoUrl;
          const fb = mediaUrlWithFallback(vSrc);
          thumbHtml = `<video class="tile-video-preview" src="${esc(vSrc)}#t=0.5" muted playsinline preload="metadata" ${fb ? `onerror="if(!this.dataset.f){this.dataset.f=1;this.src='${esc(fb)}#t=0.5';}"` : ""}></video><span class="video-badge">▶</span>`;
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
        thumbHtml = `<div class="tile-preview-text tile-preview-quote">${formatQuoteHtml(post.text)}</div>`;
      } else {
        thumbHtml = `<div class="tile-preview-text">${esc(post.text || "Без описания")}</div>`;
      }

      const subMeta = post.type === "quotes" && post.quoteAuthor
        ? `© ${post.quoteAuthor}`
        : `Автор: ${post.author || "Анон"}`;
      const comCount = (post.comments || []).length;
      const likes = Array.isArray(post.likes) ? post.likes : [];
      const liked = hasUserLiked(likes);

      return `
        <article class="tile ${isCol ? "tile-collection" : ""}" data-post-id="${esc(post.id)}">
          <div class="tile-thumb">${thumbHtml}</div>
          <div class="tile-body">
            <h3 class="tile-title">${esc(post.title)}</h3>
            <div class="tile-meta tile-meta-wrap">${renderAvatarHtml(post.author, "av-xs")}<span>${esc(subMeta)}</span></div>
          </div>
          <div class="tile-stats">
            <span class="tile-type-badge">${TYPE_ICONS[post.type] || ""} ${esc(labelForType(post.type))}</span>
            <span class="tile-stats-right">
              <button type="button" class="tile-like-btn ${liked ? "liked" : ""}" data-like-post="${esc(post.id)}" title="Лайк">${liked ? "♥" : "♡"} ${likes.length}</button>
              ${comCount > 0 ? `<span>💬 ${comCount}</span>` : ""}
              <span>${formatDate(post.createdAt)}</span>
            </span>
          </div>
        </article>
      `;
    }).join("");
  }

  function labelForType(type) {
    return { thoughts: "Мысль", quotes: "Цитата", video: "Видео", books: "Книга", photos: "Фото" }[type] || type;
  }

  // ====== ЛАЙКИ ПОСТОВ И КОММЕНТАРИЕВ ======
  function syncPostLikeUI(post) {
    const likes = Array.isArray(post.likes) ? post.likes : [];
    const liked = hasUserLiked(likes);

    document.querySelectorAll(`[data-like-post="${CSS.escape(post.id)}"]`).forEach(btn => {
      btn.classList.toggle("liked", liked);
      btn.innerHTML = `${liked ? "♥" : "♡"} ${likes.length}`;
    });

    if (state.activeModalPostId === post.id) {
      renderPostLikeBar(post);
    }
  }

  function renderPostLikeBar(post) {
    const wrap = document.getElementById("view-post-like-wrap");
    if (!wrap) return;
    const likes = Array.isArray(post.likes) ? post.likes : [];
    const liked = hasUserLiked(likes);

    wrap.innerHTML = `
      <div class="post-like-bar">
        <button type="button" id="modal-like-post-btn" class="post-like-btn ${liked ? "liked" : ""}">
          ${liked ? "♥" : "♡"} Нравится · ${likes.length}
        </button>
        <button type="button" id="modal-share-post-btn" class="post-like-btn" title="Скопировать прямую ссылку на пост">
          🔗 Ссылка
        </button>
        ${likes.length ? `<span class="post-liked-by">Оценили: ${likes.map(u => esc(u)).join(", ")}</span>` : ""}
      </div>
    `;

    document.getElementById("modal-like-post-btn").onclick = () => togglePostLike(post.id);
    document.getElementById("modal-share-post-btn").onclick = async () => {
      const shareBtn = document.getElementById("modal-share-post-btn");
      const url = buildPostShareUrl(post.id);
      try {
        if (navigator.clipboard && navigator.clipboard.writeText) {
          await navigator.clipboard.writeText(url);
          shareBtn.textContent = "✓ Скопировано!";
          setTimeout(() => {
            if (document.body.contains(shareBtn)) shareBtn.textContent = "🔗 Ссылка";
          }, 1800);
          return;
        }
      } catch {}
      prompt("Скопируй ссылку на пост:", url);
    };
  }

  async function togglePostLike(postId) {
    if (!state.currentUser) {
      closeModal("modal-view");
      syncAuthModalFields();
      openModal("modal-auth");
      return;
    }
    if (!ensureTokenInteractive()) return;

    const post = state.posts.find(p => p.id === postId);
    if (!post) return;

    const prevLikes = [...(post.likes || [])];
    post.likes = toggleUserInLikes(prevLikes, state.currentUser.username);
    syncPostLikeUI(post);

    try {
      if (IS_GITHUB_READY) {
        const username = state.currentUser.username;
        const freshList = await ghUpdateJson(
          "data/posts.json",
          list => list.map(p => p.id === postId
            ? { ...p, likes: toggleUserInLikes(p.likes, username) }
            : p
          ),
          `Toggle like on ${postId}`
        );
        const freshPost = freshList.find(p => p.id === postId);
        if (freshPost) {
          post.likes = freshPost.likes || [];
          saveOptimisticPost(freshPost);
        }
      } else {
        localStorage.setItem(LS_LOCAL_POSTS, JSON.stringify(state.posts));
      }
      syncPostLikeUI(post);
    } catch (err) {
      post.likes = prevLikes;
      syncPostLikeUI(post);
      alert("Не вышло поставить лайк: " + err.message);
    }
  }

  async function toggleCommentLike(postId, commentId) {
    if (!state.currentUser) {
      closeModal("modal-view");
      syncAuthModalFields();
      openModal("modal-auth");
      return;
    }
    if (!ensureTokenInteractive()) return;

    const post = state.posts.find(p => p.id === postId);
    const comment = post && (post.comments || []).find(c => c.id === commentId);
    if (!post || !comment) return;

    const prevLikes = [...(comment.likes || [])];
    comment.likes = toggleUserInLikes(prevLikes, state.currentUser.username);
    renderCommentsSection(post);

    try {
      if (IS_GITHUB_READY) {
        const username = state.currentUser.username;
        const freshList = await ghUpdateJson(
          "data/posts.json",
          list => list.map(p => p.id === postId
            ? {
                ...p,
                comments: (p.comments || []).map(c => c.id === commentId
                  ? { ...c, likes: toggleUserInLikes(c.likes, username) }
                  : c
                )
              }
            : p
          ),
          `Toggle comment like on ${postId}`
        );
        const freshPost = freshList.find(p => p.id === postId);
        if (freshPost) {
          post.comments = freshPost.comments || [];
          saveOptimisticPost(freshPost);
        }
      } else {
        localStorage.setItem(LS_LOCAL_POSTS, JSON.stringify(state.posts));
      }
      renderCommentsSection(post);
    } catch (err) {
      comment.likes = prevLikes;
      renderCommentsSection(post);
      alert("Не вышло поставить лайк на коммент: " + err.message);
    }
  }

  // ====== ПРОСМОТР ПОСТА И ДРЕВОВИДНЫЕ КОММЕНТАРИИ ======
  function openPostModal(postId, fromHistory = false, focusCommentId = null) {
    const post = state.posts.find(p => p.id === postId);
    if (!post) return;

    state.activeModalPostId = postId;
    state.carouselMove = null;
    state.replyToComment = null;

    if (!fromHistory && getPostIdFromUrl() !== postId) {
      try {
        history.pushState(
          { modalPostId: postId },
          "",
          `${window.location.pathname}${window.location.search}#post=${encodeURIComponent(postId)}`
        );
        state.pushedPostHistory = true;
      } catch {}
    }

    const titleEl = document.getElementById("view-modal-title");
    const bodyEl = document.getElementById("view-modal-body");
    titleEl.textContent = post.title;

    let mainHtml = "";
    const tailHtml = `<div id="view-post-like-wrap"></div>` + buildMetaTable(post) + `<div id="view-comments-wrap"></div>`;

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

      bodyEl.innerHTML = mainHtml + tailHtml;

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
      const imgs = getPostImages(post);
      if (imgs.length <= 1) {
        const one = imgs[0];
        mainHtml = `
          ${one ? `<div class="detail-media"><img src="${esc(one.src)}" alt="${esc(post.title)}" ${one.fallback ? `onerror="if(!this.dataset.f){this.dataset.f=1;this.src='${esc(one.fallback)}';}"` : ""}></div>` : ""}
          ${post.text ? `<div class="detail-thought-box">${esc(post.text)}</div>` : ""}
        `;
        bodyEl.innerHTML = mainHtml + tailHtml;
      } else {
        mainHtml = `
          <div class="carousel-wrap">
            <div class="carousel-stage" id="car-stage">
              <img id="car-main-img" src="${esc(imgs[0].src)}" alt="${esc(post.title)}">
              <button type="button" class="carousel-nav carousel-prev" id="car-prev" aria-label="Назад">‹</button>
              <button type="button" class="carousel-nav carousel-next" id="car-next" aria-label="Вперёд">›</button>
              <div class="carousel-counter" id="car-counter">1 / ${imgs.length}</div>
            </div>
            <div class="carousel-thumbs" id="car-thumbs">
              ${imgs.map((im, i) => `
                <button type="button" class="carousel-thumb ${i === 0 ? "active" : ""}" data-car-idx="${i}">
                  <img src="${esc(im.src)}" alt="" ${im.fallback ? `onerror="if(!this.dataset.f){this.dataset.f=1;this.src='${esc(im.fallback)}';}"` : ""}>
                </button>
              `).join("")}
            </div>
          </div>
          ${post.text ? `<div class="detail-thought-box">${esc(post.text)}</div>` : ""}
        `;
        bodyEl.innerHTML = mainHtml + tailHtml;

        let cur = 0;
        const mainImg = document.getElementById("car-main-img");
        const counterEl = document.getElementById("car-counter");
        const thumbBtns = bodyEl.querySelectorAll(".carousel-thumb");

        const setSlide = (idx) => {
          cur = (idx + imgs.length) % imgs.length;
          const im = imgs[cur];
          mainImg.dataset.f = "";
          mainImg.onerror = im.fallback ? () => {
            if (!mainImg.dataset.f) { mainImg.dataset.f = "1"; mainImg.src = im.fallback; }
          } : null;
          mainImg.src = im.src;
          counterEl.textContent = `${cur + 1} / ${imgs.length}`;
          thumbBtns.forEach((b, i) => {
            b.classList.toggle("active", i === cur);
            if (i === cur) b.scrollIntoView({ behavior: "smooth", inline: "nearest", block: "nearest" });
          });
        };

        setSlide(0);
        document.getElementById("car-prev").onclick = () => setSlide(cur - 1);
        document.getElementById("car-next").onclick = () => setSlide(cur + 1);
        thumbBtns.forEach(b => {
          b.onclick = () => setSlide(Number(b.dataset.carIdx));
        });

        let touchX = 0;
        const stage = document.getElementById("car-stage");
        stage.addEventListener("touchstart", (e) => { touchX = e.changedTouches[0].clientX; }, { passive: true });
        stage.addEventListener("touchend", (e) => {
          const dx = e.changedTouches[0].clientX - touchX;
          if (Math.abs(dx) > 40) setSlide(dx < 0 ? cur + 1 : cur - 1);
        }, { passive: true });

        state.carouselMove = (dir) => setSlide(cur + dir);
      }
    } else if (post.type === "video") {
      const src = state.sessionMedia[post.id] || post.mediaUrl || "";
      const ytId = extractYouTubeId(post.videoUrl);
      const vSrc = src || post.videoUrl || "";
      const fb = mediaUrlWithFallback(vSrc);
      let mediaEl = "";
      if (ytId) {
        mediaEl = `<div class="detail-media"><iframe src="https://www.youtube.com/embed/${esc(ytId)}" allowfullscreen></iframe></div>`;
      } else if (vSrc) {
        mediaEl = `<div class="detail-media"><video src="${esc(vSrc)}" controls playsinline ${fb ? `onerror="if(!this.dataset.f){this.dataset.f=1;this.src='${esc(fb)}';}"` : ""}></video></div>`;
      }
      bodyEl.innerHTML = `${mediaEl}${post.text ? `<div class="detail-thought-box">${esc(post.text)}</div>` : ""}` + tailHtml;
    } else if (post.type === "quotes") {
      mainHtml = `
        <div class="detail-quote-box">
          <div class="detail-quote-text">${formatQuoteHtml(post.text)}</div>
          ${post.quoteAuthor ? `<div class="detail-quote-author">— ${esc(post.quoteAuthor)}</div>` : ""}
        </div>`;
      bodyEl.innerHTML = mainHtml + tailHtml;
    } else {
      mainHtml = `<div class="detail-thought-box">${esc(post.text)}</div>`;
      bodyEl.innerHTML = mainHtml + tailHtml;
    }

    const delBtn = document.getElementById("view-delete-btn");
    if (delBtn) delBtn.onclick = () => deletePost(post.id);
    const pinBtn = document.getElementById("view-pin-btn");
    if (pinBtn) pinBtn.onclick = () => togglePinPost(post.id);
    const editBtn = document.getElementById("view-edit-btn");
    if (editBtn) editBtn.onclick = () => openEditPostModal(post.id);

    if (focusCommentId && Array.isArray(post.comments)) {
      expandAncestorsFor(post.comments, focusCommentId);
    }

    renderPostLikeBar(post);
    renderCommentsSection(post);
    openModal("modal-view");

    if (focusCommentId) {
      setTimeout(() => {
        const el = document.querySelector(`.comment-item[data-comment-id="${CSS.escape(focusCommentId)}"]`);
        if (el) {
          el.scrollIntoView({ behavior: "smooth", block: "center" });
          el.classList.add("comment-highlight");
          setTimeout(() => {
            if (document.body.contains(el)) el.classList.remove("comment-highlight");
          }, 3500);
        }
      }, 120);
    }
  }

  function buildCommentTree(comments) {
    const list = Array.isArray(comments) ? comments : [];
    const byId = new Map();
    list.forEach(c => {
      if (c && c.id) byId.set(c.id, { ...c, children: [], descCount: 0 });
    });

    const roots = [];
    list.forEach(c => {
      if (!c || !c.id) return;
      const node = byId.get(c.id);
      if (c.parentId && c.parentId !== c.id && byId.has(c.parentId)) {
        byId.get(c.parentId).children.push(node);
      } else {
        roots.push(node);
      }
    });

    const countDesc = (node, seen = new Set()) => {
      if (seen.has(node.id)) return 0;
      seen.add(node.id);
      let total = 0;
      for (const ch of node.children) {
        total += 1 + countDesc(ch, seen);
      }
      node.descCount = total;
      return total;
    };
    roots.forEach(r => countDesc(r));

    return { roots, byId };
  }

  function renderCommentNode(node, depth, seen = new Set()) {
    if (seen.has(node.id)) return "";
    seen.add(node.id);

    const isCreatorComment = (node.author || "").toLowerCase() === "miralys";
    const canDelComment = state.currentUser && (
      state.currentUser.isCreator ||
      state.currentUser.username.toLowerCase() === (node.author || "").toLowerCase()
    );

    const likes = Array.isArray(node.likes) ? node.likes : [];
    const liked = hasUserLiked(likes);
    const likedTitle = likes.length ? `Оценили: ${likes.join(", ")}` : "Лайкнуть";

    const hasReplies = node.children.length > 0;
    let isExpanded;
    if (state.threadToggles[node.id] !== undefined) {
      isExpanded = state.threadToggles[node.id];
    } else {
      isExpanded = depth < 2 && node.descCount <= 3;
    }

    const isReplyingHere = state.replyToComment && state.replyToComment.id === node.id;

    const inlineReplyHtml = isReplyingHere ? `
      <form id="inline-reply-form" class="inline-reply-box comment-form">
        <div class="inline-reply-head">
          <span>Ответ для <strong>@${esc(node.author)}</strong></span>
          <button type="button" id="inline-reply-cancel" class="comment-cancel-btn">Отмена</button>
        </div>
        <textarea id="inline-reply-input" rows="2" required placeholder="Напиши ответ..."></textarea>
        <div style="display:flex;justify-content:flex-end;">
          <button type="submit" id="inline-reply-submit" class="btn-primary">Отправить ответ</button>
        </div>
      </form>
    ` : "";

    const repliesHtml = hasReplies && isExpanded
      ? `<div class="comment-replies ${depth >= 2 ? "depth-capped" : ""}">
           ${node.children.map(ch => renderCommentNode(ch, depth + 1, seen)).join("")}
         </div>`
      : "";

    return `
      <div class="comment-node">
        <div class="comment-item" data-comment-id="${esc(node.id)}">
          <div class="comment-head">
            <div class="comment-author-wrap">
              ${renderAvatarHtml(node.author, "av-sm", true)}
              <span class="comment-author">${esc(node.author)}</span>
              ${isCreatorComment ? `<span class="comment-creator-tag">Создатель</span>` : ""}
              ${node.replyTo ? `<span class="comment-reply-badge">↪ @${esc(node.replyTo)}</span>` : ""}
            </div>
            <div class="comment-meta-right">
              <span>${formatDateTime(node.createdAt)}</span>
              ${canDelComment ? `<button type="button" class="comment-del-btn" data-del-comment="${esc(node.id)}" title="Удалить">✕</button>` : ""}
            </div>
          </div>
          <div class="comment-body">${esc(node.text)}</div>
          <div class="comment-actions">
            <button type="button" class="comment-like-btn ${liked ? "liked" : ""}" data-like-comment="${esc(node.id)}" title="${esc(likedTitle)}">
              ${liked ? "♥" : "♡"}${likes.length ? ` ${likes.length}` : ""}
            </button>
            <button type="button" class="comment-action-btn" data-reply-id="${esc(node.id)}" data-reply-author="${esc(node.author)}">Ответить</button>
            ${hasReplies ? `
              <button type="button" class="comment-action-btn comment-toggle-btn" data-toggle-thread="${esc(node.id)}">
                ${isExpanded ? `▾ Свернуть (${node.descCount})` : `▸ Развернуть (${node.descCount})`}
              </button>
            ` : ""}
          </div>
          ${inlineReplyHtml}
        </div>
        ${repliesHtml}
      </div>
    `;
  }

  function renderCommentsSection(post) {
    const wrap = document.getElementById("view-comments-wrap");
    if (!wrap) return;
    const comments = Array.isArray(post.comments) ? post.comments : [];
    const { roots } = buildCommentTree(comments);

    const listHtml = roots.length
      ? roots.map(r => renderCommentNode(r, 0)).join("")
      : `<div class="muted-note">Комментариев пока нет. Будь первым!</div>`;

    const formHtml = state.currentUser
      ? `
        <form id="comment-form" class="comment-form">
          <textarea id="comment-input" rows="2" required placeholder="Написать комментарий..."></textarea>
          <div style="display:flex;justify-content:flex-end;">
            <button type="submit" id="comment-submit-btn" class="btn-primary">Отправить</button>
          </div>
        </form>
      `
      : `
        <div class="comment-login-prompt">
          <span>Хочешь лайкать или комментить? Войди в аккаунт!</span>
          <button type="button" id="comment-login-btn" class="btn-secondary">Войти / Рега</button>
        </div>
      `;

    wrap.innerHTML = `
      <div class="comments-section">
        <h4 class="comments-title">Комментарии (${comments.length})</h4>
        <div class="comments-list">${listHtml}</div>
        ${formHtml}
      </div>
    `;

    const cForm = document.getElementById("comment-form");
    if (cForm) {
      cForm.onsubmit = async (e) => {
        e.preventDefault();
        const input = document.getElementById("comment-input");
        const text = input.value.trim();
        if (!text) return;
        await handleAddComment(post.id, text, null, "");
      };
    }

    wrap.querySelectorAll("[data-like-comment]").forEach(btn => {
      btn.onclick = () => toggleCommentLike(post.id, btn.dataset.likeComment);
    });

    wrap.querySelectorAll("[data-reply-id]").forEach(btn => {
      btn.onclick = () => {
        if (!state.currentUser) {
          closeModal("modal-view");
          syncAuthModalFields();
          openModal("modal-auth");
          return;
        }
        const id = btn.dataset.replyId;
        const author = btn.dataset.replyAuthor;
        state.replyToComment = (state.replyToComment && state.replyToComment.id === id)
          ? null
          : { id, author };
        renderCommentsSection(post);
        if (state.replyToComment) {
          const inp = document.getElementById("inline-reply-input");
          if (inp) inp.focus();
        }
      };
    });

    const inlineForm = document.getElementById("inline-reply-form");
    if (inlineForm && state.replyToComment) {
      inlineForm.onsubmit = async (e) => {
        e.preventDefault();
        const text = document.getElementById("inline-reply-input").value.trim();
        if (!text) return;
        await handleAddComment(post.id, text, state.replyToComment.id, state.replyToComment.author);
      };
      document.getElementById("inline-reply-cancel").onclick = () => {
        state.replyToComment = null;
        renderCommentsSection(post);
      };
    }

    wrap.querySelectorAll("[data-toggle-thread]").forEach(btn => {
      btn.onclick = () => {
        const tid = btn.dataset.toggleThread;
        const currentlyExpanded = btn.textContent.trim().startsWith("▾");
        state.threadToggles[tid] = !currentlyExpanded;
        renderCommentsSection(post);
      };
    });

    const cLoginBtn = document.getElementById("comment-login-btn");
    if (cLoginBtn) {
      cLoginBtn.onclick = () => {
        closeModal("modal-view");
        syncAuthModalFields();
        openModal("modal-auth");
      };
    }

    wrap.querySelectorAll("[data-del-comment]").forEach(btn => {
      btn.onclick = () => handleDeleteComment(post.id, btn.dataset.delComment);
    });
  }

  function expandAncestorsFor(comments, startId) {
    const byId = new Map((comments || []).map(c => [c.id, c]));
    let cur = startId;
    const guard = new Set();
    while (cur && !guard.has(cur)) {
      guard.add(cur);
      state.threadToggles[cur] = true;
      const node = byId.get(cur);
      cur = node ? node.parentId : null;
    }
  }

  async function handleAddComment(postId, text, parentId = null, replyTo = "") {
    if (!ensureTokenInteractive()) return;
    const btn = parentId
      ? document.getElementById("inline-reply-submit")
      : document.getElementById("comment-submit-btn");
    if (btn) { btn.disabled = true; btn.textContent = "Отправляем..."; }

    const newComment = {
      id: `c-${Date.now()}-${Math.random().toString(36).slice(2, 5)}`,
      author: state.currentUser.username,
      text,
      likes: [],
      createdAt: new Date().toISOString()
    };
    if (parentId) {
      newComment.parentId = parentId;
      newComment.replyTo = replyTo;
    }

    try {
      if (IS_GITHUB_READY) {
        state.posts = await ghUpdateJson(
          "data/posts.json",
          list => list.map(p => p.id === postId ? { ...p, comments: [...(p.comments || []), newComment] } : p),
          `Comment on ${postId}`
        );
        const updated = state.posts.find(p => p.id === postId);
        if (updated) saveOptimisticPost(updated);
      } else {
        state.posts = state.posts.map(p => p.id === postId ? { ...p, comments: [...(p.comments || []), newComment] } : p);
        localStorage.setItem(LS_LOCAL_POSTS, JSON.stringify(state.posts));
      }

      const freshPost = state.posts.find(p => p.id === postId);
      state.replyToComment = null;
      if (freshPost) {
        if (parentId) expandAncestorsFor(freshPost.comments, parentId);
        renderCommentsSection(freshPost);
      }
      renderFeed();
    } catch (err) {
      alert("Не вышло отправить коммент: " + err.message);
      if (btn) { btn.disabled = false; btn.textContent = parentId ? "Отправить ответ" : "Отправить"; }
    }
  }

  async function handleDeleteComment(postId, commentId) {
    const post = state.posts.find(p => p.id === postId);
    const list = post ? (post.comments || []) : [];

    const toDelete = new Set([commentId]);
    let added = true;
    while (added) {
      added = false;
      for (const c of list) {
        if (c.parentId && toDelete.has(c.parentId) && !toDelete.has(c.id)) {
          toDelete.add(c.id);
          added = true;
        }
      }
    }

    const msg = toDelete.size > 1
      ? `Удалить комментарий и все ответы в ветке (${toDelete.size - 1} шт.)?`
      : "Удалить этот комментарий?";
    if (!confirm(msg)) return;
    if (!ensureTokenInteractive()) return;

    try {
      if (IS_GITHUB_READY) {
        state.posts = await ghUpdateJson(
          "data/posts.json",
          postsArr => postsArr.map(p => p.id === postId
            ? { ...p, comments: (p.comments || []).filter(c => !toDelete.has(c.id)) }
            : p
          ),
          `Delete comment on ${postId}`
        );
        const updated = state.posts.find(p => p.id === postId);
        if (updated) saveOptimisticPost(updated);
      } else {
        state.posts = state.posts.map(p => p.id === postId
          ? { ...p, comments: (p.comments || []).filter(c => !toDelete.has(c.id)) }
          : p
        );
        localStorage.setItem(LS_LOCAL_POSTS, JSON.stringify(state.posts));
      }

      const freshPost = state.posts.find(p => p.id === postId);
      if (freshPost) renderCommentsSection(freshPost);
      renderFeed();
    } catch (err) {
      alert("Ошибка удаления коммента: " + err.message);
    }
  }

  function saveOptimisticPost(post) {
    const opt = JSON.parse(localStorage.getItem(LS_OPTIMISTIC_POSTS) || "[]").filter(p => p.id !== post.id);
    opt.unshift({ ...post, _ts: Date.now() });
    localStorage.setItem(LS_OPTIMISTIC_POSTS, JSON.stringify(opt));
  }

  function buildMetaTable(post) {
    const isDev = isCreatorUser();
    const canDelete = state.currentUser && (
      isDev ||
      state.currentUser.username.toLowerCase() === (post.author || "").toLowerCase()
    );
    return `
      <table class="detail-meta-table">
        <tr><td>Раздел</td><td>${esc(labelForType(post.type))}</td></tr>
        <tr><td>Опубликовал</td><td><span class="tile-meta-wrap">${renderAvatarHtml(post.author, "av-sm", true)}<span>${esc(post.author || "Аноним")}</span></span></td></tr>
        <tr><td>Дата архивации</td><td>${formatDate(post.createdAt)}</td></tr>
        ${post.tags && post.tags.length ? `<tr><td>Теги</td><td>${post.tags.map(t => `#${esc(t)}`).join(" ")}</td></tr>` : ""}
      </table>
      ${(canDelete || isDev) ? `
        <div class="dev-actions-row">
          ${isDev ? `<button type="button" id="view-pin-btn" class="btn-secondary">${post.featured ? "Открепить" : "📌 Закрепить"}</button>` : ""}
          ${isDev ? `<button type="button" id="view-edit-btn" class="btn-secondary">✏️ Редактировать</button>` : ""}
          ${canDelete ? `<button type="button" id="view-delete-btn" class="btn-danger">Удалить из архива</button>` : ""}
        </div>
      ` : ""}
    `;
  }

  async function togglePinPost(postId) {
    if (!isCreatorUser() || !ensureTokenInteractive()) return;
    const btn = document.getElementById("view-pin-btn");
    if (btn) btn.disabled = true;
    try {
      if (IS_GITHUB_READY) {
        state.posts = await ghUpdateJson(
          "data/posts.json",
          list => list.map(p => p.id === postId ? { ...p, featured: !p.featured } : p),
          `Update author toggle pin ${postId}`
        );
        const up = state.posts.find(p => p.id === postId);
        if (up) saveOptimisticPost(up);
      } else {
        state.posts = state.posts.map(p => p.id === postId ? { ...p, featured: !p.featured } : p);
        localStorage.setItem(LS_LOCAL_POSTS, JSON.stringify(state.posts));
      }
      renderFeed();
      openPostModal(postId, true);
    } catch (err) {
      alert("Не вышло закрепить: " + err.message);
      if (btn) btn.disabled = false;
    }
  }

  function openEditPostModal(postId) {
    if (!isCreatorUser()) return;
    const post = state.posts.find(p => p.id === postId);
    if (!post) return;

    let modal = document.getElementById("modal-edit-post");
    if (!modal) {
      modal = document.createElement("div");
      modal.id = "modal-edit-post";
      modal.className = "modal-backdrop hidden";
      modal.style.zIndex = "250";
      modal.innerHTML = `
        <div class="modal-box modal-md">
          <div class="modal-head">
            <h3>✏️ Редактор поста (Dev)</h3>
            <button class="modal-close" data-close="modal-edit-post">✕</button>
          </div>
          <div class="modal-body" id="edit-post-body"></div>
        </div>
      `;
      document.body.appendChild(modal);
      modal.querySelector("[data-close='modal-edit-post']").addEventListener("click", () => closeModal("modal-edit-post"));
      modal.addEventListener("click", (e) => { if (e.target === modal) closeModal("modal-edit-post"); });
    }

    document.getElementById("edit-post-body").innerHTML = `
      <form id="edit-post-form" class="ia-form">
        <label>Заголовок<input type="text" id="ep-title" required value="${esc(post.title || "")}"></label>
        <div class="form-row-2">
          <label>Автор поста<input type="text" id="ep-author" required value="${esc(post.author || "")}"></label>
          <label>Дата публикации<input type="datetime-local" id="ep-date" value="${esc(toLocalInputValue(post.createdAt))}"></label>
        </div>
        ${post.type === "quotes" ? `<label>Чья цитата<input type="text" id="ep-quote-author" value="${esc(post.quoteAuthor || "")}"></label>` : ""}
        ${post.type === "books" ? `
          <div class="form-row-2">
            <label>Автор книги<input type="text" id="ep-book-author" value="${esc(post.bookAuthor || "")}"></label>
            <label>Эпоха / год<input type="text" id="ep-book-year" value="${esc(post.bookYear || "")}"></label>
          </div>` : ""}
        <label>Текст<textarea id="ep-text" rows="5"></textarea></label>
        <label>Теги (через запятую)<input type="text" id="ep-tags" value="${esc((post.tags || []).join(", "))}"></label>
        <div id="ep-err" class="form-error hidden"></div>
        <button type="submit" id="ep-save-btn" class="btn-primary full-btn">Сохранить изменения</button>
      </form>
    `;
    document.getElementById("ep-text").value = post.text || "";

    document.getElementById("edit-post-form").onsubmit = async (e) => {
      e.preventDefault();
      if (!ensureTokenInteractive()) return;
      const btn = document.getElementById("ep-save-btn");
      btn.disabled = true;
      btn.textContent = "Сохраняем...";

      const dateVal = document.getElementById("ep-date").value;
      let nextIso = post.createdAt;
      if (dateVal) {
        const d = new Date(dateVal);
        if (!isNaN(d.getTime())) nextIso = d.toISOString();
      }

      const patchObj = {
        title: document.getElementById("ep-title").value.trim() || post.title,
        author: document.getElementById("ep-author").value.trim() || post.author,
        text: document.getElementById("ep-text").value.trim(),
        tags: document.getElementById("ep-tags").value.split(",").map(s => s.trim()).filter(Boolean),
        createdAt: nextIso
      };
      const qa = document.getElementById("ep-quote-author");
      if (qa) patchObj.quoteAuthor = qa.value.trim();
      const ba = document.getElementById("ep-book-author");
      if (ba) patchObj.bookAuthor = ba.value.trim();
      const by = document.getElementById("ep-book-year");
      if (by) patchObj.bookYear = by.value.trim();

      try {
        if (IS_GITHUB_READY) {
          state.posts = await ghUpdateJson(
            "data/posts.json",
            list => list.map(p => p.id === postId ? { ...p, ...patchObj } : p),
            `Update author edit post ${postId}`
          );
          const up = state.posts.find(p => p.id === postId);
          if (up) saveOptimisticPost(up);
        } else {
          state.posts = state.posts.map(p => p.id === postId ? { ...p, ...patchObj } : p);
          localStorage.setItem(LS_LOCAL_POSTS, JSON.stringify(state.posts));
        }
        closeModal("modal-edit-post");
        renderFeed();
        openPostModal(postId, true);
      } catch (err) {
        const er = document.getElementById("ep-err");
        er.textContent = "Ошибка сохранения: " + err.message;
        er.classList.remove("hidden");
        btn.disabled = false;
        btn.textContent = "Сохранить изменения";
      }
    };

    openModal("modal-edit-post");
  }

  async function deletePost(postId) {
    if (!confirm("Точно выпилить эту запись (и её файлы) из архива?")) return;
    if (!ensureTokenInteractive()) return;

    const target = state.posts.find(p => p.id === postId);
    const delBtn = document.getElementById("view-delete-btn");
    if (delBtn) {
      delBtn.disabled = true;
      delBtn.textContent = "Удаляем...";
    }

    try {
      if (IS_GITHUB_READY) {
        await ghUpdateJson("data/posts.json", list => list.filter(p => p.id !== postId), `Delete post ${postId}`);

        const opt = JSON.parse(localStorage.getItem(LS_OPTIMISTIC_POSTS) || "[]").filter(p => p.id !== postId);
        localStorage.setItem(LS_OPTIMISTIC_POSTS, JSON.stringify(opt));

        const allMedia = [target?.mediaUrl, ...(target?.mediaUrls || []), target?.thumbUrl];
        const pathsToRemove = [...new Set(
          allMedia.filter(u => u && u.startsWith("./uploads/")).map(u => u.replace(/^\.\//, ""))
        )];

        for (const p of pathsToRemove) {
          try {
            await ghDeleteFile(p, `Delete media for ${postId}`);
          } catch (err) {
            console.warn("Не вышло снести файл:", p, err);
          }
        }
      } else {
        const next = state.posts.filter(p => p.id !== postId);
        localStorage.setItem(LS_LOCAL_POSTS, JSON.stringify(next));
      }

      state.posts = state.posts.filter(p => p.id !== postId);
      closeModal("modal-view");
      updateCounts();
      renderFeed();
    } catch (err) {
      alert("Не удалось удалить: " + err.message);
      if (delBtn) {
        delBtn.disabled = false;
        delBtn.textContent = "Удалить из архива";
      }
    }
  }

  // ====== ПРОФИЛЬ, СМЕНА НИКА И ПРИВЯЗКА TELEGRAM ======
  function renameUserInPosts(postsList, oldLower, newName) {
    const swapName = (val) => (String(val || "").toLowerCase() === oldLower ? newName : val);
    const swapArr = (arr) => (Array.isArray(arr) ? arr.map(swapName) : arr);
    return (Array.isArray(postsList) ? postsList : []).map(p => ({
      ...p,
      author: swapName(p.author),
      likes: swapArr(p.likes),
      comments: Array.isArray(p.comments)
        ? p.comments.map(c => ({
            ...c,
            author: swapName(c.author),
            replyTo: c.replyTo ? swapName(c.replyTo) : c.replyTo,
            likes: swapArr(c.likes)
          }))
        : p.comments
    }));
  }

  function ensureProfileModal() {
    let modal = document.getElementById("modal-profile");
    if (modal) return modal;

    modal = document.createElement("div");
    modal.id = "modal-profile";
    modal.className = "modal-backdrop hidden";
    modal.innerHTML = `
      <div class="modal-box modal-sm">
        <div class="modal-head">
          <h3>Мой аккаунт</h3>
          <button class="modal-close" data-close="modal-profile">✕</button>
        </div>
        <div class="modal-body" id="profile-modal-body"></div>
      </div>
    `;
    document.body.appendChild(modal);

    modal.querySelector("[data-close='modal-profile']").addEventListener("click", () => closeModal("modal-profile"));
    modal.addEventListener("click", (e) => {
      if (e.target === modal) closeModal("modal-profile");
    });
    return modal;
  }

  function renderProfileBody() {
    if (!state.currentUser) return;
    const body = document.getElementById("profile-modal-body");
    if (!body) return;

    const myLower = state.currentUser.username.toLowerCase();
    const isLinked = Boolean(state.tgStatus && state.tgStatus[myLower]);
    const botUser = (CFG.TG_BOT_USERNAME || "debinpost_bot").replace(/^@/, "");

    if (!state.pendingTgCode) {
      state.pendingTgCode = "D" + (Math.random().toString(36) + "0000000").slice(2, 9).toUpperCase();
    }

    const tgBlock = IS_GITHUB_READY ? (
      isLinked
        ? `
          <div class="tg-link-box tg-linked">
            <div><strong>Почта Дебина (Telegram):</strong> ✅ Привязано</div>
            <div class="muted-note" style="margin:0.4rem 0 0.8rem;">
              Личные уведомления о постах, лайках и ответах идут к тебе в @${esc(botUser)}.
            </div>
            <button type="button" id="tg-unlink-btn" class="btn-secondary full-btn">Отвязать Telegram</button>
            <div id="tg-link-msg" class="form-status hidden" style="margin-top:0.8rem;"></div>
          </div>
        `
        : `
          <div class="tg-link-box">
            <div><strong>Почта Дебина (Telegram):</strong> не привязана</div>
            <div class="muted-note" style="margin:0.4rem 0 0.9rem;">
              Привяжи бота — никто другой не сможет занять твой ник. Уведомления будут приходить только в личку.
            </div>
            <a href="https://t.me/${esc(botUser)}?start=${esc(state.pendingTgCode)}" target="_blank" rel="noopener" class="btn-secondary full-btn" style="display:block;text-align:center;text-decoration:none;margin-bottom:0.8rem;">
              1. Открыть @${esc(botUser)} и нажать START
            </a>
            <button type="button" id="tg-confirm-btn" class="btn-primary full-btn">
              2. Я нажал(а) START — привязать
            </button>
            <div id="tg-link-msg" class="form-status hidden" style="margin-top:0.8rem;"></div>
          </div>
        `
    ) : "";

    const dp = (state.presence && state.presence.devPrefs) || { showOnline: false, showLastSeen: false };
    const devStealthSection = isCreatorUser()
      ? `
        <div class="dev-panel-box">
          <div class="dev-panel-title">🥷 Невидимка Создателя</div>
          <label class="toggle-row">
            <span>Показывать, что я онлайн</span>
            <input type="checkbox" id="dev-toggle-online" ${dp.showOnline ? "checked" : ""}>
          </label>
          <label class="toggle-row">
            <span>Показывать, когда был в сети</span>
            <input type="checkbox" id="dev-toggle-lastseen" ${dp.showLastSeen ? "checked" : ""}>
          </label>
        </div>
      `
      : "";

    const renameSection = state.currentUser.isCreator
      ? `${devStealthSection}<p class="muted-note">Создатель <strong>Miralys</strong> — имя неприкасаемое, менять нельзя.</p>`
      : `
        <form id="profile-rename-form" class="ia-form" style="margin-bottom:1.4rem;">
          <label>
            Новый никнейм (пароль останется старый)
            <input type="text" id="profile-new-name" required maxlength="24" value="${esc(state.currentUser.username)}" autocomplete="off">
          </label>
          <div id="profile-error" class="form-error hidden"></div>
          <div id="profile-status" class="form-status hidden"></div>
          <button type="submit" id="profile-rename-btn" class="btn-primary full-btn">Сменить никнейм</button>
        </form>
      `;

    const myAv = getAvatarInfo(state.currentUser.username);
    body.innerHTML = `
      <div class="user-row ${state.currentUser.isCreator ? "creator-row" : ""}" style="margin-bottom:0.8rem;">
        <div class="user-row-left">
          ${renderAvatarHtml(state.currentUser.username, "av-lg", true)}
          <div>
            <strong>${esc(state.currentUser.username)}</strong>
            <div class="muted-note" style="margin:0;">Текущий профиль</div>
          </div>
        </div>
        <span class="${state.currentUser.isCreator ? "badge-creator" : "badge-member"}">${state.currentUser.isCreator ? "Создатель" : "Участник"}</span>
      </div>
      <div class="avatar-controls">
        <input type="file" id="profile-avatar-input" accept="image/*,video/mp4,video/webm,video/quicktime" class="hidden">
        <button type="button" id="profile-avatar-btn" class="btn-secondary" style="flex:1;">📷 ${myAv.hasCustom ? "Сменить аватар" : "Загрузить аватар"}</button>
        ${myAv.hasCustom ? `<button type="button" id="profile-avatar-del-btn" class="btn-danger">Убрать</button>` : ""}
      </div>
      <div id="profile-av-status" class="form-status hidden" style="margin-bottom:1rem;"></div>
      ${tgBlock}
      ${renameSection}
      <div style="border-top:1px solid #eee;padding-top:1.2rem;">
        <button type="button" id="profile-logout-btn" class="btn-danger full-btn">Выйти из аккаунта</button>
      </div>
    `;

    const avBtn = document.getElementById("profile-avatar-btn");
    const avInp = document.getElementById("profile-avatar-input");
    const avDel = document.getElementById("profile-avatar-del-btn");
    if (avBtn && avInp) {
      avBtn.onclick = () => avInp.click();
      avInp.onchange = async () => {
        const f = avInp.files && avInp.files[0];
        avInp.value = "";
        if (!f) return;
        if (!ensureTokenInteractive()) return;
        let proc;
        try {
          proc = await openAvatarCropper(f);
        } catch (err) {
          return alert("Не вышло открыть картинку: " + err.message);
        }
        if (!proc) return;
        avBtn.disabled = true;
        avBtn.textContent = "Загружаем аву...";
        try {
          const safeKey = myLower.replace(/[^a-z0-9_-]/g, "") || "u";
          const filePath = `uploads/av_${safeKey}_${Date.now()}.${proc.ext}`;
          const prevPath = (state.avatars && state.avatars[myLower]) || "";
          const blobUrl = URL.createObjectURL(proc.blob);
          state.sessionMedia["av_" + myLower] = blobUrl;
          state.sessionMedia["av_vid_" + myLower] = Boolean(proc.isVideo);

          let savedVal = blobUrl;
          if (IS_GITHUB_READY) {
            await ghPutRaw(filePath, await blobToBase64(proc.blob), `Upload avatar for ${state.currentUser.username}`);
            savedVal = `./${filePath}`;
            state.avatars = await ghUpdateJson("data/avatars.json", obj => ({ ...(obj || {}), [myLower]: savedVal }), `Set avatar for ${state.currentUser.username}`, {});
            if (prevPath && prevPath.startsWith("./uploads/")) {
              enqueueGhWrite(() => ghDeleteFile(prevPath.replace(/^\.\//, ""), `Remove old avatar for ${state.currentUser.username}`)).catch(() => {});
            }
          } else {
            savedVal = `data:${proc.mime};base64,${await blobToBase64(proc.blob)}`;
            state.avatars[myLower] = savedVal;
            localStorage.setItem(LS_LOCAL_AVATARS, JSON.stringify(state.avatars));
          }
          renderProfileBody();
          updateAuthUI();
          renderFeed();
          const st2 = document.getElementById("profile-av-status");
          if (st2) { st2.textContent = "✅ Аватар обновлён!"; st2.classList.remove("hidden"); }
        } catch (err) {
          alert("Не вышло поставить аву: " + err.message);
          avBtn.disabled = false;
          avBtn.textContent = "📷 Загрузить аватар";
        }
      };
    }
    if (avDel) {
      avDel.onclick = async () => {
        if (!confirm("Удалить аватарку?")) return;
        if (!ensureTokenInteractive()) return;
        avDel.disabled = true;
        try {
          const prevPath = (state.avatars && state.avatars[myLower]) || "";
          delete state.sessionMedia["av_" + myLower];
          delete state.sessionMedia["av_vid_" + myLower];
          if (IS_GITHUB_READY) {
            state.avatars = await ghUpdateJson("data/avatars.json", obj => {
              const next = { ...(obj || {}) };
              delete next[myLower];
              return next;
            }, `Remove avatar for ${state.currentUser.username}`, {});
            if (prevPath && prevPath.startsWith("./uploads/")) {
              enqueueGhWrite(() => ghDeleteFile(prevPath.replace(/^\.\//, ""), `Delete avatar file for ${state.currentUser.username}`)).catch(() => {});
            }
          } else {
            delete state.avatars[myLower];
            localStorage.setItem(LS_LOCAL_AVATARS, JSON.stringify(state.avatars));
          }
          renderProfileBody();
          updateAuthUI();
          renderFeed();
        } catch (err) {
          alert("Ошибка: " + err.message);
          avDel.disabled = false;
        }
      };
    }

    const confirmBtn = document.getElementById("tg-confirm-btn");
    if (confirmBtn) {
      confirmBtn.onclick = async () => {
        if (!ensureTokenInteractive()) return;
        const msgEl = document.getElementById("tg-link-msg");
        confirmBtn.disabled = true;
        confirmBtn.textContent = "Отправляем запрос...";
        try {
          await ghUpdateJson(
            "data/tg_requests.json",
            list => [
              ...(Array.isArray(list) ? list : []),
              {
                id: `req-${Date.now()}`,
                action: "link",
                username: state.currentUser.username,
                code: state.pendingTgCode,
                createdAt: new Date().toISOString()
              }
            ],
            `TG link request for ${state.currentUser.username}`,
            []
          );
          msgEl.textContent = `Запрос отправлен! В течение ~15 сек @${botUser} напишет тебе в личку для подтверждения.`;
          msgEl.classList.remove("hidden");

          // Через 12 и 24 сек проверяем обновился ли tg_status.json
          [12000, 24000].forEach(delay => {
            setTimeout(async () => {
              const pModal = document.getElementById("modal-profile");
              if (!pModal || pModal.classList.contains("hidden")) return;
              try {
                const st = await ghGetFile("data/tg_status.json");
                state.tgStatus = st.data || {};
                if (state.tgStatus[myLower]) {
                  state.pendingTgCode = "";
                  renderProfileBody();
                }
              } catch {}
            }, delay);
          });
        } catch (err) {
          alert("Ошибка привязки: " + err.message);
          confirmBtn.disabled = false;
          confirmBtn.textContent = "2. Я нажал(а) START — привязать";
        }
      };
    }

    const unlinkBtn = document.getElementById("tg-unlink-btn");
    if (unlinkBtn) {
      unlinkBtn.onclick = async () => {
        if (!confirm("Отвязать Telegram и выключить личные уведомления?")) return;
        if (!ensureTokenInteractive()) return;
        unlinkBtn.disabled = true;
        unlinkBtn.textContent = "Отвязываем...";
        try {
          await ghUpdateJson(
            "data/tg_requests.json",
            list => [
              ...(Array.isArray(list) ? list : []),
              {
                id: `req-${Date.now()}`,
                action: "unlink",
                username: state.currentUser.username,
                createdAt: new Date().toISOString()
              }
            ],
            `TG unlink request for ${state.currentUser.username}`,
            []
          );
          delete state.tgStatus[myLower];
          state.pendingTgCode = "";
          renderProfileBody();
          const msgEl = document.getElementById("tg-link-msg");
          if (msgEl) {
            msgEl.textContent = "Telegram отвязан! Бот скоро попрощается с тобой в личке.";
            msgEl.classList.remove("hidden");
          }
        } catch (err) {
          alert("Ошибка отвязки: " + err.message);
          unlinkBtn.disabled = false;
          unlinkBtn.textContent = "Отвязать Telegram";
        }
      };
    }

    const togOn = document.getElementById("dev-toggle-online");
    const togLs = document.getElementById("dev-toggle-lastseen");
    const saveDevStealth = async () => {
      if (!isCreatorUser() || !IS_GITHUB_READY || !ensureTokenInteractive()) return;
      const showOnline = Boolean(togOn && togOn.checked);
      const showLastSeen = Boolean(togLs && togLs.checked);
      try {
        state.presence = await ghUpdateJson(
          "presence.json",
          (obj) => {
            const base = (obj && typeof obj === "object") ? obj : {};
            const users = { ...(base.users || {}) };
            if (!showOnline && !showLastSeen) {
              delete users["miralys"];
            } else {
              users["miralys"] = { lastSeen: Date.now() };
            }
            return { users, devPrefs: { showOnline, showLastSeen } };
          },
          "Update dev presence prefs",
          { users: {}, devPrefs: { showOnline: false, showLastSeen: false } },
          "presence"
        );
      } catch (err) {
        alert("Ошибка сохранения невидимки: " + err.message);
      }
    };
    if (togOn) togOn.onchange = saveDevStealth;
    if (togLs) togLs.onchange = saveDevStealth;

    const renameForm = document.getElementById("profile-rename-form");
    if (renameForm) {
      renameForm.onsubmit = async (e) => {
        e.preventDefault();
        await handleRenameNickname();
      };
    }

    document.getElementById("profile-logout-btn").onclick = () => {
      state.currentUser = null;
      state.pendingTgCode = "";
      localStorage.removeItem(LS_SESSION);
      updateAuthUI();
      closeModal("modal-profile");
    };
  }

  function openProfileModal() {
    if (!state.currentUser) return;
    ensureProfileModal();
    renderProfileBody();
    openModal("modal-profile");

    if (IS_GITHUB_READY) {
      Promise.all([
        ghGetFile("data/tg_status.json").then(r => { state.tgStatus = r.data || {}; }).catch(() => {}),
        loadPresence()
      ]).then(() => {
        const pModal = document.getElementById("modal-profile");
        if (pModal && !pModal.classList.contains("hidden")) {
          renderProfileBody();
        }
      });
    }
  }

  async function handleRenameNickname() {
    const errBox = document.getElementById("profile-error");
    const statusBox = document.getElementById("profile-status");
    const btn = document.getElementById("profile-rename-btn");
    errBox.classList.add("hidden");
    statusBox.classList.add("hidden");

    const showErr = (m) => { errBox.textContent = m; errBox.classList.remove("hidden"); };

    const oldName = state.currentUser.username;
    const oldLower = oldName.toLowerCase();
    const newName = document.getElementById("profile-new-name").value.trim();
    const newLower = newName.toLowerCase();

    if (!newName) return showErr("Введи новый ник!");
    if (newName === oldName) return showErr("Это и так твой текущий ник!");
    if (newLower === "miralys") return showErr("Аккаунт не зарегистрирован");
    if (state.users.some(u => u.username.toLowerCase() === newLower && u.username.toLowerCase() !== oldLower)) {
      return showErr("Такой ник уже занят кем-то другим!");
    }
    if (!ensureTokenInteractive()) return;

    btn.disabled = true;
    btn.textContent = "Переименовываем...";
    try {
      if (IS_GITHUB_READY) {
        state.users = await ghUpdateJson("data/users.json", list => {
          const conflict = list.some(u => u.username.toLowerCase() === newLower && u.username.toLowerCase() !== oldLower);
          if (conflict) throw new Error("Этот ник только что занял кто-то другой!");
          return list.map(u => {
            if (u.username.toLowerCase() !== oldLower) return u;
            return {
              ...u,
              username: newName,
              authKey: (u.authKey || u.username).toLowerCase()
            };
          });
        }, `Rename user ${oldName} -> ${newName}`);

        statusBox.textContent = "Обновляем посты и комменты...";
        statusBox.classList.remove("hidden");

        state.posts = await ghUpdateJson(
          "data/posts.json",
          list => renameUserInPosts(list, oldLower, newName),
          `Update author ${oldName} -> ${newName}`
        );

        if (state.tgStatus && state.tgStatus[oldLower]) {
          await ghUpdateJson(
            "data/tg_requests.json",
            list => [
              ...(Array.isArray(list) ? list : []),
              {
                id: `req-${Date.now()}`,
                action: "rename",
                username: oldName,
                newUsername: newName,
                createdAt: new Date().toISOString()
              }
            ],
            `Rename user ${oldName} -> ${newName}`,
            []
          );
          delete state.tgStatus[oldLower];
          state.tgStatus[newLower] = true;
        }

        if (state.avatars && state.avatars[oldLower]) {
          state.avatars = await ghUpdateJson("data/avatars.json", obj => {
            const next = { ...(obj || {}) };
            if (next[oldLower]) { next[newLower] = next[oldLower]; delete next[oldLower]; }
            return next;
          }, `Move avatar ${oldName} -> ${newName}`, {});
          if (state.sessionMedia["av_" + oldLower]) {
            state.sessionMedia["av_" + newLower] = state.sessionMedia["av_" + oldLower];
            delete state.sessionMedia["av_" + oldLower];
          }
        }

        const opt = JSON.parse(localStorage.getItem(LS_OPTIMISTIC_POSTS) || "[]");
        localStorage.setItem(LS_OPTIMISTIC_POSTS, JSON.stringify(renameUserInPosts(opt, oldLower, newName)));
      } else {
        state.users = state.users.map(u => u.username.toLowerCase() === oldLower
          ? { ...u, username: newName, authKey: (u.authKey || u.username).toLowerCase() }
          : u
        );
        state.posts = renameUserInPosts(state.posts, oldLower, newName);
        localStorage.setItem(LS_LOCAL_USERS, JSON.stringify(state.users));
        localStorage.setItem(LS_LOCAL_POSTS, JSON.stringify(state.posts));
      }

      state.currentUser.username = newName;
      localStorage.setItem(LS_SESSION, JSON.stringify(state.currentUser));
      updateAuthUI();
      renderFeed();
      closeModal("modal-profile");
    } catch (err) {
      showErr("Не вышло сменить ник: " + err.message);
      btn.disabled = false;
      btn.textContent = "Сменить никнейм";
    }
  }

  // ====== АВТОРИЗАЦИЯ И ШИЗА С MIRALYS ======
  function updateAuthUI() {
    const btn = document.getElementById("nav-auth-btn");
    const lbl = document.getElementById("nav-auth-label");
    const defSvg = btn.querySelector("svg");
    let navAv = document.getElementById("nav-auth-avatar");
    if (!navAv) {
      navAv = document.createElement("span");
      navAv.id = "nav-auth-avatar";
      btn.insertBefore(navAv, lbl);
    }

    if (state.currentUser) {
      lbl.textContent = state.currentUser.isCreator ? `Miralys [Создатель]` : state.currentUser.username;
      const { hasCustom } = getAvatarInfo(state.currentUser.username);
      if (hasCustom) {
        if (defSvg) defSvg.classList.add("hidden");
        navAv.innerHTML = renderAvatarHtml(state.currentUser.username, "av-nav");
        navAv.classList.remove("hidden");
      } else {
        if (defSvg) defSvg.classList.remove("hidden");
        navAv.classList.add("hidden");
      }
    } else {
      lbl.textContent = "Войти";
      if (defSvg) defSvg.classList.remove("hidden");
      navAv.classList.add("hidden");
    }
    const showDevBanner = isDevMode() && (!state.currentUser || isCreatorUser());
    document.getElementById("dev-banner").classList.toggle("hidden", !showDevBanner);
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

    if (lower === "miralys") {
      if (state.authMode === "register" || !isDevMode()) {
        return showErr("Аккаунт не зарегистрирован");
      }
      if (CFG.CREATOR_PASS_HASH) {
        const hash = sha256Hex("DEBIN_CREATOR:" + password);
        if (hash !== CFG.CREATOR_PASS_HASH) return showErr("Неверный ключ Создателя.");
      }
      state.currentUser = { username: "Miralys", isCreator: true };
      localStorage.setItem(LS_SESSION, JSON.stringify(state.currentUser));
      updateAuthUI();
      pingPresence(true);
      closeModal("modal-auth");
      return;
    }

    if (state.authMode === "login") {
      const found = state.users.find(u => u.username.toLowerCase() === lower);
      if (!found) return showErr("Аккаунт не зарегистрирован");
      const authKey = (found.authKey || found.username).toLowerCase();
      const expectedHash = sha256Hex("DEBIN_USER:" + authKey + ":" + password);
      if (found.passHash !== expectedHash) return showErr("Неверный пароль.");

      state.currentUser = { username: found.username, isCreator: false };
      localStorage.setItem(LS_SESSION, JSON.stringify(state.currentUser));
      updateAuthUI();
      pingPresence(true);
      closeModal("modal-auth");
      return;
    }

    if (state.users.some(u => u.username.toLowerCase() === lower)) {
      return showErr("Такой ник уже занят!");
    }

    if (IS_GITHUB_READY && CFG.ENCRYPTED_TOKEN && !getUnlockedToken()) {
      const tok = decryptToken(CFG.ENCRYPTED_TOKEN, passphrase);
      if (!tok) return showErr("Братик, там же написано: напиши 0!");
      saveUnlockedToken(tok);
    }

    const passHash = sha256Hex("DEBIN_USER:" + lower + ":" + password);
    const newUser = {
      username: usernameRaw,
      passHash,
      createdAt: new Date().toISOString()
    };

    const btn = document.getElementById("auth-submit-btn");
    btn.disabled = true;
    btn.textContent = "Регистрируем...";
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
      pingPresence(true);
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
      fileInput.multiple = true;
      document.getElementById("pub-file-label").textContent = "Выбрать фото (можно сразу несколько, сожмутся в WebP)";
    } else if (type === "video") {
      fileInput.accept = "video/*";
      fileInput.multiple = false;
      const maxLabel = HAS_CLOUDINARY ? 100 : 65;
      document.getElementById("pub-file-label").textContent = `Загрузить видеофайл (до ${maxLabel} МБ)`;
      clearSelectedPhotos();
    } else {
      fileInput.multiple = false;
      clearSelectedPhotos();
    }

    const textLabels = {
      thoughts: "Текст мысли",
      quotes: "Цитата или диалог (можно с Enter и тире —)",
      photos: "Подпись к фото (по желанию)",
      video: "Описание видео (по желанию)",
      books: "Текст книги (деление на страницы через строку ---)"
    };
    document.getElementById("pub-text-label").textContent = textLabels[type] || "Текст";
    const qaInp = document.getElementById("pub-quote-author");
    if (qaInp) qaInp.placeholder = "Кто сказал / где было? (можно пустым)";

    let devBox = document.getElementById("pub-dev-box");
    if (!devBox) {
      devBox = document.createElement("div");
      devBox.id = "pub-dev-box";
      devBox.className = "dev-panel-box hidden";
      devBox.innerHTML = `
        <div class="dev-panel-title">🛠 Опции Создателя</div>
        <label class="toggle-row" style="margin-bottom:0.6rem;">
          <span>🤫 Тихий пост (без уведомления в Telegram)</span>
          <input type="checkbox" id="pub-silent">
        </label>
        <label style="font-weight:500;">
          📅 Своя дата поста (пусто = сейчас)
          <input type="datetime-local" id="pub-custom-date">
        </label>
      `;
      const passGrp = document.getElementById("pub-passphrase-group");
      passGrp.parentNode.insertBefore(devBox, passGrp);
    }
    devBox.classList.toggle("hidden", !isCreatorUser());

    const needPass = IS_GITHUB_READY && Boolean(CFG.ENCRYPTED_TOKEN) && !getUnlockedToken();
    document.getElementById("pub-passphrase-group").classList.toggle("hidden", !needPass);
    renderSelectedPhotosPreview();
  }

  async function handlePublishSubmit(e) {
    e.preventDefault();
    const errBox = document.getElementById("pub-error");
    const statusBox = document.getElementById("pub-status");
    const btn = document.getElementById("pub-submit-btn");
    errBox.classList.add("hidden");
    statusBox.classList.add("hidden");
    hideProgress();

    const showErr = (m) => { errBox.textContent = m; errBox.classList.remove("hidden"); };

    if (!state.currentUser) {
      closeModal("modal-publish");
      openModal("modal-auth");
      return;
    }

    if (IS_GITHUB_READY && CFG.ENCRYPTED_TOKEN && !getUnlockedToken()) {
      const phrase = document.getElementById("pub-passphrase").value.trim();
      const tok = decryptToken(CFG.ENCRYPTED_TOKEN, phrase);
      if (!tok) return showErr("Братик, там же написано: напиши 0!");
      saveUnlockedToken(tok);
    }

    const type = document.getElementById("pub-type").value;
    const title = document.getElementById("pub-title").value.trim();
    const text = document.getElementById("pub-text").value.trim();
    const quoteAuthor = document.getElementById("pub-quote-author").value.trim();
    const bookAuthor = document.getElementById("pub-book-author").value.trim();
    const bookYear = document.getElementById("pub-book-year").value.trim();
    let videoUrl = document.getElementById("pub-video-url").value.trim();
    const singleFile = document.getElementById("pub-file").files[0];
    const tags = document.getElementById("pub-tags").value
      .split(",").map(s => s.trim()).filter(Boolean);

    if (!title) return showErr("Нужен заголовок!");
    if ((type === "thoughts" || type === "quotes" || type === "books") && !text) {
      return showErr("Напиши хоть пару слов!");
    }
    if (type === "photos" && !state.selectedPhotoFiles.length) {
      return showErr("Выбери хотя бы одну фотку!");
    }
    if (type === "video" && !singleFile && !videoUrl) {
      return showErr("Выбери видеофайл или вставь ссылку!");
    }

    const postId = `post-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    let mediaUrl = "";
    let mediaUrls = [];
    let thumbUrl = "";

    btn.disabled = true;
    try {
      if (type === "photos") {
        const files = state.selectedPhotoFiles;
        const processedList = [];
        let totalBytes = 0;

        for (let i = 0; i < files.length; i++) {
          setProgress(
            Math.round(((i + 0.5) / files.length) * 25),
            `Сжимаем фото ${i + 1} из ${files.length} в WebP...`
          );
          const processed = await processImageForUpload(files[i]);
          totalBytes += processed.blob.size;
          const suffix = files.length === 1 ? "" : `_${i}`;
          const filePath = `uploads/${postId}${suffix}.${processed.ext}`;
          processedList.push({
            path: filePath,
            blob: processed.blob,
            mime: processed.mime,
            blobUrl: URL.createObjectURL(processed.blob)
          });
        }

        if (totalBytes / (1024 * 1024) > 65) {
          throw new Error("Пачка фоток даже после сжатия больше 65 МБ — раздели на два поста!");
        }

        state.sessionMedia[postId] = processedList.map(p => p.blobUrl);

        if (IS_GITHUB_READY) {
          const filesToPush = [];
          for (let i = 0; i < processedList.length; i++) {
            filesToPush.push({
              path: processedList[i].path,
              base64: await blobToBase64(processedList[i].blob)
            });
          }

          if (filesToPush.length === 1 && processedList[0].blob.size <= 3 * 1024 * 1024) {
            await ghPutRaw(
              filesToPush[0].path,
              filesToPush[0].base64,
              `Upload photo ${postId}`,
              null,
              (pct) => setProgress(25 + Math.round(pct * 0.65), `Загрузка фото: ${pct}%`)
            );
          } else {
            await ghUploadViaGitBlobs(
              filesToPush,
              `Upload ${filesToPush.length} photo(s) ${postId}`,
              (pct, _l, _t, idx, cnt) => {
                setProgress(25 + Math.round(pct * 0.68), `Отправка фото (${idx}/${cnt}): ${pct}%`);
              }
            );
          }
          mediaUrls = processedList.map(p => `./${p.path}`);
          mediaUrl = mediaUrls[0];
        } else {
          mediaUrls = [];
          for (const p of processedList) {
            mediaUrls.push(
              p.blob.size < 1.5 * 1024 * 1024
                ? `data:${p.mime};base64,${await blobToBase64(p.blob)}`
                : p.blobUrl
            );
          }
          mediaUrl = mediaUrls[0];
        }
      } else if (type === "video" && singleFile) {
        const sizeMb = singleFile.size / (1024 * 1024);
        const maxMb = HAS_CLOUDINARY ? 100 : 65;
        if (sizeMb > maxMb) {
          throw new Error(`Файл ${sizeMb.toFixed(1)} МБ — лимит загрузки ${maxMb} МБ. Сожми видос или кинь ссылку с YouTube!`);
        }

        setProgress(5, "Выхватываем обложку видео...");
        const thumbData = await extractVideoThumbnail(singleFile);
        if (thumbData) {
          state.sessionMedia[postId + "_thumb"] = URL.createObjectURL(thumbData.blob);
        }

        if (IS_GITHUB_READY && HAS_CLOUDINARY) {
          const onProg = (pct, loaded, total) => {
            const mbL = (loaded / 1048576).toFixed(1);
            const mbT = (total / 1048576).toFixed(1);
            setProgress(10 + Math.round(pct * 0.85), `Загрузка видео: ${pct}% (${mbL} / ${mbT} МБ)`);
          };
          const cldRes = await uploadVideoToCloudinary(singleFile, onProg);
          videoUrl = cldRes.videoUrl;
          thumbUrl = cldRes.thumbUrl;
        } else if (IS_GITHUB_READY) {
          const ext = (singleFile.name.split(".").pop() || "mp4").toLowerCase().replace(/[^a-z0-9]/g, "");
          const filePath = `uploads/${postId}.${ext}`;
          state.sessionMedia[postId] = URL.createObjectURL(singleFile);

          setProgress(10, `Подготовка видео (${sizeMb.toFixed(1)} МБ)...`);
          const filesToPush = [{ path: filePath, base64: await blobToBase64(singleFile) }];
          let thumbPath = "";
          if (thumbData) {
            thumbPath = `uploads/${postId}_thumb.${thumbData.ext}`;
            filesToPush.push({ path: thumbPath, base64: await blobToBase64(thumbData.blob) });
          }

          const onProg = (pct, loaded, total) => {
            const mbL = (loaded / 1048576).toFixed(1);
            const mbT = (total / 1048576).toFixed(1);
            setProgress(10 + Math.round(pct * 0.82), `Отправка: ${pct}% (${mbL} / ${mbT} МБ)`);
          };

          if (singleFile.size > 3 * 1024 * 1024) {
            await ghUploadViaGitBlobs(filesToPush, `Upload video ${postId}`, onProg);
          } else {
            await ghPutRaw(filePath, filesToPush[0].base64, `Upload video ${postId}`, null, onProg);
            if (thumbPath) {
              await ghPutRaw(thumbPath, filesToPush[1].base64, `Upload video thumb ${postId}`);
            }
          }
          mediaUrl = `./${filePath}`;
          if (thumbPath) thumbUrl = `./${thumbPath}`;
        } else {
          mediaUrl = URL.createObjectURL(singleFile);
          state.sessionMedia[postId] = mediaUrl;
        }
      }

      setProgress(95, "Записываем пост в архив...");
      let postDateIso = new Date().toISOString();
      let isSilentPost = false;
      if (isCreatorUser()) {
        const cdEl = document.getElementById("pub-custom-date");
        const silEl = document.getElementById("pub-silent");
        if (cdEl && cdEl.value) {
          const parsedD = new Date(cdEl.value);
          if (!isNaN(parsedD.getTime())) postDateIso = parsedD.toISOString();
        }
        if (silEl && silEl.checked) isSilentPost = true;
      }

      const newPost = {
        id: postId,
        type,
        title,
        text,
        author: state.currentUser.username,
        createdAt: postDateIso,
        tags,
        likes: [],
        comments: []
      };
      if (type === "quotes" && quoteAuthor) newPost.quoteAuthor = quoteAuthor;
      if (type === "books") {
        newPost.bookAuthor = bookAuthor || state.currentUser.username;
        newPost.bookYear = bookYear || "1 стр.";
      }
      if (mediaUrl) newPost.mediaUrl = mediaUrl;
      if (mediaUrls.length > 1) newPost.mediaUrls = mediaUrls;
      if (thumbUrl) newPost.thumbUrl = thumbUrl;
      if (videoUrl) newPost.videoUrl = videoUrl;

      if (IS_GITHUB_READY) {
        const cMsg = isSilentPost ? `Update author silent post ${postId}` : `Add ${type}: ${title}`;
        state.posts = await ghUpdateJson("data/posts.json", list => [newPost, ...list], cMsg);
        saveOptimisticPost(newPost);
      } else {
        state.posts.unshift(newPost);
        localStorage.setItem(LS_LOCAL_POSTS, JSON.stringify(state.posts));
      }

      setProgress(100, "Готово!");
      document.getElementById("publish-form").reset();
      clearSelectedPhotos();
      syncPublishFormFields();
      updateCounts();
      renderFeed();
      setTimeout(() => {
        hideProgress();
        closeModal("modal-publish");
      }, 300);
    } catch (err) {
      hideProgress();
      showErr("Не вышло запушить: " + err.message);
      syncPublishFormFields();
    } finally {
      btn.disabled = false;
    }
  }

  // ====== УЧАСТНИКИ ======
  async function resetUserPassword(username) {
    if (!isCreatorUser()) return;
    const newPass = prompt(`Введи новый пароль для ${username}:`);
    if (!newPass) return;
    if (!ensureTokenInteractive()) return;
    const lower = username.toLowerCase();
    try {
      state.users = await ghUpdateJson(
        "data/users.json",
        list => list.map(u => {
          if (u.username.toLowerCase() !== lower) return u;
          const authKey = (u.authKey || u.username).toLowerCase();
          return { ...u, passHash: sha256Hex("DEBIN_USER:" + authKey + ":" + newPass) };
        }),
        `Update author reset password for ${username}`
      );
      alert(`✅ Пароль для ${username} изменён! Можешь скинуть ему новый пароль.`);
    } catch (err) {
      alert("Ошибка сброса: " + err.message);
    }
  }

  function renderUsersModalBody() {
    const listEl = document.getElementById("users-list");
    if (!listEl) return;
    const postCountBy = {};
    state.posts.forEach(p => {
      const k = (p.author || "").toLowerCase();
      postCountBy[k] = (postCountBy[k] || 0) + 1;
    });
    const isDev = isCreatorUser();

    let html = `
      <div class="user-row creator-row">
        <div class="user-row-left">
          ${renderAvatarHtml("Miralys", "av-md", true)}
          <div>
            <strong>Miralys</strong>
            <div class="muted-note" style="margin:0;">Постов: ${postCountBy["miralys"] || 0} • ${formatPresenceLine("Miralys", "старше вселенной")}</div>
          </div>
        </div>
        <span class="badge-creator">Создатель</span>
      </div>
    `;

    state.users.forEach(u => {
      const cnt = postCountBy[u.username.toLowerCase()] || 0;
      const presLine = formatPresenceLine(u.username, `С нами с ${formatDate(u.createdAt)}`);
      html += `
        <div class="user-row">
          <div class="user-row-left">
            ${renderAvatarHtml(u.username, "av-md", true)}
            <div>
              <strong>${esc(u.username)}</strong>
              <div class="muted-note" style="margin:0;">Постов: ${cnt} • ${presLine}</div>
            </div>
          </div>
          <div class="user-row-actions">
            ${isDev ? `<button type="button" class="btn-mini" data-reset-pass="${esc(u.username)}" title="Сбросить пароль">🔑</button>` : ""}
            <span class="badge-member">Участник</span>
          </div>
        </div>
      `;
    });

    listEl.innerHTML = html;
    listEl.querySelectorAll("[data-reset-pass]").forEach(btn => {
      btn.onclick = () => resetUserPassword(btn.dataset.resetPass);
    });

    const inviteBox = document.getElementById("invite-box");
    inviteBox.classList.toggle("hidden", !getUnlockedToken() || !IS_GITHUB_READY);
  }

  function openUsersModal() {
    renderUsersModalBody();
    openModal("modal-users");
    if (IS_GITHUB_READY) {
      loadPresence().then(() => {
        const um = document.getElementById("modal-users");
        if (um && !um.classList.contains("hidden")) renderUsersModalBody();
      });
    }
  }

  // ====== МОДАЛКИ И СОБЫТИЯ ======
  function openModal(id) { document.getElementById(id).classList.remove("hidden"); }

  function closeModal(id, fromHistory = false) {
    const modal = document.getElementById(id);
    if (!modal || modal.classList.contains("hidden")) return;

    modal.querySelectorAll("video, audio").forEach(m => {
      try { m.pause(); m.removeAttribute("src"); m.load(); } catch {}
    });
    modal.querySelectorAll("iframe").forEach(f => { f.src = "about:blank"; });

    if (id === "modal-view") {
      document.getElementById("view-modal-body").innerHTML = "";
      state.carouselMove = null;
      state.replyToComment = null;
      state.activeModalPostId = null;

      if (!fromHistory) {
        if (state.pushedPostHistory) {
          state.pushedPostHistory = false;
          history.back();
        } else if (getPostIdFromUrl()) {
          history.replaceState(null, "", window.location.pathname + window.location.search);
        }
      } else {
        state.pushedPostHistory = false;
      }
    }
    modal.classList.add("hidden");
  }

  function setTab(tab) {
    state.currentTab = tab;
    document.querySelectorAll("[data-tab]").forEach(btn => {
      btn.classList.toggle("active", btn.dataset.tab === tab);
    });
    renderFeed();
  }

  function handleInviteHash() {
    const rawHash = window.location.hash.replace(/^#/, "");
    if (!rawHash) return;
    const hp = new URLSearchParams(rawHash);
    const key = hp.get("key");
    if (key && CFG.ENCRYPTED_TOKEN) {
      const tok = decryptToken(CFG.ENCRYPTED_TOKEN, key);
      if (tok) saveUnlockedToken(tok);
      hp.delete("key");
      const rest = hp.toString();
      history.replaceState(null, "", window.location.pathname + window.location.search + (rest ? `#${rest}` : ""));
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
    updateAuthUI();
    updateCounts();
    renderFeed();

    if (IS_GITHUB_READY) {
      loadPresence().then(() => pingPresence(false));
      setInterval(() => pingPresence(false), 60000);
      document.addEventListener("visibilitychange", () => {
        if (document.visibilityState === "visible") pingPresence(false);
      });
    }

    const initialPostId = getPostIdFromUrl();
    const initialCommentId = getCommentIdFromUrl();
    if (initialPostId) {
      if (state.posts.some(p => p.id === initialPostId)) {
        openPostModal(initialPostId, true, initialCommentId);
      } else {
        history.replaceState(null, "", window.location.pathname + window.location.search);
      }
    }

    window.addEventListener("popstate", () => {
      const pid = getPostIdFromUrl();
      const cid = getCommentIdFromUrl();
      const viewModal = document.getElementById("modal-view");
      if (pid) {
        if (state.activeModalPostId !== pid) openPostModal(pid, true, cid);
      } else if (viewModal && !viewModal.classList.contains("hidden")) {
        closeModal("modal-view", true);
      }
    });

    document.querySelectorAll("[data-tab]").forEach(btn => {
      btn.addEventListener("click", () => {
        setTab(btn.dataset.tab);
        document.querySelector(".media-menu").classList.remove("open");
      });
    });

    document.getElementById("mobile-menu-btn").addEventListener("click", () => {
      document.querySelector(".media-menu").classList.toggle("open");
    });

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

    document.getElementById("feed-grid").addEventListener("click", (e) => {
      const likeBtn = e.target.closest("[data-like-post]");
      if (likeBtn) {
        e.stopPropagation();
        togglePostLike(likeBtn.dataset.likePost);
        return;
      }
      const card = e.target.closest(".tile");
      if (card) openPostModal(card.dataset.postId);
    });

    document.getElementById("nav-auth-btn").addEventListener("click", () => {
      if (state.currentUser) {
        openProfileModal();
      } else {
        syncAuthModalFields();
        openModal("modal-auth");
      }
    });

    document.querySelectorAll("[data-auth-mode]").forEach(btn => {
      btn.addEventListener("click", () => {
        state.authMode = btn.dataset.authMode;
        document.querySelectorAll("[data-auth-mode]").forEach(b => b.classList.toggle("active", b === btn));
        syncAuthModalFields();
      });
    });

    document.getElementById("auth-form").addEventListener("submit", handleAuthSubmit);

    const openPublish = () => {
      if (!state.currentUser) {
        syncAuthModalFields();
        openModal("modal-auth");
        return;
      }
      hideProgress();
      syncPublishFormFields();
      openModal("modal-publish");
    };
    document.getElementById("nav-publish-btn").addEventListener("click", openPublish);
    document.getElementById("hero-publish-cta").addEventListener("click", openPublish);
    document.getElementById("pub-type").addEventListener("change", syncPublishFormFields);

    document.getElementById("pub-file").addEventListener("change", (e) => {
      if (document.getElementById("pub-type").value !== "photos") return;
      const picked = [...(e.target.files || [])];
      if (!picked.length) return;

      const existingKeys = new Set(state.selectedPhotoFiles.map(f => `${f.name}_${f.size}_${f.lastModified}`));
      for (const f of picked) {
        if (state.selectedPhotoFiles.length >= 20) {
          alert("Максимум 20 фото за один пост, братик!");
          break;
        }
        const key = `${f.name}_${f.size}_${f.lastModified}`;
        if (!existingKeys.has(key)) {
          f._previewUrl = URL.createObjectURL(f);
          state.selectedPhotoFiles.push(f);
          existingKeys.add(key);
        }
      }
      e.target.value = "";
      renderSelectedPhotosPreview();
    });

    document.getElementById("publish-form").addEventListener("submit", handlePublishSubmit);

    document.getElementById("nav-users-btn").addEventListener("click", openUsersModal);
    document.getElementById("subnav-users-link").addEventListener("click", openUsersModal);

    document.getElementById("copy-invite-btn").addEventListener("click", () => {
      const phrase = prompt("Введи 0 (или своё слово), чтобы зашить его в одноразовую инвайт-ссылку:");
      if (!phrase) return;
      const link = `${window.location.origin}${window.location.pathname}#key=${encodeURIComponent(phrase)}`;
      navigator.clipboard?.writeText(link);
      alert("Ссылка скопирована! Кидай её в беседу:\n" + link);
    });

    document.querySelectorAll("[data-close]").forEach(btn => {
      btn.addEventListener("click", () => closeModal(btn.dataset.close));
    });
    document.querySelectorAll(".modal-backdrop").forEach(bg => {
      bg.addEventListener("click", (e) => {
        if (e.target === bg) closeModal(bg.id);
      });
    });
    document.addEventListener("click", (e) => {
      const av = e.target.closest("[data-zoom-avatar]");
      if (av) {
        e.stopPropagation();
        openAvatarLightbox(av.dataset.zoomAvatar);
      }
    });

    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape") {
        document.querySelectorAll(".modal-backdrop:not(.hidden)").forEach(m => closeModal(m.id));
      } else if (state.carouselMove && !document.getElementById("modal-view").classList.contains("hidden")) {
        if (!["TEXTAREA", "INPUT"].includes(document.activeElement?.tagName)) {
          if (e.key === "ArrowLeft") state.carouselMove(-1);
          if (e.key === "ArrowRight") state.carouselMove(1);
        }
      }
    });
  }

  document.addEventListener("DOMContentLoaded", init);
})();
