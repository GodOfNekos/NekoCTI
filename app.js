// NekoCTI dashboard - vanilla JS, no framework or build step.

const state = {
  tab: "high_ticket",
  range: "24h",
  selectedId: null,
  managingWatchlist: false,
  searchQuery: "",
};

const TAB_LABELS = {
  high_ticket: "HIGH TICKET",
  watchlist: "WATCHLIST MATCHES",
  breaches: "MAJOR SECURITY BREACHES",
  entities: "APT / TRACKED ENTITY MATCHES",
  campaigns: "TRACKED CAMPAIGN MATCHES",
  archive: "FULL ARCHIVE",
};

async function fetchJSON(url, opts) {
  const res = await fetch(url, opts);
  if (!res.ok) throw new Error(`${url} -> HTTP ${res.status}`);
  return res.json();
}

function errorHTML(err) {
  return `<div class="empty-state error-state">SIGNAL LOST - COULD NOT REACH NEKOCTI BACKEND.<br>${escapeHtml(String(err.message || err))}</div>`;
}

function formatMeta(article) {
  const bits = [];
  if (article.cves.length === 1) {
    const c = article.cves[0];
    bits.push(c.cvss ? `<span class="${c.cvss >= 9 ? 'cve-crit' : ''}">${c.id} (${c.cvss})</span>` : c.id);
  } else if (article.cves.length > 1) {
    const scores = article.cves.map((c) => c.cvss).filter((s) => s !== null);
    let note = `${article.cves.length} CVEs`;
    if (scores.length) note += `, highest ${Math.max(...scores)}`;
    bits.push(note);
  }
  if (article.vendors.length) {
    const shown = article.vendors.slice(0, 3).join(", ");
    const extra = article.vendors.length > 3 ? ` +${article.vendors.length - 3} more` : "";
    bits.push(shown + extra);
  }
  if (article.entities.length) {
    bits.push(article.entities.join(", "));
  }
  if (article.campaigns && article.campaigns.length) {
    bits.push(article.campaigns.join(", "));
  }
  bits.push(article.published_at || "");
  return bits.filter(Boolean).map((b) => `<span>${b}</span>`).join("");
}

function renderList(articles) {
  const list = document.getElementById("list");
  list.hidden = false;
  document.getElementById("manage-panel").hidden = true;
  document.getElementById("attack-view").hidden = true;
  document.getElementById("pocs-view").hidden = true;
  closeReader();

  if (!articles.length) {
    list.innerHTML = `<div class="empty-state">NOTHING CAPTURED YET IN THIS RANGE.</div>`;
    return;
  }

  const label = TAB_LABELS[state.tab] || "";
  const rows = articles.map((a) => `
    <div class="row ${a.id === state.selectedId ? "selected" : ""}" data-id="${a.id}" data-link="${a.link}">
      <span class="title">${a.title}</span>
      <span class="meta">${formatMeta(a)}</span>
    </div>
  `).join("");

  list.innerHTML = `<div class="section-label">// ${label}</div>${rows}`;

  list.querySelectorAll(".row").forEach((el) => {
    el.addEventListener("click", () => {
      state.selectedId = Number(el.dataset.id);
      openReader(state.selectedId);
    });
  });
}

async function loadArticles() {
  try {
    const data = await fetchJSON(`/api/articles?tab=${state.tab}&range=${state.range}`);
    renderList(data.articles);
    updateCounts(data.counts);
  } catch (err) {
    document.getElementById("list").hidden = false;
    document.getElementById("list").innerHTML = errorHTML(err);
  }
}

// --- Search ---
// Real full-text search across the whole archive (SQLite FTS5 on the
// backend), independent of whichever tab happens to be active - Neko's
// explicit request for "search for specific things when I need to".
// Ranked by relevance, not date, unlike every other view in this app.

async function renderSearchResults(query) {
  document.getElementById("manage-panel").hidden = true;
  document.getElementById("attack-view").hidden = true;
  document.getElementById("pocs-view").hidden = true;
  closeReader();
  const list = document.getElementById("list");
  list.hidden = false;
  list.innerHTML = `<div class="section-label">// SEARCHING...</div>`;

  let data;
  try {
    data = await fetchJSON(`/api/search?q=${encodeURIComponent(query)}`);
  } catch (err) {
    list.innerHTML = errorHTML(err);
    return;
  }

  if (!data.articles.length) {
    list.innerHTML = `<div class="section-label">// SEARCH RESULTS FOR "${escapeHtml(query)}"</div>
      <div class="empty-state">NO MATCHES.</div>`;
    return;
  }

  const rows = data.articles.map((a) => `
    <div class="row" data-id="${a.id}">
      <span class="title">${a.title}</span>
      <span class="meta">${formatMeta(a)}</span>
    </div>
  `).join("");

  list.innerHTML = `<div class="section-label">// SEARCH RESULTS FOR "${escapeHtml(query)}" (${data.articles.length})</div>${rows}`;
  list.querySelectorAll(".row").forEach((el) => {
    el.addEventListener("click", () => openReader(Number(el.dataset.id)));
  });
}

function updateCounts(counts) {
  for (const key of ["high_ticket", "watchlist", "breaches", "entities", "campaigns", "archive"]) {
    const el = document.getElementById(`count-${key}`);
    if (el && counts[key] !== undefined) el.textContent = counts[key];
  }
  document.getElementById("footer-archive").textContent = `ARCHIVE ${counts.archive ?? "-"}`;
  document.getElementById("footer-highticket").textContent = `HIGH TICKET ${counts.high_ticket ?? "-"}`;
  const total = counts.archive || 1;
  const pct = Math.min(100, Math.round(((counts.high_ticket || 0) / total) * 100 * 4));
  document.getElementById("footer-gauge").style.width = `${pct}%`;
}

// --- In-dashboard reader ---
// Reads the real captured content (full article text for THN, the real
// description for KEV) here instead of forwarding to the original site -
// Neko's explicit request: this is meant to be the central place for
// consumption, not a launchpad out to other pages.

async function openReader(id) {
  const overlay = document.getElementById("reader-overlay");
  overlay.hidden = false;
  overlay.innerHTML = `<div class="reader-body">LOADING...</div>`;

  let article;
  try {
    article = await fetchJSON(`/api/article/${id}`);
  } catch (err) {
    overlay.innerHTML = `<div class="reader-body">${errorHTML(err)}</div>`;
    return;
  }

  const metaParts = [];
  if (article.published_at) metaParts.push(article.published_at);
  if (article.cves.length) {
    metaParts.push(article.cves.map((c) => c.cvss ? `${c.id} (${c.cvss})` : c.id).join(", "));
  }
  if (article.vendors.length) metaParts.push(`VENDORS: ${article.vendors.join(", ")}`);
  if (article.entities.length) metaParts.push(`TRACKED: ${article.entities.join(", ")}`);
  if (article.campaigns && article.campaigns.length) metaParts.push(`CAMPAIGN: ${article.campaigns.join(", ")}`);
  if (article.is_breach) metaParts.push("FLAGGED: MAJOR BREACH");
  if (article.mentions_poc) metaParts.push("PoC/EXPLOIT DISCUSSED");

  // Real inline images the source article carried, shown alongside the
  // text instead of the reader's right side sitting empty on wide
  // screens - Neko's explicit request. Shown as captured, not every
  // extracted image is guaranteed to be a technical diagram (some are
  // decorative), so this is a real-content panel, not a curated one.
  // Recolored toward the phosphor palette via a CSS filter rather than
  // regenerated - a diagram's actual content must never be reinterpreted,
  // only its color treatment. Hovering (or the explicit link) shows the
  // real, unfiltered original.
  const images = article.images || [];
  // .reader-images-grid wraps just the cards, separate from the section
  // label above it -- at the mobile/tablet breakpoint the grid switches
  // to a wrapping flex row so cards can share or fill it, but the label
  // must stay its own full-width heading above that row, not a flex
  // sibling competing for the same row space (a real bug found and fixed
  // live: without this wrapper, the label's own text width was eating
  // into the row, leaving a single real image looking like it still had
  // a dead gap beside it).
  const imagesHtml = images.length ? `
    <div class="reader-images">
      <div class="section-label">// CAPTURED IMAGES (${images.length})</div>
      <div class="reader-images-grid">
        ${images.map((src, i) => `
          <div class="reader-image-card">
            <div class="reader-image-index">IMAGE ${i + 1} OF ${images.length}</div>
            <img class="reader-image" src="${src}" loading="lazy" alt="" data-src="${src}">
            <a class="reader-image-original" href="${src}" target="_blank" rel="noopener">VIEW ORIGINAL &rarr;</a>
          </div>
        `).join("")}
      </div>
    </div>
  ` : "";

  overlay.innerHTML = `
    <div class="reader-header">
      <div class="reader-title">${article.title}</div>
      <div class="reader-close" id="reader-close-btn">CLOSE [x]</div>
    </div>
    <div class="reader-meta">${metaParts.map((m) => `<span>${m}</span>`).join("")}</div>
    <div class="reader-main">
      <div class="reader-body">${renderArticleBody(article.body)}</div>
      ${imagesHtml}
    </div>
    <a class="reader-source-link" href="${article.link}" target="_blank" rel="noopener">VIEW ORIGINAL SOURCE &rarr;</a>
  `;

  document.getElementById("reader-close-btn").addEventListener("click", closeReader);
  overlay.querySelectorAll(".reader-image").forEach((img) => {
    img.addEventListener("click", () => openImageLightbox(img.dataset.src));
  });
}

// --- Image lightbox ---
// Full-size, real-color zoom view for actually reading fine detail on a
// real diagram - Neko's explicit request. Always shows true colors, never
// the reader panel's themed filter, since the point of zooming in is
// inspecting the real content accurately.

function openImageLightbox(src) {
  const box = document.getElementById("image-lightbox");
  box.hidden = false;
  box.innerHTML = `
    <div class="reader-close" id="lightbox-close-btn">CLOSE [x]</div>
    <img src="${src}" alt="">
  `;
  box.addEventListener("click", closeImageLightbox);
  document.getElementById("lightbox-close-btn").addEventListener("click", (e) => {
    e.stopPropagation();
    closeImageLightbox();
  });
}

function closeImageLightbox() {
  const box = document.getElementById("image-lightbox");
  box.hidden = true;
  box.innerHTML = "";
}

function closeReader() {
  const overlay = document.getElementById("reader-overlay");
  overlay.hidden = true;
  overlay.innerHTML = "";
}

function escapeHtml(text) {
  const div = document.createElement("div");
  div.textContent = text;
  return div.innerHTML;
}

// Real markdown pipe-tables show up in ingested full-text (e.g. ZDI's
// monthly patch-review roundups) but were being dumped as raw escaped
// text -- a wall of "| Yes | No | Yes |" with no visible column headers,
// genuinely illegible. This splits the body into plain-text runs and
// real pipe-table blocks, rendering the latter as actual <table>
// markup instead of flowing text.
function splitTableRow(line) {
  return line.trim().replace(/^\|/, "").replace(/\|$/, "").split("|").map((c) => c.trim());
}

function isSeparatorCells(cells) {
  return cells.length > 0 && cells.every((c) => c === "" || /^:?-+:?$/.test(c));
}

function renderMarkdownTable(lines) {
  const rows = lines.map(splitTableRow);
  const sepIdxs = rows.reduce((acc, cells, i) => (isSeparatorCells(cells) ? [...acc, i] : acc), []);
  if (!sepIdxs.length) return escapeHtml(lines.join("\n"));

  // Some real source tables (ZDI's Apple review among them) carry a
  // caption row -- essentially prose explaining what the columns mean,
  // like "Yes/No indicates whether each update is affected" -- ahead of
  // their real header, with its own separator row in between. When more
  // than one separator exists, only the row right before the LAST one is
  // the real header; everything earlier is caption text, not data.
  const lastSep = sepIdxs[sepIdxs.length - 1];
  const headerIdx = lastSep - 1;
  const captionText = rows.slice(0, headerIdx)
    .filter((cells) => !isSeparatorCells(cells))
    .map((cells) => cells.filter(Boolean).join(" "))
    .filter(Boolean)
    .join(" ");
  const headerCells = rows[headerIdx] || [];
  const bodyRows = rows.slice(lastSep + 1).filter((cells) => cells.some((c) => c !== ""));

  const yesNoClass = (val) => {
    const v = val.trim().toLowerCase();
    if (v === "yes") return " class=\"cell-yes\"";
    if (v === "no") return " class=\"cell-no\"";
    return "";
  };

  const headHtml = `<tr>${headerCells.map((c) => `<th>${escapeHtml(c)}</th>`).join("")}</tr>`;
  const bodyHtml = bodyRows.map((cells) =>
    `<tr>${cells.map((c) => `<td${yesNoClass(c)}>${escapeHtml(c)}</td>`).join("")}</tr>`
  ).join("");

  return `${captionText ? `<div class="reader-table-caption">${escapeHtml(captionText)}</div>` : ""}
    <div class="reader-table-wrap"><table class="reader-table"><thead>${headHtml}</thead><tbody>${bodyHtml}</tbody></table></div>`;
}

function renderArticleBody(text) {
  const lines = text.split("\n");
  const isTableRow = (line) => /^\s*\|.*\|\s*$/.test(line);
  const blocks = [];
  let textBuf = [];
  const flushText = () => {
    if (textBuf.length) blocks.push({ type: "text", lines: textBuf });
    textBuf = [];
  };
  let i = 0;
  while (i < lines.length) {
    if (isTableRow(lines[i])) {
      const start = i;
      while (i < lines.length && isTableRow(lines[i])) i++;
      flushText();
      blocks.push({ type: "table", lines: lines.slice(start, i) });
    } else {
      textBuf.push(lines[i]);
      i++;
    }
  }
  flushText();
  return blocks.map((b) => b.type === "table" ? renderMarkdownTable(b.lines) : escapeHtml(b.lines.join("\n"))).join("");
}

// --- MITRE ATT&CK matrix ---
// Real tactics x techniques from MITRE's own data (attack.py), with a real
// count of matched articles per technique - a technique with zero matches
// still renders, dimmed, so the whole framework stays visible, not just a
// filtered list of what happened to match.

let attackMatrixCache = null;

async function renderAttackMatrix() {
  document.getElementById("list").hidden = true;
  document.getElementById("manage-panel").hidden = true;
  closeReader();
  const view = document.getElementById("attack-view");
  view.hidden = false;

  if (!attackMatrixCache) {
    view.innerHTML = `<div class="attack-search"><input disabled placeholder="LOADING REAL ATT&CK DATA..."></div>`;
    try {
      attackMatrixCache = await fetchJSON("/api/attack/matrix");
    } catch (err) {
      view.innerHTML = errorHTML(err);
      return;
    }
  }

  const { tactics, techniques } = attackMatrixCache;

  const columns = tactics.map((tactic) => {
    const inTactic = Object.entries(techniques)
      .filter(([, info]) => info.tactics.includes(tactic.shortname))
      .sort((a, b) => b[1].count - a[1].count);

    const rows = inTactic.map(([id, info]) => `
      <div class="attack-tech ${info.count > 0 ? "has-matches" : ""}" data-id="${id}" data-name="${info.name.toLowerCase()}">
        ${id}: ${info.name}${info.count > 0 ? `<span class="tech-count">${info.count}</span>` : ""}
      </div>
    `).join("");

    return `
      <div class="attack-col" data-tactic="${tactic.shortname}">
        <div class="attack-col-header">${tactic.name.toUpperCase()}</div>
        ${rows}
      </div>
    `;
  }).join("");

  view.innerHTML = `
    <div class="attack-search"><input id="attack-search-input" placeholder="SEARCH TECHNIQUES (NAME OR ID)..."></div>
    <div class="attack-grid">${columns}</div>
  `;

  document.getElementById("attack-search-input").addEventListener("input", (e) => {
    const q = e.target.value.trim().toLowerCase();
    view.querySelectorAll(".attack-tech").forEach((el) => {
      const matches = !q || el.dataset.id.toLowerCase().includes(q) || el.dataset.name.includes(q);
      el.classList.toggle("dimmed-search", !matches);
    });
  });

  view.querySelectorAll(".attack-tech.has-matches").forEach((el) => {
    el.addEventListener("click", () => openAttackTechnique(el.dataset.id));
  });
}

async function openAttackTechnique(techniqueId) {
  const view = document.getElementById("attack-view");
  let data;
  try {
    data = await fetchJSON(`/api/attack/technique/${techniqueId}`);
  } catch (err) {
    view.innerHTML = errorHTML(err);
    return;
  }

  const rows = data.articles.map((a) => `
    <div class="row" data-id="${a.id}">
      <span class="title">${a.title}</span>
      <span class="meta">${formatMeta(a)}</span>
    </div>
  `).join("");

  view.innerHTML = `
    <div class="reader-header">
      <div class="reader-title">${data.technique_id}: ${data.technique_name}</div>
      <div class="reader-close" id="attack-back-btn">BACK TO MATRIX [x]</div>
    </div>
    <div class="list" style="flex:1;display:flex;flex-direction:column;gap:3px;overflow-y:auto;">
      ${rows || '<div class="empty-state">NO MATCHED ARTICLES.</div>'}
    </div>
  `;

  document.getElementById("attack-back-btn").addEventListener("click", renderAttackMatrix);
  view.querySelectorAll(".row").forEach((el) => {
    el.addEventListener("click", () => openReader(Number(el.dataset.id)));
  });
}

// --- Real public PoC availability (nomi-sec/PoC-in-GitHub enrichment) ---
// A real CVE-keyed lookup, not an article feed - shows how many real
// public PoC repos exist for CVEs NekoCTI has already captured, cross-
// referenced against its own coverage (article count, a real CVSS score
// if one was ever recorded). Not cached, unlike the ATT&CK matrix -
// PoC data changes with every "run check now" and should read fresh.

async function renderPocsOverview() {
  document.getElementById("list").hidden = true;
  document.getElementById("manage-panel").hidden = true;
  document.getElementById("attack-view").hidden = true;
  closeReader();
  const view = document.getElementById("pocs-view");
  view.hidden = false;
  view.innerHTML = `<div class="attack-search"><input disabled placeholder="LOADING REAL POC DATA..."></div>`;

  let data;
  try {
    data = await fetchJSON("/api/pocs");
  } catch (err) {
    view.innerHTML = errorHTML(err);
    return;
  }

  const cves = data.cves || [];
  const countEl = document.getElementById("count-pocs");
  if (countEl) countEl.textContent = cves.length;
  const rows = cves.map((c) => `
    <div class="row poc-row" data-cve="${c.cve_id}" data-search="${c.cve_id.toLowerCase()} ${(c.title || "").toLowerCase()} ${c.vendors.join(" ").toLowerCase()} ${c.attack_techniques.map((t) => t.technique_id).join(" ").toLowerCase()}">
      <span class="title">
        ${c.cve_id}${c.cvss ? ` <span class="${c.cvss >= 9 ? 'cve-crit' : ''}">(CVSS ${c.cvss})</span>` : ""}
        ${c.title ? `<div class="poc-cve-desc">${escapeHtml(c.title)}</div>` : ""}
        ${c.vendors.length ? `<div class="poc-cve-vendors">${c.vendors.map(escapeHtml).join(", ")}</div>` : ""}
        ${c.attack_techniques.length ? `<div class="poc-attack-tags">${c.attack_techniques.map((t) =>
          `<span class="attack-tag ${t.confidence === "expert" ? "attack-tag-expert" : "attack-tag-llm"}" title="${escapeHtml(t.technique_name)}">${t.technique_id}</span>`
        ).join("")}</div>` : ""}
      </span>
      <span class="meta">
        <span>${c.latest_activity_at ? c.latest_activity_at.slice(0, 10) : ""}</span>
        ${c.has_public_repo
          ? `<span>${c.poc_count} PUBLIC REPO${c.poc_count === 1 ? "" : "S"}</span><span>${c.max_stars}&#9733; TOP</span>`
          : `<span class="poc-mention-only">MENTIONED, NO PUBLIC REPO</span>`}
        ${c.mention_count ? `<span>${c.mention_count} DISCUSSED IN</span>` : ""}
        ${c.article_count ? `<span>${c.article_count} ARTICLE${c.article_count === 1 ? "" : "S"}</span>` : ""}
      </span>
    </div>
  `).join("");

  view.innerHTML = `
    <div class="attack-search"><input id="pocs-search-input" placeholder="SEARCH CVE ID..."></div>
    <div class="list" style="flex:1;display:flex;flex-direction:column;gap:3px;overflow-y:auto;padding:0 30px 20px;">
      ${rows || '<div class="empty-state">NO REAL POC EVIDENCE FOUND YET.</div>'}
    </div>
  `;

  document.getElementById("pocs-search-input").addEventListener("input", (e) => {
    const q = e.target.value.trim().toLowerCase();
    view.querySelectorAll(".poc-row").forEach((el) => {
      el.style.display = (!q || el.dataset.search.includes(q)) ? "" : "none";
    });
  });

  view.querySelectorAll(".poc-row").forEach((el) => {
    el.addEventListener("click", () => openPocDetail(el.dataset.cve));
  });
}

async function openPocDetail(cveId) {
  const view = document.getElementById("pocs-view");
  let data;
  try {
    data = await fetchJSON(`/api/poc/${encodeURIComponent(cveId)}`);
  } catch (err) {
    view.innerHTML = errorHTML(err);
    return;
  }

  const pocRows = data.pocs.map((p) => `
    <div class="row poc-repo-row">
      <span class="title">
        <a href="${p.repo_url}" target="_blank" rel="noopener">${p.repo_full_name}</a>
        ${p.description ? `<div class="poc-repo-desc">${escapeHtml(p.description)}</div>` : ""}
      </span>
      <span class="meta">
        <span>${p.stars}&#9733;</span>
        <span>${p.repo_pushed_at ? p.repo_pushed_at.slice(0, 10) : ""}</span>
      </span>
    </div>
  `).join("");

  const articleRows = data.articles.map((a) => `
    <div class="row" data-id="${a.id}">
      <span class="title">${a.mentions_poc ? '<span class="poc-mention-flag">[POC DISCUSSED]</span> ' : ""}${a.title}</span>
      <span class="meta">${formatMeta(a)}</span>
    </div>
  `).join("");

  const mappingTypeLabel = { exploitation_technique: "EXPLOITATION TECHNIQUE", primary_impact: "PRIMARY IMPACT",
    secondary_impact: "SECONDARY IMPACT" };
  const attackRows = data.attack_techniques.map((t) => `
    <div class="row poc-attack-row">
      <span class="title">
        ${t.technique_id}: ${escapeHtml(t.technique_name)}
        ${t.evidence ? `<div class="poc-repo-desc">${escapeHtml(t.evidence)}</div>` : ""}
        ${t.source_url ? `<a class="poc-attack-source" href="${t.source_url}" target="_blank" rel="noopener">SOURCE &rarr;</a>` : ""}
      </span>
      <span class="meta">
        ${t.confidence === "expert"
          ? `<span class="attack-tag attack-tag-expert">MITRE-MAPPED</span><span>${mappingTypeLabel[t.mapping_type] || t.mapping_type || ""}</span>`
          : `<span class="attack-tag attack-tag-llm">BEST GUESS (LLM)</span>`}
      </span>
    </div>
  `).join("");

  view.innerHTML = `
    <div class="reader-header">
      <div class="reader-title">${data.cve_id}</div>
      <div class="reader-close" id="pocs-back-btn">BACK TO POCS [x]</div>
    </div>
    <div class="list" style="flex:1;display:flex;flex-direction:column;overflow-y:auto;padding:0 30px 20px;">
      <div class="section-label">// PUBLIC POC REPOS (${data.pocs.length})</div>
      ${pocRows || '<div class="empty-state">NONE FOUND - MAY STILL BE DISCUSSED IN COVERAGE BELOW WITHOUT A PUBLIC REPO.</div>'}
      <div class="section-label">// MITRE ATT&CK (${data.attack_techniques.length})</div>
      ${attackRows || '<div class="empty-state">NOT MAPPED YET - RUN classify-pocs TO TAG THIS CVE.</div>'}
      <div class="section-label">// NEKOCTI COVERAGE (${data.articles.length})</div>
      ${articleRows || '<div class="empty-state">NO CAPTURED ARTICLES MENTION THIS CVE.</div>'}
    </div>
  `;

  document.getElementById("pocs-back-btn").addEventListener("click", renderPocsOverview);
  view.querySelectorAll(".row[data-id]").forEach((el) => {
    el.addEventListener("click", () => openReader(Number(el.dataset.id)));
  });
}

// --- Watchlist / entities management panel ---

async function renderWatchlistPanel() {
  const list = document.getElementById("list");
  const panel = document.getElementById("manage-panel");
  list.hidden = true;
  panel.hidden = false;
  document.getElementById("attack-view").hidden = true;
  document.getElementById("pocs-view").hidden = true;

  let data;
  try {
    data = await fetchJSON("/api/watchlist");
  } catch (err) {
    panel.innerHTML = errorHTML(err);
    return;
  }
  const vendors = data.vendors || {};

  panel.innerHTML = Object.entries(vendors).map(([category, terms]) => `
    <div class="category" data-category="${category}">
      <div class="category-label">// ${category.toUpperCase().replace(/_/g, " ")}</div>
      <div class="term-list">
        ${terms.map((t) => `<span class="term" data-term="${t}">${t}<span class="remove">x</span></span>`).join("")}
      </div>
    </div>
  `).join("") + `
    <div class="add-row">
      <input id="new-category" placeholder="category (e.g. cloud_identity)">
      <input id="new-term" placeholder="vendor/product term">
      <button id="add-term-btn">ADD</button>
    </div>
  `;

  panel.querySelectorAll(".remove").forEach((el) => {
    el.addEventListener("click", async (e) => {
      e.stopPropagation();
      const termEl = el.closest(".term");
      const category = termEl.closest(".category").dataset.category;
      const term = termEl.dataset.term;
      vendors[category] = vendors[category].filter((t) => t !== term);
      await fetchJSON("/api/watchlist", { method: "PUT", body: JSON.stringify({ vendors }) });
      renderWatchlistPanel();
    });
  });

  document.getElementById("add-term-btn").addEventListener("click", async () => {
    const category = document.getElementById("new-category").value.trim();
    const term = document.getElementById("new-term").value.trim();
    if (!category || !term) return;
    vendors[category] = vendors[category] || [];
    vendors[category].push(term);
    await fetchJSON("/api/watchlist", { method: "PUT", body: JSON.stringify({ vendors }) });
    renderWatchlistPanel();
  });
}

async function renderEntitiesPanel() {
  const list = document.getElementById("list");
  const panel = document.getElementById("manage-panel");
  list.hidden = true;
  panel.hidden = false;
  document.getElementById("attack-view").hidden = true;
  document.getElementById("pocs-view").hidden = true;

  let data;
  try {
    data = await fetchJSON("/api/tags");
  } catch (err) {
    panel.innerHTML = errorHTML(err);
    return;
  }
  const entities = data.entities || [];

  panel.innerHTML = `<div class="category-label">// TRACKED ENTITIES</div>` +
    (entities.length
      ? entities.map((e, i) => `
        <div class="entity-card" data-index="${i}">
          <div class="entity-name">${e.name} <span class="remove" style="float:right;cursor:pointer;">x</span></div>
          <div class="entity-aliases">${(e.aliases || []).join(", ") || "no aliases"}</div>
        </div>
      `).join("")
      : `<div class="empty-state">NO ENTITIES TRACKED YET.</div>`) +
    `<div class="add-row">
      <input id="new-entity-name" placeholder="name (e.g. threat actor / campaign)">
      <input id="new-entity-aliases" placeholder="aliases, comma-separated">
      <button id="add-entity-btn">ADD</button>
    </div>`;

  panel.querySelectorAll(".entity-card .remove").forEach((el) => {
    el.addEventListener("click", async (e) => {
      e.stopPropagation();
      const idx = Number(el.closest(".entity-card").dataset.index);
      entities.splice(idx, 1);
      await fetchJSON("/api/tags", { method: "PUT", body: JSON.stringify({ entities }) });
      renderEntitiesPanel();
    });
  });

  panel.querySelectorAll(".entity-card").forEach((el) => {
    el.addEventListener("click", () => {
      const idx = Number(el.dataset.index);
      openEntityArticles(entities[idx].name);
    });
  });

  document.getElementById("add-entity-btn").addEventListener("click", async () => {
    const name = document.getElementById("new-entity-name").value.trim();
    const aliasesRaw = document.getElementById("new-entity-aliases").value.trim();
    if (!name) return;
    const aliases = aliasesRaw ? aliasesRaw.split(",").map((a) => a.trim()).filter(Boolean) : [];
    entities.push({ name, aliases });
    await fetchJSON("/api/tags", { method: "PUT", body: JSON.stringify({ entities }) });
    renderEntitiesPanel();
  });
}

// --- Campaign tracking panel: same shape as entities (a name plus
// aliases, click-through to matched articles), but a distinct category -
// a campaign (ClickFix, a specific RAT) is a technique/tooling name, not
// an actor, so it lives in its own tab rather than being folded into
// APT/Entities.

async function renderCampaignsPanel() {
  const list = document.getElementById("list");
  const panel = document.getElementById("manage-panel");
  list.hidden = true;
  panel.hidden = false;
  document.getElementById("attack-view").hidden = true;
  document.getElementById("pocs-view").hidden = true;

  let data;
  try {
    data = await fetchJSON("/api/campaigns");
  } catch (err) {
    panel.innerHTML = errorHTML(err);
    return;
  }
  const campaigns = data.campaigns || [];

  panel.innerHTML = `<div class="category-label">// TRACKED CAMPAIGNS</div>` +
    (campaigns.length
      ? campaigns.map((c, i) => `
        <div class="entity-card" data-index="${i}">
          <div class="entity-name">${c.name} <span class="remove" style="float:right;cursor:pointer;">x</span></div>
          <div class="entity-aliases">${(c.aliases || []).join(", ") || "no aliases"}</div>
        </div>
      `).join("")
      : `<div class="empty-state">NO CAMPAIGNS TRACKED YET.</div>`) +
    `<div class="add-row">
      <input id="new-campaign-name" placeholder="name (e.g. ClickFix, DoubleCup)">
      <input id="new-campaign-aliases" placeholder="aliases, comma-separated">
      <button id="add-campaign-btn">ADD</button>
    </div>`;

  panel.querySelectorAll(".entity-card .remove").forEach((el) => {
    el.addEventListener("click", async (e) => {
      e.stopPropagation();
      const idx = Number(el.closest(".entity-card").dataset.index);
      campaigns.splice(idx, 1);
      await fetchJSON("/api/campaigns", { method: "PUT", body: JSON.stringify({ campaigns }) });
      renderCampaignsPanel();
    });
  });

  panel.querySelectorAll(".entity-card").forEach((el) => {
    el.addEventListener("click", () => {
      const idx = Number(el.dataset.index);
      openCampaignArticles(campaigns[idx].name);
    });
  });

  document.getElementById("add-campaign-btn").addEventListener("click", async () => {
    const name = document.getElementById("new-campaign-name").value.trim();
    const aliasesRaw = document.getElementById("new-campaign-aliases").value.trim();
    if (!name) return;
    const aliases = aliasesRaw ? aliasesRaw.split(",").map((a) => a.trim()).filter(Boolean) : [];
    campaigns.push({ name, aliases });
    await fetchJSON("/api/campaigns", { method: "PUT", body: JSON.stringify({ campaigns }) });
    renderCampaignsPanel();
  });
}

async function openCampaignArticles(name) {
  document.getElementById("manage-panel").hidden = true;
  document.getElementById("attack-view").hidden = true;
  document.getElementById("pocs-view").hidden = true;
  closeReader();
  const list = document.getElementById("list");
  list.hidden = false;
  list.innerHTML = `<div class="section-label">// LOADING...</div>`;

  let data;
  try {
    data = await fetchJSON(`/api/campaign/${encodeURIComponent(name)}`);
  } catch (err) {
    list.innerHTML = errorHTML(err);
    return;
  }

  const rows = data.articles.map((a) => `
    <div class="row" data-id="${a.id}">
      <span class="title">${a.title}</span>
      <span class="meta">${formatMeta(a)}</span>
    </div>
  `).join("");

  list.innerHTML = `
    <div class="reader-header">
      <div class="reader-title">${data.campaign_name}</div>
      <div class="reader-close" id="campaign-back-btn">BACK TO CAMPAIGNS [x]</div>
    </div>
    ${rows || '<div class="empty-state">NO ARTICLES MATCHED YET.</div>'}
  `;

  document.getElementById("campaign-back-btn").addEventListener("click", renderCampaignsPanel);
  list.querySelectorAll(".row").forEach((el) => {
    el.addEventListener("click", () => openReader(Number(el.dataset.id)));
  });
}

// --- Entity click-through: same pattern as ATT&CK technique click-through,
// reusing the #list element rather than the manage panel, since this is a
// real filtered article view, not entity CRUD.

async function openEntityArticles(name) {
  document.getElementById("manage-panel").hidden = true;
  document.getElementById("attack-view").hidden = true;
  document.getElementById("pocs-view").hidden = true;
  closeReader();
  const list = document.getElementById("list");
  list.hidden = false;
  list.innerHTML = `<div class="section-label">// LOADING...</div>`;

  let data;
  try {
    data = await fetchJSON(`/api/entity/${encodeURIComponent(name)}`);
  } catch (err) {
    list.innerHTML = errorHTML(err);
    return;
  }

  const rows = data.articles.map((a) => `
    <div class="row" data-id="${a.id}">
      <span class="title">${a.title}</span>
      <span class="meta">${formatMeta(a)}</span>
    </div>
  `).join("");

  list.innerHTML = `
    <div class="reader-header">
      <div class="reader-title">${data.entity_name}</div>
      <div class="reader-close" id="entity-back-btn">BACK TO ENTITIES [x]</div>
    </div>
    ${rows || '<div class="empty-state">NO ARTICLES MATCHED YET.</div>'}
  `;

  document.getElementById("entity-back-btn").addEventListener("click", renderEntitiesPanel);
  list.querySelectorAll(".row").forEach((el) => {
    el.addEventListener("click", () => openReader(Number(el.dataset.id)));
  });
}

// --- Tab / subtab wiring ---

function setActiveTab(tabEl) {
  document.querySelectorAll(".tab").forEach((t) => t.classList.remove("active"));
  tabEl.classList.add("active");
}

function setActiveSubtab(subEl) {
  document.querySelectorAll(".subtab").forEach((t) => t.classList.remove("active"));
  subEl.classList.add("active");
}

const manageToggle = document.getElementById("manage-toggle");

document.querySelectorAll(".tab").forEach((tabEl) => {
  tabEl.addEventListener("click", () => {
    setActiveTab(tabEl);
    state.tab = tabEl.dataset.tab;
    state.managingWatchlist = false;
    clearSearch();
    refresh();
  });
});

// --- Search input wiring ---

const searchInput = document.getElementById("search-input");
const searchClear = document.getElementById("search-clear");
let searchDebounce = null;

function clearSearch() {
  state.searchQuery = "";
  searchInput.value = "";
  searchClear.hidden = true;
}

searchInput.addEventListener("input", () => {
  searchClear.hidden = !searchInput.value;
  clearTimeout(searchDebounce);
  searchDebounce = setTimeout(() => {
    state.searchQuery = searchInput.value.trim();
    refresh();
  }, 300);
});

searchInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") {
    clearTimeout(searchDebounce);
    state.searchQuery = searchInput.value.trim();
    refresh();
  }
});

searchClear.addEventListener("click", () => {
  clearSearch();
  refresh();
});

document.querySelectorAll(".subtab:not(#manage-toggle)").forEach((subEl) => {
  subEl.addEventListener("click", () => {
    setActiveSubtab(subEl);
    state.range = subEl.dataset.range;
    refresh();
  });
});

manageToggle.addEventListener("click", () => {
  state.managingWatchlist = !state.managingWatchlist;
  manageToggle.textContent = state.managingWatchlist ? "BACK TO MATCHES" : "MANAGE WATCHLIST";
  refresh();
});

function refresh() {
  manageToggle.hidden = state.tab !== "watchlist";
  document.getElementById("subnav-ranges").hidden = state.tab === "attack" || state.tab === "pocs";

  if (state.searchQuery) {
    renderSearchResults(state.searchQuery);
  } else if (state.tab === "attack") {
    renderAttackMatrix();
  } else if (state.tab === "pocs") {
    renderPocsOverview();
  } else if (state.tab === "watchlist" && state.managingWatchlist) {
    renderWatchlistPanel();
  } else if (state.tab === "entities") {
    // Entities starts empty, so the management panel is the primary view.
    renderEntitiesPanel();
  } else if (state.tab === "campaigns") {
    // Same reasoning as entities - the management panel is the primary view.
    renderCampaignsPanel();
  } else {
    loadArticles();
  }
}

document.addEventListener("keydown", (e) => {
  if (e.key !== "Escape") return;
  if (!document.getElementById("image-lightbox").hidden) {
    closeImageLightbox();
  } else if (!document.getElementById("reader-overlay").hidden) {
    closeReader();
  } else if (state.searchQuery) {
    clearSearch();
    refresh();
  }
});

// --- Manual "run check now" ---
// Real on-demand ingestion from the dashboard itself, Neko's explicit
// request, mirroring TCG Price Tracker's own "Run price check now"
// button. The backend runs the real job in a background thread and
// guards against overlap server-side (see server.py) - this just starts
// it and polls for the real result rather than trusting a fixed timeout.

const runCheckBtn = document.getElementById("run-check-btn");
let ingestPollTimer = null;

function setRunCheckIdle(text) {
  runCheckBtn.textContent = text;
  runCheckBtn.classList.remove("running");
}

function setRunCheckRunning() {
  runCheckBtn.textContent = "CHECKING...";
  runCheckBtn.classList.add("running");
}

function startIngestPolling() {
  if (ingestPollTimer) return;
  ingestPollTimer = setInterval(pollIngestStatus, 3000);
}

async function pollIngestStatus() {
  let status;
  try {
    status = await fetchJSON("/api/ingest/status");
  } catch (err) {
    clearInterval(ingestPollTimer);
    ingestPollTimer = null;
    setRunCheckIdle("RUN CHECK NOW");
    return;
  }

  if (status.running) {
    setRunCheckRunning();
    return;
  }

  clearInterval(ingestPollTimer);
  ingestPollTimer = null;

  if (status.error) {
    setRunCheckIdle("CHECK FAILED");
  } else if (status.results) {
    const totalNew = status.results.reduce((sum, r) => sum + (r.new || 0), 0);
    setRunCheckIdle(`DONE (+${totalNew} NEW)`);
    refresh();
  } else {
    setRunCheckIdle("RUN CHECK NOW");
    return;
  }
  setTimeout(() => setRunCheckIdle("RUN CHECK NOW"), 6000);
}

runCheckBtn.addEventListener("click", async () => {
  if (runCheckBtn.classList.contains("running")) return;
  setRunCheckRunning();
  try {
    const res = await fetch("/api/ingest/run", { method: "POST" });
    await res.json();
  } catch (err) {
    setRunCheckIdle("RUN CHECK NOW");
    return;
  }
  startIngestPolling();
});

// Reflects a check already running (started from another tab, or right
// before this page loaded) instead of showing a stale idle button.
(async () => {
  try {
    const status = await fetchJSON("/api/ingest/status");
    if (status.running) {
      setRunCheckRunning();
      startIngestPolling();
    }
  } catch (err) {
    // Backend not reachable at load time - the app's own error states
    // elsewhere already cover this; nothing extra needed here.
  }
})();

refresh();
