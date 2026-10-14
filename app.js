/* Copyright (C) 2026 Cameron Gates (GodOfNekos)
   SPDX-License-Identifier: AGPL-3.0-or-later */
// NekoCTI dashboard - vanilla JS, no framework or build step.
//
// Everything shown comes from feeds, advisories and user-edited lists, so
// every value that goes into HTML passes through esc(), and every link or
// image through safeUrl(). The server's Content-Security-Policy is the
// backstop, not the plan.

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

const ESCAPES = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
const esc = (value) => String(value ?? "").replace(/[&<>"']/g, (c) => ESCAPES[c]);
const safeUrl = (url) => (/^https?:\/\//i.test(url || "") ? esc(url) : "");

async function fetchJSON(url, opts) {
  const res = await fetch(url, opts);
  if (res.status === 401) location.replace("/login"); // session expired or logged out
  if (!res.ok) throw new Error(`${url} -> HTTP ${res.status}`);
  return res.json();
}

// Every write carries the header the server requires (see server.py).
function writeJSON(url, method, body) {
  return fetchJSON(url, {
    method,
    headers: { "X-NekoCTI": "1", "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

function errorHTML(err) {
  return `<div class="empty-state error-state">SIGNAL LOST - COULD NOT REACH NEKOCTI BACKEND.<br>${esc(err.message || err)}</div>`;
}

// Show one content region and hide the others and the reader.
const VIEWS = ["list", "manage-panel", "attack-view", "pocs-view"];
function showView(id) {
  for (const v of VIEWS) document.getElementById(v).hidden = v !== id;
  closeReader();
  return document.getElementById(id);
}

// NVD's official score when enrichment has it, else the article's own claim.
function cveScore(c) {
  return c.nvd_cvss !== null && c.nvd_cvss !== undefined ? c.nvd_cvss : c.cvss;
}

// KEV is CISA confirming use, an exploit report is our own coverage saying
// so, EPSS is a prediction. Distinct from "a PoC exists".
function exploitTags(c) {
  const tags = [];
  if (c.kev) tags.push(`<span class="tag-kev">KEV${c.kev_ransomware === "Known" ? " RANSOMWARE" : ""}</span>`);
  else if (c.exploit_reports) tags.push(`<span class="tag-wild">EXPLOITED REPORTED</span>`);
  if (c.epss_percentile !== null && c.epss_percentile !== undefined && c.epss_percentile >= 0.95) {
    const stale = c.epss_stale ? ` <span class="tag-stale" title="EPSS from ${esc(c.epss_date)}, refreshed on the next check">STALE</span>` : "";
    tags.push(`<span class="tag-epss">EPSS ${(c.epss_percentile * 100).toFixed(0)}th</span>${stale}`);
  }
  return tags.join(" ");
}

function formatMeta(article) {
  const bits = [];
  if (article.cves.length === 1) {
    const c = article.cves[0];
    const score = cveScore(c);
    const label = score ? `<span class="${score >= 9 ? "cve-crit" : ""}">${esc(c.id)} (${esc(score)})</span>` : esc(c.id);
    bits.push([label, exploitTags(c)].filter(Boolean).join(" "));
  } else if (article.cves.length > 1) {
    const scores = article.cves.map(cveScore).filter((s) => s !== null && s !== undefined);
    let note = `${article.cves.length} CVEs`;
    if (scores.length) note += `, highest ${esc(Math.max(...scores))}`;
    const kev = article.cves.filter((c) => c.kev).length;
    const wild = article.cves.filter((c) => !c.kev && c.exploit_reports).length;
    if (kev) note += ` <span class="tag-kev">${kev} KEV</span>`;
    if (wild) note += ` <span class="tag-wild">${wild} REPORTED EXPLOITED</span>`;
    bits.push(note);
  }
  if (article.vendors.length) {
    const shown = article.vendors.slice(0, 3).map(esc).join(", ");
    const extra = article.vendors.length > 3 ? ` +${article.vendors.length - 3} more` : "";
    bits.push(shown + extra);
  }
  if (article.entities.length) bits.push(article.entities.map(esc).join(", "));
  if (article.campaigns && article.campaigns.length) bits.push(article.campaigns.map(esc).join(", "));
  bits.push(esc(article.published_at));
  return bits.filter(Boolean).map((b) => `<span>${b}</span>`).join("");
}

// The one article-row template, and its click-through to the reader.
function articleRows(articles, { pocFlag = false } = {}) {
  return articles.map((a) => `
    <div class="row ${a.id === state.selectedId ? "selected" : ""}" data-id="${esc(a.id)}">
      <span class="title">${pocFlag && a.mentions_poc ? '<span class="poc-mention-flag">[POC DISCUSSED]</span> ' : ""}${esc(a.title)}</span>
      <span class="meta">${formatMeta(a)}</span>
    </div>
  `).join("");
}

function wireRows(container) {
  container.querySelectorAll(".row[data-id]").forEach((el) => {
    el.addEventListener("click", () => {
      state.selectedId = Number(el.dataset.id);
      openReader(state.selectedId);
    });
  });
}

function readerHeader(title, closeId, closeLabel) {
  return `<div class="reader-header">
      <div class="reader-title">${esc(title)}</div>
      <div class="reader-close" id="${closeId}">${closeLabel} [x]</div>
    </div>`;
}

function renderList(articles) {
  const list = showView("list");
  if (!articles.length) {
    list.innerHTML = `<div class="empty-state">NOTHING CAPTURED YET IN THIS RANGE.</div>`;
    return;
  }
  list.innerHTML = `<div class="section-label">// ${TAB_LABELS[state.tab] || ""}</div>${articleRows(articles)}`;
  wireRows(list);
}

async function loadArticles() {
  try {
    const data = await fetchJSON(`/api/articles?tab=${encodeURIComponent(state.tab)}&range=${encodeURIComponent(state.range)}`);
    renderList(data.articles);
    updateCounts(data.counts);
  } catch (err) {
    showView("list").innerHTML = errorHTML(err);
  }
}

// --- Search: FTS5 across the whole archive, ranked by relevance ---

async function renderSearchResults(query) {
  const list = showView("list");
  list.innerHTML = `<div class="section-label">// SEARCHING...</div>`;

  let data;
  try {
    data = await fetchJSON(`/api/search?q=${encodeURIComponent(query)}`);
  } catch (err) {
    list.innerHTML = errorHTML(err);
    return;
  }

  const label = `// SEARCH RESULTS FOR "${esc(query)}"`;
  if (!data.articles.length) {
    list.innerHTML = `<div class="section-label">${label}</div><div class="empty-state">NO MATCHES.</div>`;
    return;
  }
  list.innerHTML = `<div class="section-label">${label} (${data.articles.length})</div>${articleRows(data.articles)}`;
  wireRows(list);
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

// --- Reader: the captured article, read in the dashboard ---

async function openReader(id) {
  const overlay = document.getElementById("reader-overlay");
  overlay.hidden = false;
  overlay.innerHTML = `<div class="reader-body">LOADING...</div>`;

  let article;
  try {
    article = await fetchJSON(`/api/article/${encodeURIComponent(id)}`);
  } catch (err) {
    overlay.innerHTML = `<div class="reader-body">${errorHTML(err)}</div>`;
    return;
  }

  const metaParts = [];
  if (article.published_at) metaParts.push(article.published_at);
  if (article.cves.length) {
    metaParts.push(article.cves.map((c) => {
      const score = cveScore(c);
      const sev = c.nvd_severity ? ` ${c.nvd_severity}` : "";
      const base = score ? `${c.id} (${score}${sev})` : c.id;
      const tags = [];
      if (c.kev) tags.push(`KEV${c.kev_date ? ` ${c.kev_date}` : ""}${c.kev_ransomware === "Known" ? ", RANSOMWARE" : ""}`);
      else if (c.exploit_reports) tags.push("EXPLOITATION REPORTED");
      if (c.epss_percentile !== null && c.epss_percentile !== undefined) {
        tags.push(`EPSS ${(c.epss_percentile * 100).toFixed(0)}th`);
      }
      return tags.length ? `${base} [${tags.join(" / ")}]` : base;
    }).join(", "));
  }
  if (article.vendors.length) metaParts.push(`VENDORS: ${article.vendors.join(", ")}`);
  if (article.entities.length) metaParts.push(`TRACKED: ${article.entities.join(", ")}`);
  if (article.campaigns && article.campaigns.length) metaParts.push(`CAMPAIGN: ${article.campaigns.join(", ")}`);
  if (article.is_breach) metaParts.push("FLAGGED: MAJOR BREACH");
  if (article.mentions_poc) metaParts.push("PoC/EXPLOIT DISCUSSED");
  if (article.exploited_in_wild) metaParts.push("REPORTS EXPLOITATION IN THE WILD");

  // Images as captured, recoloured by CSS; hover or the link shows the original.
  const images = (article.images || []).map(safeUrl).filter(Boolean);
  const imagesHtml = images.length ? `
    <div class="reader-images">
      <div class="section-label">// CAPTURED IMAGES (${images.length})</div>
      <div class="reader-images-grid">
        ${images.map((src, i) => `
          <div class="reader-image-card">
            <div class="reader-image-index">IMAGE ${i + 1} OF ${images.length}</div>
            <img class="reader-image" src="${src}" loading="lazy" alt="">
            <a class="reader-image-original" href="${src}" target="_blank" rel="noopener noreferrer">VIEW ORIGINAL &rarr;</a>
          </div>
        `).join("")}
      </div>
    </div>
  ` : "";
  const link = safeUrl(article.link);

  overlay.innerHTML = `
    ${readerHeader(article.title, "reader-close-btn", "CLOSE")}
    <div class="reader-meta">${metaParts.map((m) => `<span>${esc(m)}</span>`).join("")}</div>
    <div class="reader-main">
      <div class="reader-body">${renderArticleBody(article.body)}</div>
      ${imagesHtml}
    </div>
    ${link ? `<a class="reader-source-link" href="${link}" target="_blank" rel="noopener noreferrer">VIEW ORIGINAL SOURCE &rarr;</a>` : ""}
  `;

  document.getElementById("reader-close-btn").addEventListener("click", closeReader);
  overlay.querySelectorAll(".reader-image").forEach((img) => {
    img.addEventListener("click", () => openImageLightbox(img.src));
  });
}

// Full-size, true-colour zoom for reading fine detail on a diagram.
function openImageLightbox(src) {
  const box = document.getElementById("image-lightbox");
  box.hidden = false;
  box.innerHTML = `
    <div class="reader-close" id="lightbox-close-btn">CLOSE [x]</div>
    <img src="${safeUrl(src)}" alt="">
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

// Markdown pipe-tables in article text (ZDI's patch roundups, for one) are
// rendered as real tables; everything else stays escaped plain text.
function splitTableRow(line) {
  return line.trim().replace(/^\|/, "").replace(/\|$/, "").split("|").map((c) => c.trim());
}

function isSeparatorCells(cells) {
  return cells.length > 0 && cells.every((c) => c === "" || /^:?-+:?$/.test(c));
}

function renderMarkdownTable(lines) {
  const rows = lines.map(splitTableRow);
  const sepIdxs = rows.reduce((acc, cells, i) => (isSeparatorCells(cells) ? [...acc, i] : acc), []);
  if (!sepIdxs.length) return esc(lines.join("\n"));

  // With several separator rows, only the row before the last one is the
  // header; anything earlier is a caption.
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

  const headHtml = `<tr>${headerCells.map((c) => `<th>${esc(c)}</th>`).join("")}</tr>`;
  const bodyHtml = bodyRows.map((cells) =>
    `<tr>${cells.map((c) => `<td${yesNoClass(c)}>${esc(c)}</td>`).join("")}</tr>`
  ).join("");

  return `${captionText ? `<div class="reader-table-caption">${esc(captionText)}</div>` : ""}
    <div class="reader-table-wrap"><table class="reader-table"><thead>${headHtml}</thead><tbody>${bodyHtml}</tbody></table></div>`;
}

function renderArticleBody(text) {
  const lines = String(text ?? "").split("\n");
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
  return blocks.map((b) => b.type === "table" ? renderMarkdownTable(b.lines) : esc(b.lines.join("\n"))).join("");
}

// --- MITRE ATT&CK matrix: every technique, dimmed where nothing matched ---

let attackMatrixCache = null;

async function renderAttackMatrix() {
  const view = showView("attack-view");

  if (!attackMatrixCache) {
    view.innerHTML = `<div class="attack-search"><input disabled placeholder="LOADING REAL ATT&amp;CK DATA..."></div>`;
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
      <div class="attack-tech ${info.count > 0 ? "has-matches" : ""}" data-id="${esc(id)}" data-name="${esc(info.name.toLowerCase())}">
        ${esc(id)}: ${esc(info.name)}${info.count > 0 ? `<span class="tech-count">${info.count}</span>` : ""}
      </div>
    `).join("");

    return `
      <div class="attack-col" data-tactic="${esc(tactic.shortname)}">
        <div class="attack-col-header">${esc(tactic.name.toUpperCase())}</div>
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
    data = await fetchJSON(`/api/attack/technique/${encodeURIComponent(techniqueId)}`);
  } catch (err) {
    view.innerHTML = errorHTML(err);
    return;
  }

  view.innerHTML = `
    ${readerHeader(`${data.technique_id}: ${data.technique_name}`, "attack-back-btn", "BACK TO MATRIX")}
    <div class="list">
      ${articleRows(data.articles) || '<div class="empty-state">NO MATCHED ARTICLES.</div>'}
    </div>
  `;
  document.getElementById("attack-back-btn").addEventListener("click", renderAttackMatrix);
  wireRows(view);
}

// --- Public PoC availability (nomi-sec/PoC-in-GitHub), read fresh each time ---

async function renderPocsOverview() {
  const view = showView("pocs-view");
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
  const rows = cves.map((c) => {
    const score = cveScore(c);
    const search = [c.cve_id, c.title || "", ...c.vendors, ...c.attack_techniques.map((t) => t.technique_id)].join(" ").toLowerCase();
    return `
    <div class="row poc-row" data-cve="${esc(c.cve_id)}" data-search="${esc(search)}">
      <span class="title">
        ${esc(c.cve_id)}${score ? ` <span class="${score >= 9 ? "cve-crit" : ""}">(CVSS ${esc(score)}${c.nvd_severity ? ` ${esc(c.nvd_severity)}` : ""})</span>` : ""}
        ${exploitTags(c) ? ` ${exploitTags(c)}` : ""}
        ${c.title ? `<div class="poc-cve-desc">${esc(c.title)}</div>` : ""}
        ${c.vendors.length ? `<div class="poc-cve-vendors">${c.vendors.map(esc).join(", ")}</div>` : ""}
        ${c.attack_techniques.length ? `<div class="poc-attack-tags">${c.attack_techniques.map((t) =>
          `<span class="attack-tag ${t.confidence === "expert" ? "attack-tag-expert" : "attack-tag-llm"}" title="${esc(t.technique_name)}">${esc(t.technique_id)}</span>`
        ).join("")}</div>` : ""}
      </span>
      <span class="meta">
        <span>${c.latest_activity_at ? esc(c.latest_activity_at.slice(0, 10)) : ""}</span>
        ${c.has_public_repo
          ? `<span>${c.poc_count} PUBLIC REPO${c.poc_count === 1 ? "" : "S"}</span><span>${esc(c.max_stars)}&#9733; TOP</span>`
          : `<span class="poc-mention-only">MENTIONED, NO PUBLIC REPO</span>`}
        ${c.mention_count ? `<span>${c.mention_count} DISCUSSED IN</span>` : ""}
        ${c.article_count ? `<span>${c.article_count} ARTICLE${c.article_count === 1 ? "" : "S"}</span>` : ""}
      </span>
    </div>`;
  }).join("");

  view.innerHTML = `
    <div class="attack-search"><input id="pocs-search-input" placeholder="SEARCH CVE ID..."></div>
    <div class="list sublist">
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

  const pocRows = data.pocs.map((p) => {
    const url = safeUrl(p.repo_url);
    const name = esc(p.repo_full_name);
    return `
    <div class="row poc-repo-row">
      <span class="title">
        ${url ? `<a href="${url}" target="_blank" rel="noopener noreferrer">${name}</a>` : name}
        ${p.description ? `<div class="poc-repo-desc">${esc(p.description)}</div>` : ""}
      </span>
      <span class="meta">
        <span>${esc(p.stars)}&#9733;</span>
        <span>${p.repo_pushed_at ? esc(p.repo_pushed_at.slice(0, 10)) : ""}</span>
      </span>
    </div>`;
  }).join("");

  const mappingTypeLabel = { exploitation_technique: "EXPLOITATION TECHNIQUE", primary_impact: "PRIMARY IMPACT",
    secondary_impact: "SECONDARY IMPACT" };
  const attackRows = data.attack_techniques.map((t) => {
    const source = safeUrl(t.source_url);
    return `
    <div class="row poc-attack-row">
      <span class="title">
        ${esc(t.technique_id)}: ${esc(t.technique_name)}
        ${t.evidence ? `<div class="poc-repo-desc">${esc(t.evidence)}</div>` : ""}
        ${source ? `<a class="poc-attack-source" href="${source}" target="_blank" rel="noopener noreferrer">SOURCE &rarr;</a>` : ""}
      </span>
      <span class="meta">
        ${t.confidence === "expert"
          ? `<span class="attack-tag attack-tag-expert">MITRE-MAPPED</span><span>${esc(mappingTypeLabel[t.mapping_type] || t.mapping_type || "")}</span>`
          : `<span class="attack-tag attack-tag-llm">BEST GUESS (LLM)</span>`}
      </span>
    </div>`;
  }).join("");

  view.innerHTML = `
    ${readerHeader(data.cve_id, "pocs-back-btn", "BACK TO POCS")}
    <div class="list sublist sublist-loose">
      <div class="section-label">// PUBLIC POC REPOS (${data.pocs.length})</div>
      ${pocRows || '<div class="empty-state">NONE FOUND - MAY STILL BE DISCUSSED IN COVERAGE BELOW WITHOUT A PUBLIC REPO.</div>'}
      <div class="section-label">// MITRE ATT&amp;CK (${data.attack_techniques.length})</div>
      ${attackRows || '<div class="empty-state">NOT MAPPED YET - RUN classify-pocs TO TAG THIS CVE.</div>'}
      <div class="section-label">// NEKOCTI COVERAGE (${data.articles.length})</div>
      ${articleRows(data.articles, { pocFlag: true }) || '<div class="empty-state">NO CAPTURED ARTICLES MENTION THIS CVE.</div>'}
    </div>
  `;

  document.getElementById("pocs-back-btn").addEventListener("click", renderPocsOverview);
  wireRows(view);
}

// --- Watchlist management ---

async function renderWatchlistPanel() {
  const panel = showView("manage-panel");

  let data;
  try {
    data = await fetchJSON("/api/watchlist");
  } catch (err) {
    panel.innerHTML = errorHTML(err);
    return;
  }
  const vendors = data.vendors || {};

  panel.innerHTML = Object.entries(vendors).map(([category, terms]) => `
    <div class="category" data-category="${esc(category)}">
      <div class="category-label">// ${esc(category.toUpperCase().replace(/_/g, " "))}</div>
      <div class="term-list">
        ${terms.map((t) => `<span class="term" data-term="${esc(t)}">${esc(t)}<span class="remove">x</span></span>`).join("")}
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
      vendors[category] = vendors[category].filter((t) => t !== termEl.dataset.term);
      await writeJSON("/api/watchlist", "PUT", { vendors });
      renderWatchlistPanel();
    });
  });

  document.getElementById("add-term-btn").addEventListener("click", async () => {
    const category = document.getElementById("new-category").value.trim();
    const term = document.getElementById("new-term").value.trim();
    if (!category || !term) return;
    vendors[category] = vendors[category] || [];
    vendors[category].push(term);
    await writeJSON("/api/watchlist", "PUT", { vendors });
    renderWatchlistPanel();
  });
}

// --- Tracked entities and campaigns: the same panel and drill-down, two
// lists. A campaign is a technique or tooling name, not an actor. ---

const TRACKED = {
  entities: {
    api: "/api/tags", key: "entities", label: "TRACKED ENTITIES", empty: "NO ENTITIES TRACKED YET.",
    namePlaceholder: "name (e.g. threat actor / campaign)", articles: "/api/entity/", nameKey: "entity_name",
    back: "BACK TO ENTITIES",
  },
  campaigns: {
    api: "/api/campaigns", key: "campaigns", label: "TRACKED CAMPAIGNS", empty: "NO CAMPAIGNS TRACKED YET.",
    namePlaceholder: "name (e.g. ClickFix, DoubleCup)", articles: "/api/campaign/", nameKey: "campaign_name",
    back: "BACK TO CAMPAIGNS",
  },
};

async function renderTrackedPanel(kind) {
  const cfg = TRACKED[kind];
  const panel = showView("manage-panel");

  let data;
  try {
    data = await fetchJSON(cfg.api);
  } catch (err) {
    panel.innerHTML = errorHTML(err);
    return;
  }
  const items = data[cfg.key] || [];
  const save = async () => {
    await writeJSON(cfg.api, "PUT", { [cfg.key]: items });
    renderTrackedPanel(kind);
  };

  panel.innerHTML = `<div class="category-label">// ${cfg.label}</div>` +
    (items.length
      ? items.map((item, i) => `
        <div class="entity-card" data-index="${i}">
          <div class="entity-name">${esc(item.name)} <span class="remove remove-right">x</span></div>
          <div class="entity-aliases">${(item.aliases || []).map(esc).join(", ") || "no aliases"}</div>
        </div>
      `).join("")
      : `<div class="empty-state">${cfg.empty}</div>`) +
    `<div class="add-row">
      <input id="new-tracked-name" placeholder="${esc(cfg.namePlaceholder)}">
      <input id="new-tracked-aliases" placeholder="aliases, comma-separated">
      <button id="add-tracked-btn">ADD</button>
    </div>`;

  panel.querySelectorAll(".entity-card .remove").forEach((el) => {
    el.addEventListener("click", (e) => {
      e.stopPropagation();
      items.splice(Number(el.closest(".entity-card").dataset.index), 1);
      save();
    });
  });

  panel.querySelectorAll(".entity-card").forEach((el) => {
    el.addEventListener("click", () => openTrackedArticles(kind, items[Number(el.dataset.index)].name));
  });

  document.getElementById("add-tracked-btn").addEventListener("click", () => {
    const name = document.getElementById("new-tracked-name").value.trim();
    const aliasesRaw = document.getElementById("new-tracked-aliases").value.trim();
    if (!name) return;
    const aliases = aliasesRaw ? aliasesRaw.split(",").map((a) => a.trim()).filter(Boolean) : [];
    items.push({ name, aliases });
    save();
  });
}

async function openTrackedArticles(kind, name) {
  const cfg = TRACKED[kind];
  const list = showView("list");
  list.innerHTML = `<div class="section-label">// LOADING...</div>`;

  let data;
  try {
    data = await fetchJSON(`${cfg.articles}${encodeURIComponent(name)}`);
  } catch (err) {
    list.innerHTML = errorHTML(err);
    return;
  }

  list.innerHTML = `
    ${readerHeader(data[cfg.nameKey], "tracked-back-btn", cfg.back)}
    ${articleRows(data.articles) || '<div class="empty-state">NO ARTICLES MATCHED YET.</div>'}
  `;
  document.getElementById("tracked-back-btn").addEventListener("click", () => renderTrackedPanel(kind));
  wireRows(list);
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
  setSearchOpen(false);
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
  } else if (state.tab in TRACKED) {
    renderTrackedPanel(state.tab);   // these lists start empty, so the panel leads
  } else {
    loadArticles();
  }
}

document.addEventListener("keydown", (e) => {
  if (e.key !== "Escape") return;
  if (!navMenu.hidden) {
    setMenuOpen(false);
  } else if (!document.getElementById("image-lightbox").hidden) {
    closeImageLightbox();
  } else if (!document.getElementById("reader-overlay").hidden) {
    closeReader();
  } else if (state.searchQuery) {
    clearSearch();
    refresh();
  }
});

// --- Run check now: the server runs it in the background and refuses an
// overlapping run; this starts it and polls for the result ---

const runCheckBtn = document.getElementById("run-check-btn");
let ingestPollTimer = null;

// The footer chip on desktop; the sections menu on phone and tablet.
async function logOut() {
  try {
    await writeJSON("/api/logout", "POST");
  } finally {
    location.replace("/login");
  }
}
document.getElementById("logout-btn").addEventListener("click", logOut);

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

// "12m ago" style, or "never".
function ago(iso) {
  if (!iso) return "never";
  const then = new Date(iso.endsWith("Z") || iso.includes("+") ? iso : iso + "Z");
  const mins = Math.round((Date.now() - then.getTime()) / 60000);
  if (!isFinite(mins)) return "never";
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  if (mins < 60 * 24) return `${Math.round(mins / 60)}h ago`;
  return `${Math.round(mins / 1440)}d ago`;
}

// The archive is never pruned, so freshness means the facts were re-checked.
function renderFreshness(f) {
  const el = document.getElementById("freshness-line");
  if (!el || !f) return;
  const waiting = f.cves_awaiting_nvd
    ? ` &middot; <span class="fresh-warn">${esc(f.cves_awaiting_nvd)} CVE${f.cves_awaiting_nvd === 1 ? "" : "s"} awaiting severity</span>`
    : "";
  el.innerHTML =
    `LAST CHECK ${ago(f.last_article_fetched_at)}` +
    ` &middot; EPSS ${ago(f.last_epss_at)}${f.epss_data_date ? ` (data ${esc(f.epss_data_date)})` : ""}` +
    ` &middot; KEV ${ago(f.last_kev_at)}` +
    ` &middot; SEVERITY ${esc(f.cves_with_severity)}/${esc(f.cves_total)}` +
    ` &middot; ${esc(f.kev_listed)} KEV &middot; ${esc(f.reported_exploited)} REPORTED EXPLOITED` +
    waiting;

  // Phone/tablet footer shows the headline; the full line opens on tap, and
  // the warn class keeps an awaiting-severity backlog visible meanwhile.
  const agoEl = document.getElementById("footer-ago");
  if (agoEl) agoEl.textContent = ` · ${ago(f.last_article_fetched_at).toUpperCase()}`;
  document.getElementById("footer-status-wrap")?.classList.toggle("has-warn", Boolean(f.cves_awaiting_nvd));
}

async function refreshFreshness() {
  try {
    const status = await fetchJSON("/api/ingest/status");
    renderFreshness(status.freshness);
  } catch (err) {
    // The views' own error states cover an unreachable backend.
  }
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

  renderFreshness(status.freshness);

  if (status.error) {
    setRunCheckIdle("CHECK FAILED");
  } else if (status.results) {
    // Articles only: enrichment entries count repos found, not articles.
    const totalNew = status.results
      .filter((r) => r.kind !== "enrichment")
      .reduce((sum, r) => sum + (r.new || 0), 0);
    const e = status.enrich;
    const extra = status.enrich_error
      ? ", REFRESH FAILED"
      : e ? `, ${e.nvd_scored || 0} SEVERITY, ${e.epss_updated || 0} EPSS` : "";
    setRunCheckIdle(`DONE (+${totalNew} NEW${extra})`);
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
    await writeJSON("/api/ingest/run", "POST");
  } catch (err) {
    // A 409 means a check is already running: poll it rather than give up.
    if (!String(err.message).includes("409")) {
      setRunCheckIdle("RUN CHECK NOW");
      return;
    }
  }
  startIngestPolling();
});

// Reflect a check already running (another tab, or just before this load).
(async () => {
  try {
    const status = await fetchJSON("/api/ingest/status");
    if (status.running) {
      setRunCheckRunning();
      startIngestPolling();
    }
  } catch (err) {
    // Covered by the views' own error states.
  }
})();

// --- Phone / tablet navigation (1023px and below): one slim bar and a
// menu built from the .tab elements, which stay the source of truth ---

const navMenu = document.getElementById("nav-menu");
const menuBtn = document.getElementById("menu-btn");
const mbCurrent = document.getElementById("mb-current");
const screenEl = document.querySelector(".screen");
const subnavEl = document.querySelector(".subnav");
const searchToggle = document.getElementById("search-toggle");

function tabLabel(tabEl) {
  return tabEl.firstChild.textContent.trim();
}

function tabCount(tabEl) {
  const c = tabEl.querySelector(".count");
  return c && c.textContent !== "-" ? c.textContent : "";
}

function syncMobileBar() {
  const active = document.querySelector(".topnav .tab.active");
  if (!active) return;
  document.getElementById("mb-section").textContent = tabLabel(active);
  document.getElementById("mb-count").textContent = tabCount(active);
}

function buildNavMenu() {
  const items = [...document.querySelectorAll(".topnav .tab")].map((t) => {
    const selected = t.classList.contains("active");
    return `<button class="row nav-item${selected ? " selected" : ""}" type="button" data-tab="${esc(t.dataset.tab)}"${selected ? ' aria-current="page"' : ""}>
      <span class="title">${esc(tabLabel(t))}</span><span class="meta">${esc(tabCount(t))}</span>
    </button>`;
  }).join("");
  navMenu.innerHTML = `<div class="section-label">// SECTIONS</div>${items}` +
    `<div class="section-label">// SESSION</div><button class="row nav-item" type="button" id="menu-logout"><span class="title">LOG OUT</span></button>`;
  document.getElementById("menu-logout").addEventListener("click", logOut);
  navMenu.querySelectorAll(".nav-item[data-tab]").forEach((item) => {
    item.addEventListener("click", () => {
      document.querySelector(`.topnav .tab[data-tab="${item.dataset.tab}"]`).click();
      setMenuOpen(false);
    });
  });
}

function setMenuOpen(open) {
  if (open) buildNavMenu();
  navMenu.hidden = !open;
  screenEl.classList.toggle("menu-open", open);
  for (const btn of [menuBtn, mbCurrent]) btn.setAttribute("aria-expanded", String(open));
  menuBtn.setAttribute("aria-label", open ? "Close sections menu" : "Open sections menu");
  if (open) {
    (navMenu.querySelector(".nav-item.selected") || navMenu.querySelector(".nav-item"))?.focus();
  } else if (navMenu.contains(document.activeElement) || document.activeElement === document.body) {
    menuBtn.focus();
  }
}

menuBtn.addEventListener("click", () => setMenuOpen(navMenu.hidden));
mbCurrent.addEventListener("click", () => setMenuOpen(navMenu.hidden));

// Counts arrive asynchronously, so watch the tab row.
new MutationObserver(syncMobileBar).observe(document.querySelector(".topnav"), {
  subtree: true, childList: true, characterData: true, attributes: true, attributeFilter: ["class"],
});
syncMobileBar();

// Search folds into an icon on phone/tablet and takes the row over when open.
function setSearchOpen(open) {
  subnavEl.classList.toggle("searching", open);
  searchToggle.setAttribute("aria-expanded", String(open));
  searchToggle.setAttribute("aria-label", open ? "Close search" : "Search the archive");
  if (open) searchInput.focus();
}

searchToggle.addEventListener("click", () => {
  if (subnavEl.classList.contains("searching")) {
    const hadQuery = Boolean(state.searchQuery);
    clearSearch();
    if (hadQuery) refresh();
  } else {
    setSearchOpen(true);
  }
});

// The footer's status line opens the full freshness detail on phone/tablet.
const statusWrap = document.getElementById("footer-status-wrap");
statusWrap.setAttribute("role", "button");
statusWrap.setAttribute("tabindex", "0");
statusWrap.setAttribute("aria-controls", "freshness-line");
function toggleFreshness() {
  const open = screenEl.classList.toggle("fresh-open");
  statusWrap.setAttribute("aria-expanded", String(open));
}
statusWrap.addEventListener("click", toggleFreshness);
statusWrap.addEventListener("keydown", (e) => {
  if (e.key === "Enter" || e.key === " ") { e.preventDefault(); toggleFreshness(); }
});

refresh();
refreshFreshness();
