/* Penego shared UI — search/filter history, result filters, export reports */
window.Penego = (function () {
  const historyState = {
    scanType: "",
    page: 1,
    limit: 10,
    q: "",
    status: "",
    total: 0,
  };

  function el(tag, attrs, children) {
    const node = document.createElement(tag);
    if (attrs) {
      Object.entries(attrs).forEach(([k, v]) => {
        if (k === "className") node.className = v;
        else if (k === "text") node.textContent = v;
        else if (k === "html") node.innerHTML = v;
        else if (k.startsWith("on") && typeof v === "function")
          node.addEventListener(k.slice(2).toLowerCase(), v);
        else if (v !== undefined && v !== null) node.setAttribute(k, v);
      });
    }
    (children || []).forEach((c) => {
      if (c == null) return;
      node.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
    });
    return node;
  }

  async function api(url, options) {
    const res = await fetch(url, options);
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || res.statusText);
    return data;
  }

  function sleep(ms) {
    return new Promise((r) => setTimeout(r, ms));
  }

  function clear(node) {
    while (node.firstChild) node.removeChild(node.firstChild);
  }

  function statusPill(status) {
    const s = (status || "unknown").toLowerCase();
    return el("span", { className: "status-pill status-" + s, text: s });
  }

  function exportButtons(scanId, size) {
    const sm = size === "sm";
    const cls = sm ? "btn btn-sm " : "btn ";
    return el("div", { className: "btn-group export-btn-group", role: "group" }, [
      el("a", {
        className: cls + "btn-success",
        href: "/api/scans/" + scanId + "/export.html",
        target: "_blank",
        rel: "noopener",
        download: "penego-scan-" + scanId + ".html",
        title: "Download printable HTML report",
        text: "Export Report",
      }),
      el("a", {
        className: cls + "btn-outline-secondary",
        href: "/api/scans/" + scanId + "/export",
        download: "penego-scan-" + scanId + ".json",
        title: "Download JSON",
        text: "JSON",
      }),
    ]);
  }

  async function pollScan(scanId, onUpdate) {
    for (;;) {
      const scan = await api("/api/scans/" + scanId);
      if (onUpdate) onUpdate(scan);
      if (["done", "failed", "cancelled"].includes(scan.status)) return scan;
      await sleep(1500);
    }
  }

  function renderSummary(container, result) {
    clear(container);
    container.appendChild(
      el("div", { className: "alert alert-success" }, [
        el("h4", { className: "alert-heading", text: result.message || "Scan started" }),
        el("p", {
          className: "mb-0",
          text:
            "Scan ID: " +
            result.scan_id +
            " | Status: " +
            (result.status || "pending") +
            (result.scan_type ? " | Type: " + result.scan_type : ""),
        }),
      ])
    );
  }

  function hostMatchesFilter(host, query) {
    if (!query) return true;
    const q = query.toLowerCase();
    if ((host.ip || "").toLowerCase().includes(q)) return true;
    if ((host.os || "").toLowerCase().includes(q)) return true;
    for (const p of host.open_ports || []) {
      if (String(p.port).includes(q)) return true;
      if ((p.service || "").toLowerCase().includes(q)) return true;
      if ((p.banner || "").toLowerCase().includes(q)) return true;
    }
    for (const f of host.vuln_findings || []) {
      if ((f.title || "").toLowerCase().includes(q)) return true;
      if ((f.cve || "").toLowerCase().includes(q)) return true;
      if ((f.severity || "").toLowerCase().includes(q)) return true;
    }
    return false;
  }

  function buildHostCard(host) {
    const card = el("div", {
      className: "card mb-3 border-success host-card",
      "data-host-ip": host.ip || "",
    });
    card.appendChild(
      el("div", { className: "card-header bg-success text-white" }, [
        el("h5", {
          className: "mb-0",
          text: host.ip + (host.os ? " — " + host.os : ""),
        }),
      ])
    );
    const body = el("div", { className: "card-body" });
    if (host.open_ports && host.open_ports.length) {
      const table = el("table", { className: "table table-sm table-bordered mb-0" });
      table.appendChild(
        el("thead", {}, [
          el("tr", {}, [
            el("th", { text: "Port" }),
            el("th", { text: "Service" }),
            el("th", { text: "Banner" }),
          ]),
        ])
      );
      const tbody = el("tbody");
      host.open_ports.forEach((p) => {
        tbody.appendChild(
          el("tr", {}, [
            el("td", { text: String(p.port) }),
            el("td", { text: p.service || "N/A" }),
            el("td", {}, [el("code", { text: p.banner || "N/A" })]),
          ])
        );
      });
      table.appendChild(tbody);
      body.appendChild(table);
    } else {
      body.appendChild(el("p", { className: "mb-0", text: "Host is alive." }));
    }
    if (host.vuln_findings && host.vuln_findings.length) {
      body.appendChild(el("h6", { className: "mt-3", text: "Findings" }));
      const vt = el("table", { className: "table table-sm" });
      const vb = el("tbody");
      host.vuln_findings.forEach((f) => {
        vb.appendChild(
          el("tr", {}, [
            el("td", { text: f.severity }),
            el("td", { text: f.title }),
            el("td", { text: f.cve || "" }),
            el("td", {}, [el("code", { text: f.evidence || "" })]),
          ])
        );
      });
      vt.appendChild(vb);
      body.appendChild(vt);
    }
    card.appendChild(body);
    return card;
  }

  function renderScanDetail(container, scan) {
    clear(container);
    const wrap = el("div");

    const toolbar = el("div", { className: "scan-toolbar d-flex flex-wrap justify-content-between align-items-center gap-2" });
    toolbar.appendChild(
      el("div", {}, [
        el("h3", { className: "h4 mb-1", text: "Scan #" + scan.id }),
        el("div", { className: "result-meta" }, [
          statusPill(scan.status),
          document.createTextNode(
            "  " +
              scan.target +
              " · " +
              (scan.scan_type || scan.ports_scanned) +
              " · " +
              (scan.progress || 0) +
              "%"
          ),
        ]),
      ])
    );
    const actions = el("div", { className: "d-flex flex-wrap gap-2 align-items-center" });
    actions.appendChild(exportButtons(scan.id));
    if (scan.status === "running" || scan.status === "pending") {
      actions.appendChild(
        el("button", {
          className: "btn btn-outline-warning",
          text: "Cancel",
          onclick: async () => {
            try {
              await api("/api/scans/" + scan.id + "/cancel", { method: "POST" });
              refreshHistory();
            } catch (e) {
              alert(e.message);
            }
          },
        })
      );
    }
    actions.appendChild(
      el("button", {
        className: "btn btn-outline-danger",
        text: "Delete",
        onclick: async () => {
          if (!confirm("Delete scan #" + scan.id + "?")) return;
          await api("/api/scans/" + scan.id, { method: "DELETE" });
          clear(container);
          container.appendChild(el("div", { className: "alert alert-warning", text: "Scan deleted." }));
          refreshHistory();
        },
      })
    );
    toolbar.appendChild(actions);
    wrap.appendChild(toolbar);

    if (scan.error_message) {
      wrap.appendChild(el("div", { className: "alert alert-danger", text: scan.error_message }));
    }

    const alive = scan.true_targets || [];
    const dead = scan.false_targets || [];

    const filterBar = el("div", { className: "host-filter-bar" });
    const hostSearch = el("input", {
      type: "search",
      className: "form-control",
      id: "resultHostFilter",
      placeholder: "Filter hosts by IP, port, service, OS, CVE…",
      style: "max-width: 28rem",
    });
    const showDead = el("div", { className: "form-check form-check-inline ms-1" }, [
      el("input", {
        type: "checkbox",
        className: "form-check-input",
        id: "showDeadHosts",
        checked: "checked",
      }),
      el("label", { className: "form-check-label", for: "showDeadHosts", text: "Show dead hosts" }),
    ]);
    const matchLabel = el("span", { className: "text-muted small align-self-center", id: "hostMatchLabel" });
    filterBar.appendChild(hostSearch);
    filterBar.appendChild(showDead);
    filterBar.appendChild(matchLabel);
    wrap.appendChild(filterBar);

    const aliveHeader = el("h4", { text: "Alive Hosts (" + alive.length + ")" });
    wrap.appendChild(aliveHeader);
    const aliveWrap = el("div", { id: "aliveHostsWrap" });
    if (!alive.length) {
      aliveWrap.appendChild(el("div", { className: "alert alert-info", text: "No alive hosts." }));
    } else {
      alive.forEach((host) => aliveWrap.appendChild(buildHostCard(host)));
    }
    wrap.appendChild(aliveWrap);

    const deadSection = el("div", { id: "deadHostsSection" });
    deadSection.appendChild(el("h4", { className: "mt-3", text: "Dead Hosts (" + dead.length + ")" }));
    if (dead.length) {
      const ul = el("ul", { className: "list-group", id: "deadHostsList" });
      dead.forEach((h) => {
        ul.appendChild(
          el("li", {
            className: "list-group-item dead-host-item",
            "data-host-ip": h.ip || "",
            text: h.ip,
          })
        );
      });
      deadSection.appendChild(ul);
    } else {
      deadSection.appendChild(el("p", { className: "text-muted", text: "None." }));
    }
    wrap.appendChild(deadSection);

    function applyHostFilter() {
      const q = (hostSearch.value || "").trim().toLowerCase();
      const deadCb = wrap.querySelector("#showDeadHosts");
      let shown = 0;
      aliveWrap.querySelectorAll(".host-card").forEach((card, idx) => {
        const host = alive[idx];
        const ok = hostMatchesFilter(host, q);
        card.classList.toggle("hidden-by-filter", !ok);
        if (ok) shown++;
      });
      deadSection.querySelectorAll(".dead-host-item").forEach((li) => {
        const ip = (li.getAttribute("data-host-ip") || "").toLowerCase();
        const ok = !q || ip.includes(q);
        li.classList.toggle("hidden-by-filter", !ok);
      });
      const showDeadChecked = deadCb ? deadCb.checked : true;
      deadSection.hidden = !showDeadChecked;
      matchLabel.textContent = q
        ? "Showing " + shown + " of " + alive.length + " alive hosts"
        : alive.length + " alive · " + dead.length + " dead";
    }

    hostSearch.addEventListener("input", applyHostFilter);
    showDead.querySelector("input").addEventListener("change", applyHostFilter);

    container.appendChild(wrap);
    applyHostFilter();
  }

  function renderHistoryItems(listEl, items) {
    clear(listEl);
    if (!items.length) {
      listEl.appendChild(
        el("div", {
          className: "empty-state",
          text: "No scans match your search. Try another query or clear filters.",
        })
      );
      return;
    }
    items.forEach((scan) => {
      const item = el("div", { className: "scan-history-item" });
      const row = el("div", { className: "d-flex flex-wrap justify-content-between gap-3" });
      const left = el("div", { className: "flex-grow-1" }, [
        el("div", { className: "d-flex flex-wrap align-items-center gap-2 mb-1" }, [
          el("strong", { text: "#" + scan.id + " — " + scan.target }),
          statusPill(scan.status),
        ]),
        el("div", {
          className: "result-meta",
          text:
            new Date(scan.generated).toLocaleString() +
            " · " +
            (scan.scan_type || scan.ports_scanned) +
            " · Alive " +
            (scan.true_targets || []).length +
            " · Dead " +
            (scan.false_targets || []).length +
            (scan.progress != null ? " · " + scan.progress + "%" : ""),
        }),
      ]);
      const right = el("div", { className: "d-flex flex-wrap gap-2 align-items-start" });
      right.appendChild(exportButtons(scan.id, "sm"));
      right.appendChild(
        el("button", {
          className: "btn btn-sm btn-primary",
          text: "View",
          onclick: async () => {
            try {
              const detail = await api("/api/scans/" + scan.id);
              const results = document.getElementById("results");
              const content = document.getElementById("resultContent");
              if (results) results.style.display = "block";
              renderScanDetail(content, detail);
              results.scrollIntoView({ behavior: "smooth", block: "start" });
            } catch (e) {
              alert(e.message);
            }
          },
        })
      );
      row.appendChild(left);
      row.appendChild(right);
      item.appendChild(row);
      listEl.appendChild(item);
    });
  }

  function updatePagination() {
    const nav = document.getElementById("historyPagination");
    const label = document.getElementById("historyPageLabel");
    const prev = document.getElementById("historyPrev");
    const next = document.getElementById("historyNext");
    const count = document.getElementById("historyCount");
    if (!nav) return;

    const pages = Math.max(1, Math.ceil(historyState.total / historyState.limit) || 1);
    nav.hidden = historyState.total === 0;
    if (label) {
      label.textContent =
        "Page " + historyState.page + " of " + pages + " · " + historyState.total + " total";
    }
    if (count) count.textContent = historyState.total + " scans";
    if (prev) prev.disabled = historyState.page <= 1;
    if (next) next.disabled = historyState.page >= pages;
  }

  async function refreshHistory() {
    const listEl = document.getElementById("scansList");
    if (!listEl) return;
    listEl.appendChild(el("p", { className: "text-muted mb-0", text: "Loading…" }));

    const q = new URLSearchParams({
      page: String(historyState.page),
      limit: String(historyState.limit),
    });
    if (historyState.scanType) q.set("type", historyState.scanType);
    if (historyState.q) q.set("q", historyState.q);
    if (historyState.status) q.set("status", historyState.status);

    try {
      const data = await api("/api/scans?" + q.toString());
      historyState.total = data.total || 0;
      historyState.page = data.page || historyState.page;
      renderHistoryItems(listEl, data.items || []);
      updatePagination();
    } catch (e) {
      clear(listEl);
      listEl.appendChild(el("div", { className: "alert alert-danger", text: e.message }));
    }
  }

  // Back-compat alias
  async function loadScans(listEl, scanType) {
    historyState.scanType = scanType || historyState.scanType;
    historyState.page = 1;
    await refreshHistory();
  }

  function initHistory(scanType) {
    historyState.scanType = scanType || "";
    historyState.page = 1;

    const form = document.getElementById("historyFilters");
    if (form) {
      const type = form.getAttribute("data-scan-type");
      if (type) historyState.scanType = type;

      form.addEventListener("submit", (e) => {
        e.preventDefault();
        historyState.q = (document.getElementById("historySearch").value || "").trim();
        historyState.status = document.getElementById("historyStatus").value || "";
        historyState.limit = parseInt(document.getElementById("historyLimit").value || "10", 10);
        historyState.page = 1;
        refreshHistory();
      });

      let debounce;
      const searchInput = document.getElementById("historySearch");
      if (searchInput) {
        searchInput.addEventListener("input", () => {
          clearTimeout(debounce);
          debounce = setTimeout(() => {
            historyState.q = (searchInput.value || "").trim();
            historyState.page = 1;
            refreshHistory();
          }, 350);
        });
      }

      const statusSel = document.getElementById("historyStatus");
      if (statusSel) {
        statusSel.addEventListener("change", () => {
          historyState.status = statusSel.value || "";
          historyState.page = 1;
          refreshHistory();
        });
      }

      const limitSel = document.getElementById("historyLimit");
      if (limitSel) {
        limitSel.addEventListener("change", () => {
          historyState.limit = parseInt(limitSel.value || "10", 10);
          historyState.page = 1;
          refreshHistory();
        });
      }
    }

    const prev = document.getElementById("historyPrev");
    const next = document.getElementById("historyNext");
    if (prev) {
      prev.addEventListener("click", () => {
        if (historyState.page > 1) {
          historyState.page--;
          refreshHistory();
        }
      });
    }
    if (next) {
      next.addEventListener("click", () => {
        const pages = Math.max(1, Math.ceil(historyState.total / historyState.limit) || 1);
        if (historyState.page < pages) {
          historyState.page++;
          refreshHistory();
        }
      });
    }

    refreshHistory();
  }

  async function submitScan(form, endpoint, scanType, extra) {
    const fd = new FormData(form);
    const data = Object.assign(
      {
        target: fd.get("target"),
        ports: fd.get("ports") || undefined,
        concurrency: parseInt(fd.get("concurrency") || "100", 10),
        host_concurrency: parseInt(fd.get("host_concurrency") || fd.get("concurrency") || "100", 10),
        port_concurrency: parseInt(fd.get("port_concurrency") || fd.get("concurrency") || "100", 10),
        timeout_ms: parseInt(fd.get("timeout_ms") || "1000", 10),
        grab_banner: fd.get("grab_banner") === "on",
        auth_service: fd.get("auth_service") || undefined,
        username: fd.get("username") || undefined,
        password: fd.get("password") || undefined,
        auth_port: fd.get("auth_port") ? parseInt(fd.get("auth_port"), 10) : undefined,
      },
      extra || {}
    );
    if (fd.get("source_scan_id")) {
      data.source_scan_id = parseInt(fd.get("source_scan_id"), 10);
    }
    if (fd.get("engagement_id")) {
      data.engagement_id = parseInt(fd.get("engagement_id"), 10);
    }

    const submitBtn = form.querySelector('button[type="submit"]');
    const prev = submitBtn.innerHTML;
    submitBtn.disabled = true;
    submitBtn.textContent = "Starting...";

    const results = document.getElementById("results");
    const content = document.getElementById("resultContent");
    results.style.display = "block";

    try {
      const started = await api(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data),
      });
      renderSummary(content, started);
      content.appendChild(
        el("div", { className: "progress mb-3" }, [
          el("div", {
            className: "progress-bar progress-bar-striped progress-bar-animated",
            id: "scanProgress",
            role: "progressbar",
            style: "width:0%",
            text: "0%",
          }),
        ])
      );
      const finalScan = await pollScan(started.scan_id, (scan) => {
        const bar = document.getElementById("scanProgress");
        if (bar) {
          bar.style.width = (scan.progress || 0) + "%";
          bar.textContent = (scan.progress || 0) + "%";
        }
      });
      renderScanDetail(content, finalScan);
      if (scanType) historyState.scanType = scanType;
      historyState.page = 1;
      await refreshHistory();
      results.scrollIntoView({ behavior: "smooth", block: "start" });
    } catch (e) {
      clear(content);
      content.appendChild(el("div", { className: "alert alert-danger", text: e.message }));
    } finally {
      submitBtn.disabled = false;
      submitBtn.innerHTML = prev;
    }
  }

  return {
    el,
    api,
    pollScan,
    loadScans,
    submitScan,
    renderScanDetail,
    initHistory,
    refreshHistory,
    fillEngagementFromQuery: function () {
      const params = new URLSearchParams(window.location.search);
      const id = params.get("engagement_id");
      const input = document.getElementById("engagement_id");
      if (id && input) input.value = id;
    },
  };
})();
