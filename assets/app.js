/* Penego shared UI helpers — uses textContent/DOM APIs to avoid XSS from banners */
window.Penego = (function () {
  function el(tag, attrs, children) {
    const node = document.createElement(tag);
    if (attrs) {
      Object.entries(attrs).forEach(([k, v]) => {
        if (k === "className") node.className = v;
        else if (k === "text") node.textContent = v;
        else if (k.startsWith("on") && typeof v === "function") node.addEventListener(k.slice(2).toLowerCase(), v);
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

  async function pollScan(scanId, onUpdate) {
    for (;;) {
      const scan = await api("/api/scans/" + scanId);
      if (onUpdate) onUpdate(scan);
      if (["done", "failed", "cancelled"].includes(scan.status)) return scan;
      await sleep(1500);
    }
  }

  function clear(node) {
    while (node.firstChild) node.removeChild(node.firstChild);
  }

  function renderSummary(container, result) {
    clear(container);
    const alert = el("div", { className: "alert alert-success" }, [
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
    ]);
    container.appendChild(alert);
  }

  function renderScanDetail(container, scan) {
    clear(container);
    const wrap = el("div");
    wrap.appendChild(
      el("div", { className: "mb-3" }, [
        el("h3", { text: "Scan #" + scan.id }),
        el("p", {
          text:
            "Target: " +
            scan.target +
            " | Type: " +
            (scan.scan_type || scan.ports_scanned) +
            " | Status: " +
            scan.status +
            " | Progress: " +
            (scan.progress || 0) +
            "%",
        }),
      ])
    );
    if (scan.error_message) {
      wrap.appendChild(el("div", { className: "alert alert-danger", text: scan.error_message }));
    }

    const alive = scan.true_targets || [];
    const dead = scan.false_targets || [];

    wrap.appendChild(el("h4", { text: "Alive Hosts (" + alive.length + ")" }));
    if (!alive.length) {
      wrap.appendChild(el("div", { className: "alert alert-info", text: "No alive hosts." }));
    }
    alive.forEach((host) => {
      const card = el("div", { className: "card mb-3 border-success" });
      card.appendChild(
        el("div", { className: "card-header bg-success text-white" }, [
          el("h5", { className: "mb-0", text: host.ip + (host.os ? " — " + host.os : "") }),
        ])
      );
      const body = el("div", { className: "card-body" });
      if (host.open_ports && host.open_ports.length) {
        const table = el("table", { className: "table table-sm table-bordered" });
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
        body.appendChild(el("h6", { text: "Findings" }));
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
      wrap.appendChild(card);
    });

    if (dead.length) {
      wrap.appendChild(el("h4", { text: "Dead Hosts (" + dead.length + ")" }));
      const ul = el("ul", { className: "list-group" });
      dead.forEach((h) => ul.appendChild(el("li", { className: "list-group-item", text: h.ip })));
      wrap.appendChild(ul);
    }

    const actions = el("div", { className: "mt-3 d-flex gap-2 flex-wrap" });
    actions.appendChild(
      el("a", {
        className: "btn btn-outline-secondary btn-sm",
        href: "/api/scans/" + scan.id + "/export",
        text: "Export JSON",
      })
    );
    actions.appendChild(
      el("a", {
        className: "btn btn-outline-secondary btn-sm",
        href: "/api/scans/" + scan.id + "/export.html",
        text: "Export HTML Report",
      })
    );
    actions.appendChild(
      el("button", {
        className: "btn btn-outline-danger btn-sm",
        text: "Delete",
        onclick: async () => {
          if (!confirm("Delete scan #" + scan.id + "?")) return;
          await api("/api/scans/" + scan.id, { method: "DELETE" });
          clear(container);
          container.appendChild(el("div", { className: "alert alert-warning", text: "Deleted." }));
        },
      })
    );
    wrap.appendChild(actions);
    container.appendChild(wrap);
  }

  async function loadScans(listEl, scanType) {
    clear(listEl);
    const q = new URLSearchParams({ page: "1", limit: "20" });
    if (scanType) q.set("type", scanType);
    const data = await api("/api/scans?" + q.toString());
    const items = data.items || [];
    if (!items.length) {
      listEl.appendChild(el("p", { className: "text-muted", text: "No scans found." }));
      return;
    }
    items.forEach((scan) => {
      const card = el("div", { className: "card mb-3" });
      const body = el("div", { className: "card-body d-flex justify-content-between align-items-start" });
      const left = el("div", {}, [
        el("h5", { className: "card-title", text: "#" + scan.id + " — " + scan.target }),
        el("p", {
          className: "card-text text-muted mb-1",
          text: new Date(scan.generated).toLocaleString() + " | " + scan.status + " | " + (scan.progress || 0) + "%",
        }),
        el("p", {
          className: "mb-0",
          text:
            "Type: " +
            (scan.scan_type || scan.ports_scanned) +
            " | Alive: " +
            (scan.true_targets || []).length +
            " | Dead: " +
            (scan.false_targets || []).length,
        }),
      ]);
      const btn = el("button", {
        className: "btn btn-outline-primary btn-sm",
        text: "View",
        onclick: async () => {
          const detail = await api("/api/scans/" + scan.id);
          const results = document.getElementById("results");
          const content = document.getElementById("resultContent");
          results.style.display = "block";
          renderScanDetail(content, detail);
        },
      });
      body.appendChild(left);
      body.appendChild(btn);
      card.appendChild(body);
      listEl.appendChild(card);
    });
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
      },
      extra || {}
    );
    if (fd.get("source_scan_id")) {
      data.source_scan_id = parseInt(fd.get("source_scan_id"), 10);
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
      content.appendChild(el("div", { className: "progress mb-3" }, [
        el("div", {
          className: "progress-bar",
          id: "scanProgress",
          role: "progressbar",
          style: "width:0%",
          text: "0%",
        }),
      ]));
      const finalScan = await pollScan(started.scan_id, (scan) => {
        const bar = document.getElementById("scanProgress");
        if (bar) {
          bar.style.width = (scan.progress || 0) + "%";
          bar.textContent = (scan.progress || 0) + "%";
        }
      });
      renderScanDetail(content, finalScan);
      const list = document.getElementById("scansList");
      if (list) await loadScans(list, scanType);
    } catch (e) {
      clear(content);
      content.appendChild(el("div", { className: "alert alert-danger", text: e.message }));
    } finally {
      submitBtn.disabled = false;
      submitBtn.innerHTML = prev;
    }
  }

  return { el, api, pollScan, loadScans, submitScan, renderScanDetail };
})();
