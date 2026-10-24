//! Local HTTP server port discovery, interactive URL selection prompt, in-page browser probe
//! script, and isolated-world `MutationObserver` snapshot relay script.

use super::{
    LocalUrlSuggestion, RUNTIME_SCAN_INTERACTION_DURATION_THRESHOLD_MS,
    RUNTIME_SCAN_MAX_COMPONENT_EVENTS, RUNTIME_SCAN_MAX_COMPONENTS_PER_COMMIT,
    RUNTIME_SCAN_MAX_INTERACTIONS, RUNTIME_SCAN_MAX_LOAF_ENTRIES,
    RUNTIME_SCAN_MAX_SCRIPTS_PER_LOAF, RUNTIME_SCAN_MAX_SNAPSHOT_BYTES,
    RUNTIME_SCAN_MAX_SNAPSHOT_PAYLOAD_BYTES, RUNTIME_SCAN_MAX_STRING_LENGTH,
    RUNTIME_SCAN_MIN_COMPONENT_DURATION_MS,
    analysis::{limit_string, sanitize_runtime_url},
};

fn probe_local_http_addr(addr: std::net::SocketAddr, port: u16) -> bool {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::time::Duration;

    let timeout = Duration::from_millis(300);
    let Ok(mut stream) = TcpStream::connect_timeout(&addr, timeout) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));
    let req = format!("HEAD / HTTP/1.1\r\nHost: localhost:{port}\r\nConnection: close\r\n\r\n");
    if stream.write_all(req.as_bytes()).is_err() {
        return false;
    }
    let mut buf = [0u8; 32];
    let Ok(n) = stream.read(&mut buf) else {
        return false;
    };
    n >= 5 && buf[..n].starts_with(b"HTTP/")
}

/// Probes local HTTP ports on `127.0.0.1` and `::1` and returns reachable `http://localhost:<port>` suggestions.
#[must_use]
pub fn detect_local_runtime_urls(ports: &[u16]) -> Vec<LocalUrlSuggestion> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    let handles: Vec<(u16, std::thread::JoinHandle<bool>)> = ports
        .iter()
        .copied()
        .map(|port| {
            let handle = std::thread::spawn(move || {
                let v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
                let v6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port);
                probe_local_http_addr(v4, port) || probe_local_http_addr(v6, port)
            });
            (port, handle)
        })
        .collect();

    let mut suggestions = Vec::new();
    for (port, handle) in handles {
        if handle.join().unwrap_or(false) {
            suggestions.push(LocalUrlSuggestion {
                port,
                url: format!("http://localhost:{port}"),
            });
        }
    }
    suggestions
}

/// Prompts the user to select a detected local server URL or enter a custom `http(s)` URL.
///
/// # Errors
/// Returns an error if reading from `input` or writing to `output` fails.
pub fn prompt_runtime_scan_url_with_io<R: std::io::BufRead, W: std::io::Write>(
    suggestions: &[LocalUrlSuggestion],
    input: &mut R,
    output: &mut W,
) -> Result<Option<String>, String> {
    writeln!(output, "dotore").map_err(|e| e.to_string())?;
    writeln!(output, "Choose an app to scan").map_err(|e| e.to_string())?;
    writeln!(output, "We'll open Chrome and scan one interaction.").map_err(|e| e.to_string())?;
    if suggestions.is_empty() {
        writeln!(output, "No local HTTP apps detected.").map_err(|e| e.to_string())?;
    } else {
        for (idx, suggestion) in suggestions.iter().enumerate() {
            let marker = if idx == 0 { "❯" } else { "›" };
            writeln!(
                output,
                "  {marker} [{}] {} detected",
                idx + 1,
                suggestion.url
            )
            .map_err(|e| e.to_string())?;
        }
    }
    writeln!(output, "  › Enter another URL").map_err(|e| e.to_string())?;
    write!(output, "App URL: ").map_err(|e| e.to_string())?;
    output.flush().map_err(|e| e.to_string())?;

    let mut custom_mode = suggestions.is_empty();
    let mut line = String::new();
    loop {
        line.clear();
        let bytes_read = input.read_line(&mut line).map_err(|e| e.to_string())?;
        if bytes_read == 0 {
            return Ok(None);
        }
        let raw = line.trim_end_matches(['\r', '\n']);
        if raw == "\x1b" || raw.eq_ignore_ascii_case("q") || raw.eq_ignore_ascii_case("esc") {
            return Ok(None);
        }
        let trimmed = raw.trim();
        if !custom_mode {
            if trimmed.is_empty() {
                if let Some(first) = suggestions.first() {
                    return Ok(Some(first.url.clone()));
                }
                custom_mode = true;
                continue;
            }
            if trimmed == "\x1b[B" || trimmed == "j" || trimmed.eq_ignore_ascii_case("other") {
                custom_mode = true;
                writeln!(output, "App URL").map_err(|e| e.to_string())?;
                output.flush().map_err(|e| e.to_string())?;
                continue;
            }
            if let Ok(index) = trimmed.parse::<usize>() {
                if index >= 1 && index <= suggestions.len() {
                    return Ok(Some(suggestions[index - 1].url.clone()));
                }
                if index == suggestions.len() + 1 {
                    custom_mode = true;
                    writeln!(output, "App URL").map_err(|e| e.to_string())?;
                    output.flush().map_err(|e| e.to_string())?;
                    continue;
                }
            }
        }

        if sanitize_runtime_url(trimmed).is_ok() {
            return Ok(Some(limit_string(trimmed)));
        }
        writeln!(
            output,
            "Enter an absolute URL starting with http:// or https://."
        )
        .map_err(|e| e.to_string())?;
        write!(output, "App URL: ").map_err(|e| e.to_string())?;
        output.flush().map_err(|e| e.to_string())?;
    }
}

pub(super) fn build_browser_probe_source(attribute_name: &str, token: &str) -> String {
    let attr_json = serde_json::to_string(attribute_name).unwrap_or_default();
    let token_json = serde_json::to_string(token).unwrap_or_default();
    format!(
        r#"(() => {{
  const MAX_LOAF_ENTRIES = {RUNTIME_SCAN_MAX_LOAF_ENTRIES};
  const MAX_SCRIPTS_PER_LOAF = {RUNTIME_SCAN_MAX_SCRIPTS_PER_LOAF};
  const MAX_COMPONENT_EVENTS = {RUNTIME_SCAN_MAX_COMPONENT_EVENTS};
  const MAX_COMPONENTS_PER_COMMIT = {RUNTIME_SCAN_MAX_COMPONENTS_PER_COMMIT};
  const MAX_INTERACTIONS = {RUNTIME_SCAN_MAX_INTERACTIONS};
  const MAX_STRING_LENGTH = {RUNTIME_SCAN_MAX_STRING_LENGTH};
  const MIN_COMPONENT_DURATION_MS = {RUNTIME_SCAN_MIN_COMPONENT_DURATION_MS};
  const INTERACTION_DURATION_THRESHOLD_MS = {RUNTIME_SCAN_INTERACTION_DURATION_THRESHOLD_MS};
  const SNAPSHOT_CATEGORY_BUDGET_BYTES = {};
  const SNAPSHOT_ATTRIBUTE_NAME = {attr_json};
  const SNAPSHOT_TOKEN = {token_json};
  const OVERLAY_COLOR_RGB = "115,97,230";
  const OVERLAY_FONT = "Menlo,Consolas,Monaco,Liberation Mono,Lucida Console,monospace";
  const OVERLAY_VISIBLE_FRAME_COUNT = 45;
  const OVERLAY_MAX_DEVICE_PIXEL_RATIO = 2;
  const OVERLAY_MAX_ACTIVE_OUTLINES = 200;
  const OVERLAY_MAX_HOST_ELEMENTS = 20;
  const OVERLAY_MAX_LABEL_LENGTH = 40;
  const OVERLAY_FONT_SIZE_PX = 11;
  const OVERLAY_LABEL_PADDING_PX = 2;
  const OVERLAY_LABEL_GAP_PX = 4;
  const OVERLAY_LINE_WIDTH_PX = 1;
  const OVERLAY_FILL_ALPHA = 0.1;
  const OVERLAY_Z_INDEX = 2147483646;

  const fiberIds = new WeakMap();
  let nextFiberId = 1;
  const getFiberId = (fiber) => {{
    if (!fiber || typeof fiber !== "object") return 0;
    const existing = fiberIds.get(fiber) || (fiber.alternate && fiberIds.get(fiber.alternate));
    if (existing) {{
      fiberIds.set(fiber, existing);
      return existing;
    }}
    const id = nextFiberId++;
    fiberIds.set(fiber, id);
    if (fiber.alternate) fiberIds.set(fiber.alternate, id);
    return id;
  }};

  const isCompositeFiber = (fiber) => {{
    if (!fiber || typeof fiber !== "object") return false;
    const tag = fiber.tag;
    return tag === 0 || tag === 1 || tag === 11 || tag === 14 || tag === 15;
  }};

  const isHostFiber = (fiber) => {{
    if (!fiber || typeof fiber !== "object") return false;
    return fiber.tag === 5 || typeof fiber.type === "string";
  }};

  const getDisplayName = (type) => {{
    if (!type) return null;
    if (typeof type === "string") return type;
    if (typeof type === "function") return type.displayName || type.name || null;
    if (typeof type === "object") {{
      return (
        type.displayName ||
        type.name ||
        (type.render && (type.render.displayName || type.render.name)) ||
        (type.type && getDisplayName(type.type)) ||
        null
      );
    }}
    return null;
  }};

  const getTimings = (fiber) => {{
    const actualDuration = typeof fiber?.actualDuration === "number" ? fiber.actualDuration : 0;
    let selfTime = actualDuration;
    let child = fiber?.child ?? null;
    while (child !== null) {{
      if (typeof child.actualDuration === "number") {{
        selfTime -= child.actualDuration;
      }}
      child = child.sibling ?? null;
    }}
    return {{ actualDuration, selfTime: Math.max(0, selfTime) }};
  }};

  const pendingOutlines = new Map();
  const activeOutlines = new Map();
  let canvas = null;
  let context = null;
  let flushAnimationFrameId = null;
  let drawAnimationFrameId = null;
  let previousScrollX = window.scrollX;
  let previousScrollY = window.scrollY;

  const getNearestHostElements = (fiber) => {{
    const elements = [];
    const fibersToVisit = [];
    if (isHostFiber(fiber)) {{
      fibersToVisit.push(fiber);
    }} else if (fiber.child !== null && fiber.child !== undefined) {{
      fibersToVisit.push(fiber.child);
    }}
    while (fibersToVisit.length > 0 && elements.length < OVERLAY_MAX_HOST_ELEMENTS) {{
      const currentFiber = fibersToVisit.pop();
      if (!currentFiber) break;
      if (isHostFiber(currentFiber)) {{
        if (currentFiber.stateNode instanceof Element) elements.push(currentFiber.stateNode);
      }} else if (currentFiber.child) {{
        fibersToVisit.push(currentFiber.child);
      }}
      if (currentFiber.sibling) fibersToVisit.push(currentFiber.sibling);
    }}
    return elements;
  }};

  const mergeRects = (rects) => {{
    const firstRect = rects[0];
    if (rects.length === 1) return firstRect;
    let minX = firstRect.x;
    let minY = firstRect.y;
    let maxX = firstRect.right;
    let maxY = firstRect.bottom;
    for (const rect of rects.slice(1)) {{
      minX = Math.min(minX, rect.x);
      minY = Math.min(minY, rect.y);
      maxX = Math.max(maxX, rect.right);
      maxY = Math.max(maxY, rect.bottom);
    }}
    return new DOMRect(minX, minY, maxX - minX, maxY - minY);
  }};

  const resizeCanvas = () => {{
    if (canvas === null || context === null) return;
    const dpr = Math.min(window.devicePixelRatio || 1, OVERLAY_MAX_DEVICE_PIXEL_RATIO);
    canvas.style.width = `${{window.innerWidth}}px`;
    canvas.style.height = `${{window.innerHeight}}px`;
    canvas.width = window.innerWidth * dpr;
    canvas.height = window.innerHeight * dpr;
    context.setTransform(dpr, 0, 0, dpr, 0, 0);
  }};

  const ensureCanvas = () => {{
    if (canvas !== null && context !== null) return true;
    const documentElement = document.documentElement;
    if (documentElement === null) return false;
    const host = document.createElement("div");
    host.setAttribute("data-dotore-runtime-scan-overlay", "");
    const shadowRoot = host.attachShadow({{ mode: "open" }});
    const nextCanvas = document.createElement("canvas");
    nextCanvas.setAttribute("aria-hidden", "true");
    nextCanvas.style.position = "fixed";
    nextCanvas.style.inset = "0";
    nextCanvas.style.pointerEvents = "none";
    nextCanvas.style.zIndex = String(OVERLAY_Z_INDEX);
    shadowRoot.appendChild(nextCanvas);
    documentElement.appendChild(host);
    const nextContext = nextCanvas.getContext("2d");
    if (nextContext === null) {{
      host.remove();
      return false;
    }}
    canvas = nextCanvas;
    context = nextContext;
    resizeCanvas();
    return true;
  }};

  const buildGroupLabel = (outlines) => {{
    const renderCountByName = new Map();
    for (const outline of outlines) {{
      renderCountByName.set(outline.name, (renderCountByName.get(outline.name) ?? 0) + outline.count);
    }}
    const label = [...renderCountByName.entries()]
      .sort((a, b) => b[1] - a[1])
      .map(([name, count]) => `${{name}} ×${{count}}`)
      .join(", ");
    return label.length > OVERLAY_MAX_LABEL_LENGTH
      ? `${{label.slice(0, OVERLAY_MAX_LABEL_LENGTH)}}…`
      : label;
  }};

  const groupOutlines = () => {{
    const outlinesByRect = new Map();
    for (const outline of activeOutlines.values()) {{
      const key = `${{Math.round(outline.x)}},${{Math.round(outline.y)}},${{Math.round(outline.width)}},${{Math.round(outline.height)}}`;
      const existing = outlinesByRect.get(key);
      if (existing === undefined) outlinesByRect.set(key, [outline]);
      else existing.push(outline);
    }}
    return [...outlinesByRect.values()].map((outlines) => {{
      const first = outlines[0];
      return {{
        outlines,
        x: first.x,
        y: first.y,
        width: first.width,
        height: first.height,
        alpha: Math.max(...outlines.map((o) => 1 - o.elapsedFrameCount / OVERLAY_VISIBLE_FRAME_COUNT)),
      }};
    }});
  }};

  const drawActiveOutlines = () => {{
    drawAnimationFrameId = null;
    if (canvas === null || context === null) return;
    context.clearRect(0, 0, window.innerWidth, window.innerHeight);
    context.font = `${{OVERLAY_FONT_SIZE_PX}}px ${{OVERLAY_FONT}}`;
    for (const group of groupOutlines()) {{
      const x = Math.round(group.x) + OVERLAY_LINE_WIDTH_PX / 2;
      const y = Math.round(group.y) + OVERLAY_LINE_WIDTH_PX / 2;
      const width = Math.round(group.width);
      const height = Math.round(group.height);
      context.strokeStyle = `rgba(${{OVERLAY_COLOR_RGB}},${{group.alpha}})`;
      context.lineWidth = OVERLAY_LINE_WIDTH_PX;
      context.strokeRect(x, y, width, height);
      context.fillStyle = `rgba(${{OVERLAY_COLOR_RGB}},${{group.alpha * OVERLAY_FILL_ALPHA}})`;
      context.fillRect(x, y, width, height);
      const label = buildGroupLabel(group.outlines);
      const labelWidth = context.measureText(label).width + OVERLAY_LABEL_PADDING_PX * 2;
      const labelHeight = OVERLAY_FONT_SIZE_PX + OVERLAY_LABEL_PADDING_PX * 2;
      const labelY = Math.max(0, y - labelHeight - OVERLAY_LABEL_GAP_PX);
      context.fillStyle = `rgba(${{OVERLAY_COLOR_RGB}},${{group.alpha}})`;
      context.fillRect(x, labelY, labelWidth, labelHeight);
      context.fillStyle = `rgba(255,255,255,${{group.alpha}})`;
      context.fillText(label, x + OVERLAY_LABEL_PADDING_PX, labelY + labelHeight - OVERLAY_LABEL_PADDING_PX);
    }}
    for (const outline of activeOutlines.values()) {{
      outline.elapsedFrameCount += 1;
      if (outline.elapsedFrameCount > OVERLAY_VISIBLE_FRAME_COUNT) activeOutlines.delete(outline.id);
    }}
    if (activeOutlines.size > 0) drawAnimationFrameId = requestAnimationFrame(drawActiveOutlines);
  }};

  const flushPendingOutlines = () => {{
    flushAnimationFrameId = null;
    if (!ensureCanvas()) return;
    const rectByElement = new Map();
    for (const pending of pendingOutlines.values()) {{
      for (const el of pending.elements) {{
        if (!el.isConnected || rectByElement.has(el)) continue;
        rectByElement.set(el, el.getBoundingClientRect());
      }}
    }}
    for (const pending of pendingOutlines.values()) {{
      const rects = pending.elements
        .map((el) => rectByElement.get(el))
        .filter((r) => r !== undefined && r.width > 0 && r.height > 0);
      if (rects.length === 0) continue;
      const rect = mergeRects(rects);
      const existing = activeOutlines.get(pending.id);
      if (existing === undefined) {{
        if (activeOutlines.size >= OVERLAY_MAX_ACTIVE_OUTLINES) continue;
        activeOutlines.set(pending.id, {{
          id: pending.id,
          name: pending.name,
          count: pending.count,
          x: rect.x,
          y: rect.y,
          width: rect.width,
          height: rect.height,
          elapsedFrameCount: 0,
        }});
      }} else {{
        existing.count += pending.count;
        existing.x = rect.x;
        existing.y = rect.y;
        existing.width = rect.width;
        existing.height = rect.height;
        existing.elapsedFrameCount = 0;
      }}
    }}
    pendingOutlines.clear();
    if (drawAnimationFrameId === null && activeOutlines.size > 0) {{
      drawAnimationFrameId = requestAnimationFrame(drawActiveOutlines);
    }}
  }};

  const recordOverlayRender = (fiber) => {{
    if (!isCompositeFiber(fiber)) return;
    const id = getFiberId(fiber);
    const existing = pendingOutlines.get(id);
    if (existing !== undefined) {{
      existing.count += 1;
      return;
    }}
    if (pendingOutlines.size >= OVERLAY_MAX_ACTIVE_OUTLINES) return;
    const displayName = getDisplayName(fiber.type);
    if (displayName === null) return;
    const name = displayName.slice(0, OVERLAY_MAX_LABEL_LENGTH);
    const elements = getNearestHostElements(fiber);
    if (elements.length === 0) return;
    pendingOutlines.set(id, {{ id, name, elements, count: 1 }});
    if (flushAnimationFrameId === null) {{
      flushAnimationFrameId = requestAnimationFrame(flushPendingOutlines);
    }}
  }};

  window.addEventListener("resize", resizeCanvas);
  window.addEventListener("scroll", () => {{
    const dx = window.scrollX - previousScrollX;
    const dy = window.scrollY - previousScrollY;
    previousScrollX = window.scrollX;
    previousScrollY = window.scrollY;
    for (const outline of activeOutlines.values()) {{
      outline.x -= dx;
      outline.y -= dy;
    }}
    if (drawAnimationFrameId === null && activeOutlines.size > 0) {{
      drawAnimationFrameId = requestAnimationFrame(drawActiveOutlines);
    }}
  }}, {{ passive: true }});

  const performanceObservers = [];
  const snapshotTextEncoder = new TextEncoder();
  const setSnapshotAttribute = Element.prototype.setAttribute;
  const removeSnapshotAttribute = Element.prototype.removeAttribute;
  const queueSnapshotAttributeRemoval = window.queueMicrotask.bind(window);
  const longAnimationFrames = {{ entries: [], nextIndex: 0, dropped: 0 }};
  const componentEvents = {{ entries: [], nextIndex: 0, dropped: 0 }};
  const interactions = {{ entries: [], nextIndex: 0, dropped: 0 }};
  let cumulativeLayoutShift = 0;
  let largestContentfulPaintMs = null;
  let droppedScriptTimings = 0;
  let reactDetected = false;
  let reactVersion = null;
  let reactBuildType = null;
  let nativeReactTracks = false;
  let bippyComponentTracks = false;
  let didCaptureCurrentPageState = false;

  const limitString = (v) => String(v ?? "").slice(0, MAX_STRING_LENGTH);
  const sanitizeUrl = (rawUrl) => {{
    try {{
      const parsed = new URL(rawUrl, window.location.href);
      parsed.username = "";
      parsed.password = "";
      parsed.search = "";
      parsed.hash = "";
      return limitString(parsed.href);
    }} catch {{
      return "";
    }}
  }};

  const pushBoundedEntry = (bounded, limit, entry) => {{
    if (bounded.entries.length < limit) bounded.entries.push(entry);
    else {{
      bounded.entries[bounded.nextIndex] = entry;
      bounded.nextIndex = (bounded.nextIndex + 1) % limit;
      bounded.dropped += 1;
    }}
  }};

  const readBoundedEntries = (bounded) => {{
    if (bounded.nextIndex === 0) return [...bounded.entries];
    return [...bounded.entries.slice(bounded.nextIndex), ...bounded.entries.slice(0, bounded.nextIndex)];
  }};

  const takeLatestEntriesWithinByteBudget = (entries) => {{
    let minCount = 0;
    let maxCount = entries.length;
    while (minCount < maxCount) {{
      const candidateCount = Math.ceil((minCount + maxCount) / 2);
      const candidateEntries = entries.slice(entries.length - candidateCount);
      const bytes = snapshotTextEncoder.encode(JSON.stringify(candidateEntries)).byteLength;
      if (bytes <= SNAPSHOT_CATEGORY_BUDGET_BYTES) minCount = candidateCount;
      else maxCount = candidateCount - 1;
    }}
    return {{
      entries: entries.slice(entries.length - minCount),
      dropped: entries.length - minCount,
    }};
  }};

  const observe = (entryType, listener, durationThreshold) => {{
    try {{
      const observer = new PerformanceObserver((list) => {{
        for (const entry of list.getEntries()) listener(entry);
      }});
      observer.observe({{ type: entryType, buffered: true, durationThreshold }});
      performanceObservers.push({{ observer, listener }});
      return true;
    }} catch {{
      return false;
    }}
  }};

  const loafSupported = observe("long-animation-frame", (entry) => {{
    const scripts = entry.scripts ?? [];
    droppedScriptTimings += Math.max(0, scripts.length - MAX_SCRIPTS_PER_LOAF);
    pushBoundedEntry(longAnimationFrames, MAX_LOAF_ENTRIES, {{
      startTime: entry.startTime,
      durationMs: entry.duration,
      blockingDurationMs: entry.blockingDuration ?? 0,
      renderStart: entry.renderStart ?? 0,
      styleAndLayoutStart: entry.styleAndLayoutStart ?? 0,
      firstUiEventTimestamp: entry.firstUIEventTimestamp ?? 0,
      scripts: scripts.slice(0, MAX_SCRIPTS_PER_LOAF).map((s) => ({{
        invoker: limitString(s.invoker ?? ""),
        invokerType: limitString(s.invokerType ?? ""),
        sourceUrl: sanitizeUrl(s.sourceURL ?? ""),
        sourceFunctionName: limitString(s.sourceFunctionName ?? ""),
        sourceCharPosition: s.sourceCharPosition ?? 0,
        executionStart: s.executionStart ?? 0,
        durationMs: s.duration ?? 0,
        forcedStyleAndLayoutDurationMs: s.forcedStyleAndLayoutDuration ?? 0,
        pauseDurationMs: s.pauseDuration ?? 0,
      }})),
    }});
  }});

  observe("event", (entry) => {{
    const interactionId = entry.interactionId ?? 0;
    if (interactionId === 0) return;
    pushBoundedEntry(interactions, MAX_INTERACTIONS, {{
      name: limitString(entry.name),
      startTime: entry.startTime,
      durationMs: entry.duration,
      processingStart: entry.processingStart ?? entry.startTime,
      processingEnd: entry.processingEnd ?? entry.startTime,
      interactionId,
      targetTag: entry.target == null ? null : limitString(entry.target.tagName),
    }});
  }}, INTERACTION_DURATION_THRESHOLD_MS);

  observe("layout-shift", (entry) => {{
    if (entry.hadRecentInput === true) return;
    cumulativeLayoutShift += entry.value ?? 0;
  }});

  observe("largest-contentful-paint", (entry) => {{
    largestContentfulPaintMs = Math.max(largestContentfulPaintMs ?? 0, entry.startTime);
  }});

  observe("measure", (entry) => {{
    const devtools = entry.detail?.devtools;
    if (!devtools?.track?.includes("Components")) return;
    if (devtools.dotoreSource === "bippy") return;
    nativeReactTracks = true;
    pushBoundedEntry(componentEvents, MAX_COMPONENT_EVENTS, {{
      name: limitString(String(entry.name ?? "").replace(/^\u200B/, "")),
      startTime: entry.startTime,
      durationMs: entry.duration,
      depth: 0,
      source: "native",
    }});
  }});

  const versionHasNativeTracks = (version) => {{
    const [maj, min] = String(version).split(".");
    const major = Number.parseInt(maj ?? "", 10);
    const minor = Number.parseInt(min ?? "", 10);
    return major > 19 || (major === 19 && minor >= 2);
  }};

  const attachRenderer = (renderer) => {{
    if (!renderer) return;
    reactDetected = true;
    reactVersion = typeof renderer.version === "string" ? limitString(renderer.version) : null;
    reactBuildType = renderer.bundleType === 0 ? "production" : "development";
  }};

  const traverseRenderedFibers = (root, cb) => {{
    const current = root?.current;
    if (!current) return;
    const stack = [current];
    while (stack.length > 0) {{
      const fiber = stack.pop();
      if (!fiber) continue;
      cb(fiber);
      if (fiber.sibling) stack.push(fiber.sibling);
      if (fiber.child) stack.push(fiber.child);
    }}
  }};

  const onCommit = (_rendererId, root) => {{
    const shouldRecordFallback = reactVersion === null || !versionHasNativeTracks(reactVersion);
    let count = 0;
    traverseRenderedFibers(root, (fiber) => {{
      if (!isCompositeFiber(fiber)) return;
      if (count >= MAX_COMPONENTS_PER_COMMIT) return;
      recordOverlayRender(fiber);
      if (!shouldRecordFallback) {{
        count += 1;
        return;
      }}
      const {{ selfTime }} = getTimings(fiber);
      if (selfTime >= MIN_COMPONENT_DURATION_MS) {{
        let depth = 0;
        let p = fiber.return;
        while (p) {{ depth += 1; p = p.return; }}
        const name = limitString(getDisplayName(fiber.type) ?? "Anonymous");
        const startTime = fiber.actualStartTime ?? performance.now() - selfTime;
        pushBoundedEntry(componentEvents, MAX_COMPONENT_EVENTS, {{
          name,
          startTime,
          durationMs: selfTime,
          depth,
          source: "bippy",
        }});
        bippyComponentTracks = true;
      }}
      count += 1;
    }});
  }};

  const ensureHook = () => {{
    let hook = window.__REACT_DEVTOOLS_GLOBAL_HOOK__;
    if (!hook) {{
      const renderers = new Map();
      let nextId = 1;
      hook = {{
        renderers,
        supportsFiber: true,
        inject: (renderer) => {{
          const id = nextId++;
          renderers.set(id, renderer);
          attachRenderer(renderer);
          return id;
        }},
        onCommitFiberRoot: (id, root) => onCommit(id, root),
        onCommitFiberUnmount: () => {{}},
      }};
      try {{
        Object.defineProperty(window, "__REACT_DEVTOOLS_GLOBAL_HOOK__", {{
          configurable: true,
          enumerable: false,
          get: () => hook,
        }});
      }} catch {{
        window.__REACT_DEVTOOLS_GLOBAL_HOOK__ = hook;
      }}
    }} else {{
      if (hook.renderers && typeof hook.renderers.values === "function") {{
        for (const r of hook.renderers.values()) attachRenderer(r);
      }}
      const origInject = hook.inject;
      if (typeof origInject === "function") {{
        hook.inject = function(renderer, ...rest) {{
          attachRenderer(renderer);
          return origInject.call(this, renderer, ...rest);
        }};
      }}
      const origCommit = hook.onCommitFiberRoot;
      hook.onCommitFiberRoot = function(id, root, ...rest) {{
        try {{ onCommit(id, root); }} catch {{}}
        if (typeof origCommit === "function") return origCommit.call(this, id, root, ...rest);
      }};
    }}
  }};
  ensureHook();

  const snapshot = () => {{
    for (const {{ observer, listener }} of performanceObservers) {{
      for (const entry of observer.takeRecords()) listener(entry);
    }}
    const budgetedLoaf = takeLatestEntriesWithinByteBudget(readBoundedEntries(longAnimationFrames));
    const budgetedComp = takeLatestEntriesWithinByteBudget(readBoundedEntries(componentEvents));
    const budgetedInter = takeLatestEntriesWithinByteBudget(readBoundedEntries(interactions));
    return {{
      timeOrigin: performance.timeOrigin,
      finalUrl: sanitizeUrl(window.location.href),
      support: {{
        reactDetected,
        reactVersion,
        reactBuildType,
        nativeReactTracks,
        bippyComponentTracks,
        loaf: loafSupported,
      }},
      longAnimationFrames: budgetedLoaf.entries,
      componentEvents: budgetedComp.entries,
      interactions: budgetedInter.entries,
      cumulativeLayoutShift,
      largestContentfulPaintMs,
      droppedLongAnimationFrames: longAnimationFrames.dropped + budgetedLoaf.dropped,
      droppedScriptTimings,
      droppedComponentEvents: componentEvents.dropped + budgetedComp.dropped,
      droppedInteractions: interactions.dropped + budgetedInter.dropped,
    }};
  }};

  window.__DOTORE_RUNTIME_SCAN__ = {{ snapshot }};

  const captureSnapshot = (snap) => {{
    const el = document.documentElement;
    if (!el) return;
    try {{
      setSnapshotAttribute.call(el, SNAPSHOT_ATTRIBUTE_NAME, JSON.stringify({{ token: SNAPSHOT_TOKEN, snapshot: snap }}));
      queueSnapshotAttributeRemoval(() => {{
        try {{ removeSnapshotAttribute.call(el, SNAPSHOT_ATTRIBUTE_NAME); }} catch {{}}
      }});
    }} catch {{}}
  }};

  const captureNavigationSnapshot = () => {{
    if (window !== window.top || didCaptureCurrentPageState) return;
    didCaptureCurrentPageState = true;
    captureSnapshot(snapshot());
  }};

  document.addEventListener("visibilitychange", () => {{
    if (document.visibilityState === "hidden") captureNavigationSnapshot();
    else didCaptureCurrentPageState = false;
  }});
  window.addEventListener("pageshow", () => {{ didCaptureCurrentPageState = false; }});
  window.addEventListener("beforeunload", captureNavigationSnapshot);
  window.addEventListener("pagehide", captureNavigationSnapshot);
}})();"#,
        RUNTIME_SCAN_MAX_SNAPSHOT_BYTES / 3
    )
}

pub(super) fn build_snapshot_relay_source(attribute_name: &str, binding_name: &str) -> String {
    let attr_json = serde_json::to_string(attribute_name).unwrap_or_default();
    let binding_json = serde_json::to_string(binding_name).unwrap_or_default();
    format!(
        r#"(() => {{
  let didRelaySnapshot = false;
  const getSnapshotAttribute = Element.prototype.getAttribute;
  const removeSnapshotAttribute = Element.prototype.removeAttribute;
  const relaySnapshot = () => {{
    const documentElement = document.documentElement;
    if (documentElement === null) return;
    const payload = getSnapshotAttribute.call(documentElement, {attr_json});
    removeSnapshotAttribute.call(documentElement, {attr_json});
    if (
      didRelaySnapshot ||
      typeof payload !== "string" ||
      payload.length > {RUNTIME_SCAN_MAX_SNAPSHOT_PAYLOAD_BYTES}
    ) return;
    if (new TextEncoder().encode(payload).byteLength > {RUNTIME_SCAN_MAX_SNAPSHOT_PAYLOAD_BYTES}) return;
    const captureBinding = Reflect.get(globalThis, {binding_json});
    if (typeof captureBinding !== "function") return;
    didRelaySnapshot = true;
    captureBinding(payload);
  }};
  new MutationObserver(relaySnapshot).observe(document, {{
    attributes: true,
    subtree: true,
    attributeFilter: [{attr_json}],
  }});
}})();"#
    )
}
