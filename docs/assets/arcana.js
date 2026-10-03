/* Arcana website - no dependencies.
 * - reads the latest release and the star count from the GitHub API (falls back to the values below);
 * - shows the star reminder when a download starts;
 * - byte inspector: reads the first 32 KB of a file IN THE BROWSER (nothing is uploaded, nothing is extracted) and
 *   applies a JavaScript copy of Arcana's detection rules (see identify(): keep it in sync with ArchiveDetector);
 * - table of contents highlighting and copy buttons.
 */
(function () {
  "use strict";

  var REPO = "RealBurst/arcana";
  var FALLBACK = { version: "1.0.2", date: "" }; // used when the GitHub API cannot be reached: update it at each release
  var REPO_URL = "https://github.com/" + REPO;

  /* ------------------------------------------------------------------ release and stars */

  function assetUrl(version, name) {
    return REPO_URL + "/releases/download/v" + version + "/" + name;
  }

  function setVersion(version, date) {
    document.querySelectorAll("[data-version]").forEach(function (el) { el.textContent = version; });
    document.querySelectorAll("[data-jar]").forEach(function (el) { el.textContent = "Arcana-v" + version + ".jar"; });
    document.querySelectorAll("a.js-download").forEach(function (a) {
      var name = a.getAttribute("data-file").replace("{v}", version);
      a.href = assetUrl(version, name);
      a.setAttribute("data-name", name);
    });
    if (date) document.querySelectorAll("[data-release-date]").forEach(function (el) { el.textContent = date; });
  }

  function formatSize(n) {
    if (n < 1024) return n + " B";
    if (n < 1048576) return (n / 1024).toFixed(0) + " KB";
    return (n / 1048576).toFixed(2) + " MB";
  }

  function describeAsset(name) {
    if (/^Arcana-v/.test(name)) return "Command-line tool and Java library";
    var p = pluginByJar(name);
    if (p) return "Plugin: " + (p.summary || p.name) + " (" + p.license + ")";
    if (name === "SHA256SUMS.txt") return "SHA-256 checksums of the JAR files";
    if (/^arcana-plugin-/.test(name)) return "Plugin";
    return "";
  }

  function fillAssets(assets) {
    var body = document.getElementById("release-assets");
    if (!body || !assets || !assets.length) return;
    body.innerHTML = "";
    function rank(n) { return /^Arcana-v/.test(n) ? 0 : /^arcana-plugin-/.test(n) ? 1 : 2; }
    assets = assets.slice().sort(function (x, y) { return rank(x.name) - rank(y.name) || (x.name < y.name ? -1 : 1); });
    assets.forEach(function (a) {
      var tr = document.createElement("tr");
      var td1 = document.createElement("td");
      var link = document.createElement("a");
      link.href = a.browser_download_url;
      link.textContent = a.name;
      if (/\.jar$/.test(a.name)) { link.className = "js-download"; link.setAttribute("data-name", a.name); link.setAttribute("data-file", a.name); }
      td1.appendChild(link);
      var td2 = document.createElement("td"); td2.textContent = describeAsset(a.name);
      var td3 = document.createElement("td"); td3.textContent = formatSize(a.size);
      tr.appendChild(td1); tr.appendChild(td2); tr.appendChild(td3);
      body.appendChild(tr);
    });
    bindDownloads(body);
  }

  /* ------------------------------------------------------------------ known plugins (docs/plugins.json) */

  var PLUGINS = [];

  function pluginByJar(name) {
    for (var i = 0; i < PLUGINS.length; i++) if (PLUGINS[i].jar === name) return PLUGINS[i];
    return null;
  }

  function cell(tr, text) {
    var td = document.createElement("td");
    td.textContent = text || "";
    tr.appendChild(td);
    return td;
  }

  // "Known plugins" table, and the plugin rows of the download table (used when the GitHub API cannot be reached)
  function fillPlugins() {
    var body = document.getElementById("known-plugins-list");
    if (body && PLUGINS.length) {
      body.innerHTML = "";
      PLUGINS.forEach(function (p) {
        var tr = document.createElement("tr");
        var td = cell(tr, "");
        var a = document.createElement("a");
        a.href = p.url;
        a.textContent = p.name;
        td.appendChild(a);
        cell(tr, p.description);
        cell(tr, p.files);
        cell(tr, p.capabilities);
        cell(tr, p.author);
        cell(tr, p.license);
        body.appendChild(tr);
      });
    }
    var sums = document.getElementById("sums-row");
    if (sums) {
      PLUGINS.forEach(function (p) {
        if (!p.jar) return;
        var tr = document.createElement("tr");
        var td = cell(tr, "");
        var a = document.createElement("a");
        a.className = "js-download";
        a.setAttribute("data-file", p.jar);
        a.href = REPO_URL + "/releases/latest";
        a.textContent = p.jar;
        td.appendChild(a);
        cell(tr, describeAsset(p.jar));
        cell(tr, "");
        sums.parentNode.insertBefore(tr, sums);
      });
    }
  }

  function loadPlugins() {
    if (!window.fetch) return Promise.resolve();
    return fetch("plugins.json", { cache: "no-cache" }).then(function (r) { return r.ok ? r.json() : null; }).then(function (data) {
      if (data && data.plugins && data.plugins.length) {
        PLUGINS = data.plugins.slice().sort(function (x, y) { return x.name < y.name ? -1 : x.name > y.name ? 1 : 0; });
        fillPlugins();
      }
    }).catch(function () { /* file:// or offline: the table keeps its link to plugins.json */ });
  }

  function loadRelease() {
    setVersion(FALLBACK.version, FALLBACK.date);
    if (!window.fetch) return;
    fetch("https://api.github.com/repos/" + REPO + "/releases/latest").then(function (r) { return r.ok ? r.json() : null; }).then(function (rel) {
      if (!rel || !rel.tag_name) return;
      var version = rel.tag_name.replace(/^v/, "");
      var date = rel.published_at ? new Date(rel.published_at).toLocaleDateString("en-GB", { year: "numeric", month: "long", day: "numeric" }) : "";
      setVersion(version, date);
      fillAssets(rel.assets);
    }).catch(function () { /* offline or rate limited: keep the fallback */ });
    fetch("https://api.github.com/repos/" + REPO).then(function (r) { return r.ok ? r.json() : null; }).then(function (repo) {
      if (!repo || typeof repo.stargazers_count !== "number") return;
      document.querySelectorAll("[data-stars]").forEach(function (el) { el.textContent = repo.stargazers_count.toLocaleString("en-US"); });
    }).catch(function () {});
  }

  /* ------------------------------------------------------------------ download and star reminder */

  var dialog = document.getElementById("star-dialog");

  function bindDownloads(root) {
    (root || document).querySelectorAll("a.js-download").forEach(function (a) {
      if (a.dataset.bound) return;
      a.dataset.bound = "1";
      a.addEventListener("click", function () {
        // the link itself starts the download; the reminder opens next to it
        if (!dialog || typeof dialog.showModal !== "function") return;
        var name = a.getAttribute("data-name") || a.textContent;
        dialog.querySelector(".dl-file").textContent = name;
        dialog.querySelector(".dl-retry").href = a.href;
        window.setTimeout(function () { if (!dialog.open) dialog.showModal(); }, 250);
      });
    });
  }

  if (dialog) {
    dialog.addEventListener("click", function (e) { if (e.target === dialog) dialog.close(); });
    dialog.querySelectorAll("[data-close]").forEach(function (b) { b.addEventListener("click", function () { dialog.close(); }); });
  }

  /* ------------------------------------------------------------------ byte inspector */

  function bytes(s) { return s.split(" ").map(function (h) { return parseInt(h, 16); }); }
  function ascii(s) { var a = []; for (var i = 0; i < s.length; i++) a.push(s.charCodeAt(i)); return a; }
  function at(b, off, sig) { if (b.length < off + sig.length) return false; for (var i = 0; i < sig.length; i++) if (b[off + i] !== sig[i]) return false; return true; }
  function u16(b, p) { return b[p] | (b[p + 1] << 8); }
  function u32(b, p) { return (b[p] | (b[p + 1] << 8) | (b[p + 2] << 16) | (b[p + 3] << 24)) >>> 0; }
  function str(b, p, n) { var s = ""; for (var i = p; i < p + n && i < b.length; i++) s += String.fromCharCode(b[i]); return s; }
  function ext(name) { var n = (name || "").toLowerCase(); var m = n.match(/(\.tar\.[a-z0-9]+|\.[a-z0-9]+)$/); return m ? m[1] : ""; }
  function findAscii(b, text, limit) {
    var t = ascii(text), end = Math.min(b.length, limit) - t.length;
    for (var i = 0; i <= end; i++) if (at(b, i, t)) return i;
    return -1;
  }

  var ZIP_DOCS = [
    [/^\.(docx|docm|dotx|dotm)$/, "Word document (Office Open XML)"],
    [/^\.(xlsx|xlsm|xltx|xltm)$/, "Excel workbook (Office Open XML)"],
    [/^\.(pptx|pptm|potx|potm)$/, "PowerPoint presentation (Office Open XML)"],
    [/^\.(odt|ods|odp|odg|odf|odb)$/, "OpenDocument file"],
    [/^\.epub$/, "EPUB book"],
    [/^\.(jar|war|ear|aar)$/, "Java archive"],
    [/^\.(apk|ipa)$/, "Mobile application package"],
    [/^\.(whl|egg)$/, "Python package"],
    [/^\.(xpi|crx|vsix|nupkg)$/, "Extension or package"],
    [/^\.kmz$/, "Google Earth file"],
    [/^\.cbz$/, "Comic book"],
    [/^\.(xps|oxps)$/, "XPS document"],
    [/^\.(fcstd|3mf)$/, "3D model"]
  ];

  function zipKind(b, name) {
    var e = ext(name), i;
    // the first local file headers are in the bytes read: look for the names that identify the container
    if (findAscii(b, "[Content_Types].xml", b.length) >= 0) {
      for (i = 0; i < 3; i++) if (ZIP_DOCS[i][0].test(e)) return [ZIP_DOCS[i][1], "a ZIP container"];
      return ["Office Open XML document", "a ZIP container"];
    }
    if (findAscii(b, "application/epub+zip", 200) >= 0) return ["EPUB book", "a ZIP container"];
    if (findAscii(b, "application/vnd.oasis.opendocument", 200) >= 0) return ["OpenDocument file", "a ZIP container"];
    if (findAscii(b, "AndroidManifest.xml", b.length) >= 0) return ["Android package (APK)", "a ZIP container"];
    if (findAscii(b, "META-INF/MANIFEST.MF", b.length) >= 0) return ["Java archive (JAR)", "a ZIP container"];
    for (i = 0; i < ZIP_DOCS.length; i++) if (ZIP_DOCS[i][0].test(e)) return [ZIP_DOCS[i][1], "a ZIP container"];
    return ["ZIP archive", null];
  }

  // KEEP IN SYNC WITH THE JAVA CODE: this is a JavaScript copy of the detection rules, not Arcana itself.
  // Order and signatures follow be.stef.arcana.detector.ArchiveDetector.detectByContent(), then a few
  // identification-only types of be.stef.arcana.analyze. When a signature is added or changed there, update it here
  // (and in the "Signature" column of the formats table in index.html).
  function identify(b, name) {
    var e = ext(name), m;
    if (at(b, 0, bytes("52 61 72 21 1A 07 01 00"))) return { off: 0, len: 8, title: "RAR 5 archive", how: "x", fmt: "rar" };
    if (at(b, 0, bytes("52 61 72 21 1A 07 00"))) return { off: 0, len: 7, title: "RAR 4 archive", how: "x", fmt: "rar" };
    if (at(b, 0, bytes("50 4B 03 04"))) { m = zipKind(b, name); return { off: 0, len: 4, title: m[0], inside: m[1], how: "x", fmt: "zip" }; }
    if (at(b, 0, bytes("1F 8B"))) {
      if (e === ".dia") return { off: 0, len: 2, title: "Dia diagram", inside: "GZIP-compressed XML", how: "x", fmt: "gz" };
      if (e === ".svgz") return { off: 0, len: 2, title: "Compressed SVG image", inside: "GZIP-compressed XML", how: "x", fmt: "gz" };
      if (e === ".tar.gz" || e === ".tgz") return { off: 0, len: 2, title: "TAR archive compressed with GZIP", how: "x", fmt: "tar.gz" };
      return { off: 0, len: 2, title: "GZIP stream", how: "x", fmt: "gz" };
    }
    if (at(b, 0, bytes("42 5A 68"))) return { off: 0, len: 3, title: e === ".tar.bz2" || e === ".tbz2" ? "TAR archive compressed with BZIP2" : "BZIP2 stream", how: "x" };
    if (at(b, 0, bytes("37 7A BC AF 27 1C"))) return { off: 0, len: 6, title: "7-Zip archive", how: "x", fmt: "7z" };
    if (at(b, 0, bytes("FD 2F B5 28"))) return { off: 0, len: 4, title: e === ".tar.zst" ? "TAR archive compressed with Zstandard" : "Zstandard stream", how: "x" };
    if (at(b, 0, bytes("FD 37 7A 58 5A 00"))) return { off: 0, len: 6, title: e === ".tar.xz" || e === ".txz" ? "TAR archive compressed with XZ" : "XZ stream", how: "x" };
    if (at(b, 0, bytes("04 22 4D 18"))) return { off: 0, len: 4, title: e === ".tar.lz4" ? "TAR archive compressed with LZ4" : "LZ4 frame", how: "x" };
    if (at(b, 0, bytes("FF 06 00 00 73 4E 61 50 70 59"))) return { off: 0, len: 10, title: "Snappy stream", how: "x" };
    if (at(b, 0, ascii("07070"))) return { off: 0, len: 6, title: "CPIO archive", how: "x" };
    if (at(b, 0, bytes("1F 9D"))) return { off: 0, len: 2, title: "Unix compress (.Z) stream", how: "x" };
    if (at(b, 0, ascii("!<arch>\n"))) return { off: 0, len: 8, title: e === ".deb" ? "Debian package (AR archive)" : "AR archive", how: "x" };
    if (at(b, 0, bytes("ED AB EE DB"))) return { off: 0, len: 4, title: "RPM package", how: "x" };
    if (at(b, 0, ascii("xar!"))) return { off: 0, len: 4, title: "XAR archive", how: "x" };
    if (at(b, 0, ascii("MSCF"))) return { off: 0, len: 4, title: "Microsoft Cabinet", how: "x" };
    if (b.length > 5 && b[2] === 0x2D && b[3] === 0x6C && b[4] === 0x68) return { off: 2, len: 3, title: "LHA / LZH archive", how: "x" };
    if (at(b, 257, ascii("ustar"))) return { off: 257, len: 5, title: "TAR archive", how: "x" };
    if (at(b, 0, ascii("MSWIM"))) return { off: 0, len: 5, title: "Windows Imaging Format (WIM)", how: "x" };
    if (at(b, 0, ascii("ITSF"))) return { off: 0, len: 4, title: "Compiled HTML Help (CHM)", how: "x" };
    if (at(b, 0, bytes("53 5A 44 44 88 F0 27 33"))) return { off: 0, len: 8, title: "File packed by MS COMPRESS.EXE (SZDD)", how: "x" };
    if (at(b, 0, bytes("60 EA")) && b.length > 10 && b[10] === 2) return { off: 0, len: 2, title: "ARJ archive", how: "x" };
    if (at(b, 0, bytes("D0 CF 11 E0 A1 B1 1A E1"))) return { off: 0, len: 8, title: e === ".msi" ? "Windows Installer package" : "OLE compound file (legacy Office document, MSI, Outlook message...)", how: "x" };
    if (at(b, 0, ascii("hsqs"))) return { off: 0, len: 4, title: "SquashFS file system", how: "x" };
    for (var s = 16; s < 32; s++) {
      // UDF volume recognition sequence: a "NSR02" or "NSR03" descriptor, also on UDF + ISO 9660 discs
      var o = s * 2048 + 1;
      if (at(b, o, ascii("NSR02")) || at(b, o, ascii("NSR03"))) return { off: o, len: 5, title: "UDF disc image", how: "x" };
    }
    if (at(b, 0x8001, ascii("CD001"))) return { off: 0x8001, len: 5, title: "ISO 9660 disc image", how: "x" };
    if (at(b, 0, ascii("MZ"))) {
      var upx = findAscii(b, "UPX0", 4096);
      if (upx >= 0) return { off: 0, len: 2, title: "Windows executable compressed with UPX", how: "upx" };
      return { off: 0, len: 2, title: "Windows or DOS executable", how: "exe" };
    }
    if (at(b, 0, bytes("7F 45 4C 46"))) {
      if (findAscii(b, "UPX!", 4096) >= 0) return { off: 0, len: 4, title: "Linux executable (ELF) compressed with UPX", how: "upx" };
      return { off: 0, len: 4, title: "Linux executable (ELF)", how: "exe" };
    }
    if (at(b, 0, bytes("89 50 4E 47 0D 0A 1A 0A"))) return { off: 0, len: 8, title: "PNG image", how: "i" };
    if (at(b, 0, bytes("FF D8 FF"))) return { off: 0, len: 3, title: "JPEG image", how: "i" };
    if (at(b, 0, ascii("GIF8"))) return { off: 0, len: 4, title: "GIF image", how: "i" };
    if (at(b, 0, ascii("RIFF")) && at(b, 8, ascii("WEBP"))) return { off: 0, len: 4, title: "WebP image", how: "i" };
    if (at(b, 0, ascii("%PDF"))) return { off: 0, len: 4, title: "PDF document", how: "i" };
    if (at(b, 0, ascii("SQLite format 3"))) return { off: 0, len: 15, title: "SQLite database", how: "i" };
    if (at(b, 0, bytes("CA FE BA BE"))) return { off: 0, len: 4, title: "Java class file", how: "i" };
    if (at(b, 0, bytes("00 61 73 6D"))) return { off: 0, len: 4, title: "WebAssembly module", how: "i" };
    if (at(b, 4, ascii("ftyp"))) return { off: 4, len: 4, title: "MP4 / ISO media file", how: "i" };
    if (at(b, 0, ascii("fLaC"))) return { off: 0, len: 4, title: "FLAC audio", how: "i" };
    if (at(b, 0, ascii("OggS"))) return { off: 0, len: 4, title: "Ogg container", how: "i" };
    if (at(b, 0, ascii("ID3"))) return { off: 0, len: 3, title: "MP3 audio", how: "i" };
    if (b.length && b[0] === 0x5D && (e === ".lzma" || e === ".tar.lzma")) return { off: 0, len: 1, title: "LZMA stream (recognized with its extension)", how: "x" };
    if (e === ".br" || e === ".tar.br") return { off: -1, len: 0, title: "Brotli stream (Brotli has no signature: Arcana relies on the extension)", how: "x" };
    return null;
  }

  var ARCHIVE_EXT = { ".zip": "zip", ".7z": "7z", ".rar": "rar", ".gz": "gz", ".tar.gz": "tar.gz", ".tgz": "tar.gz" };

  function claimedFormat(name) {
    return ARCHIVE_EXT[ext(name)] || "";
  }

  function explain(r, name) {
    var file = name || "file";
    var cmd = "arcana x " + file;
    var p = document.createElement("div");
    function para(html) { var x = document.createElement("p"); x.innerHTML = html; p.appendChild(x); }
    function esc(s) { return s.replace(/[&<>"]/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]; }); }
    var strong = document.createElement("strong");
    if (!r) {
      strong.textContent = "Not an archive Arcana knows";
      p.appendChild(strong);
      para("No signature from Arcana's built-in formats was found in the first bytes. A plugin may still handle it, and <code>arcana i " + esc(file) + "</code> gives a fuller identification.");
      return p;
    }
    strong.textContent = r.title;
    p.appendChild(strong);
    if (r.inside) para("Inside, it is " + esc(r.inside) + ". Arcana opens it like any archive.");
    if (r.how === "x") para("Extract it: <code>" + esc(cmd) + "</code>");
    else if (r.how === "upx") para("Arcana alone identifies it. With the <a href=\"#known-plugins\">UPX plugin</a> installed, <code>" + esc(cmd) + "</code> writes the unpacked executable, without running it.");
    else if (r.how === "exe") para("<code>arcana i " + esc(file) + "</code> describes it. If it is a self-extracting archive, <code>" + esc(cmd) + "</code> extracts what it contains, and <code>arcana s " + esc(file) + " -n</code> lists the files glued inside.");
    else para("Not an archive: <code>arcana i " + esc(file) + "</code> identifies it and shows its details.");
    var claimed = claimedFormat(name);
    if (claimed && r.fmt && claimed !== r.fmt && !(claimed === "tar.gz" && r.fmt === "gz")) {
      para("The name says <code>" + esc(ext(name)) + "</code>, the bytes say " + esc(r.title) + ". Arcana trusts the bytes.");
    }
    return p;
  }

  function hexRow(b, start, hl) {
    // offsets on 5 digits (enough for the disc image signatures below 0x10000), one continuous mark over the signature
    var off = ("0000" + start.toString(16).toUpperCase()).slice(-5);
    var h = "", a = "", inH = false;
    function on(i) { return hl && i >= hl[0] && i < hl[0] + hl[1]; }
    for (var i = start; i < start + 16; i++) {
      var sep = i === start ? "" : (i === start + 8 ? "  " : " ");
      if (i >= b.length) { h += sep + "  "; continue; }
      var x = ("0" + b[i].toString(16).toUpperCase()).slice(-2);
      var c = b[i] >= 32 && b[i] < 127 ? String.fromCharCode(b[i]) : ".";
      c = c.replace(/[&<>]/g, function (ch) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;" }[ch]; });
      if (on(i) && !inH) { h += sep + "<mark>" + x; inH = true; }
      else if (!on(i) && inH) { h += "</mark>" + sep + x; inH = false; }
      else h += sep + x;
      a += on(i) ? "<mark>" + c + "</mark>" : c;
    }
    if (inH) h += "</mark>";
    return "<span class=\"off\">" + off + "</span>  " + h + "  " + a.replace(/<\/mark><mark>/g, "");
  }

  function render(b, name) {
    var r = identify(b, name);
    var hl = r && r.off >= 0 ? [r.off, r.len] : null;
    var rows = [];
    for (var s = 0; s < Math.min(48, b.length); s += 16) rows.push(hexRow(b, s, hl));
    if (hl && hl[0] >= 48) {
      rows.push("<span class=\"skip\">          ... " + (hl[0] - 48).toLocaleString("en-US") + " bytes later ...</span>");
      rows.push(hexRow(b, hl[0] - (hl[0] % 16), hl));
    }
    document.getElementById("hexdump").innerHTML = rows.join("\n");
    document.getElementById("hex-name").textContent = name + "  (" + (b.totalSize || b.length).toLocaleString("en-US") + " bytes)";
    var v = document.getElementById("verdict");
    v.innerHTML = "";
    v.appendChild(explain(r, name));
  }

  function sample(name, parts, total) {
    var b = [];
    parts.forEach(function (p) {
      if (typeof p === "number") { for (var i = 0; i < p; i++) b.push(0); }
      else if (typeof p === "string" && p.charAt(0) === "'") { b = b.concat(ascii(p.slice(1))); }
      else b = b.concat(bytes(p));
    });
    b.totalSize = total;
    return { name: name, data: b };
  }

  var SAMPLES = [
    sample("report.docx", ["50 4B 03 04 14 00 06 00 08 00 00 00 21 00 DF A4 D2 6C 5A 01 00 00 20 05 00 00 13 00 08 02", "'[Content_Types].xml", "A2 04 02 28 A0 00 02 00 00 00 00 00"], 18733),
    sample("backup.7z", ["37 7A BC AF 27 1C 00 04 8D 9B D5 0F 1C 01 00 00 00 00 00 00 23 00 00 00 00 00 00 00 5B 2E 3F 1A 00 11 88 6B 24 B4 A1 D7 06 3E 41 FF 09 25 13 70"], 452),
    sample("film.rar", ["52 61 72 21 1A 07 01 00 33 92 B5 E5 0A 01 05 06 00 05 01 01 80 80 00 3A 4C 9E 44 2B 02 03 0B 8B 9C 01 04 9C B7 01 20 0B 49 E1 6C 80 03 00 0A 6D"], 9871204),
    sample("schema.dia", ["1F 8B 08 00 00 00 00 00 00 03 ED 5D 5B 73 DB 36 16 7E CF AF 40 F5 D2 99 8E 45 81 B8 5F 9C 38 33 7D 69 D3 76 76 A6 D3 4E 9B EC BE EC 74"], 4122),
    sample("disc.iso", [32769, "'CD001", "01 00", "'LINUX", 20], 734003200),
    sample("setup.exe", ["4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00", 28, "F8 00 00 00", 200, "'UPX0", 3], 89088)
  ];

  function initInspector() {
    var drop = document.getElementById("drop");
    if (!drop) return;
    var box = document.getElementById("samples");
    SAMPLES.forEach(function (s, i) {
      var btn = document.createElement("button");
      btn.type = "button";
      btn.textContent = s.name;
      btn.setAttribute("aria-pressed", i === 0 ? "true" : "false");
      btn.addEventListener("click", function () {
        box.querySelectorAll("button").forEach(function (x) { x.setAttribute("aria-pressed", "false"); });
        btn.setAttribute("aria-pressed", "true");
        render(s.data, s.name);
      });
      box.appendChild(btn);
    });
    render(SAMPLES[0].data, SAMPLES[0].name);

    function readFile(f) {
      if (!f) return;
      var reader = new FileReader();
      reader.onload = function () {
        var b = Array.prototype.slice.call(new Uint8Array(reader.result));
        b.totalSize = f.size;
        box.querySelectorAll("button").forEach(function (x) { x.setAttribute("aria-pressed", "false"); });
        render(b, f.name);
      };
      reader.readAsArrayBuffer(f.slice(0, 0x10000)); // enough for the ISO 9660 and UDF descriptors (sectors 16 to 31)
    }
    var input = document.getElementById("file-input");
    input.addEventListener("change", function () { readFile(input.files[0]); });
    ["dragenter", "dragover"].forEach(function (t) { drop.addEventListener(t, function (e) { e.preventDefault(); drop.classList.add("over"); }); });
    ["dragleave", "drop"].forEach(function (t) { drop.addEventListener(t, function (e) { e.preventDefault(); drop.classList.remove("over"); }); });
    drop.addEventListener("drop", function (e) { if (e.dataTransfer && e.dataTransfer.files.length) readFile(e.dataTransfer.files[0]); });
    // dropping elsewhere on the page must not open the file in the browser
    window.addEventListener("dragover", function (e) { e.preventDefault(); });
    window.addEventListener("drop", function (e) { e.preventDefault(); });
  }

  /* ------------------------------------------------------------------ table of contents and copy buttons */

  function initToc() {
    var links = Array.prototype.slice.call(document.querySelectorAll(".toc a"));
    if (!links.length || !("IntersectionObserver" in window)) return;
    var byId = {};
    links.forEach(function (a) { byId[a.getAttribute("href").slice(1)] = a; });
    var obs = new IntersectionObserver(function (entries) {
      entries.forEach(function (en) {
        if (!en.isIntersecting) return;
        var a = byId[en.target.id];
        if (!a) return;
        links.forEach(function (l) { l.removeAttribute("aria-current"); });
        a.setAttribute("aria-current", "true");
      });
    }, { rootMargin: "-15% 0px -75% 0px" });
    Object.keys(byId).forEach(function (id) { var el = document.getElementById(id); if (el) obs.observe(el); });
  }

  function initCopy() {
    if (!navigator.clipboard) return;
    document.querySelectorAll("pre.code, pre.term").forEach(function (pre) {
      var wrap = document.createElement("div");
      wrap.className = "copy-wrap";
      pre.parentNode.insertBefore(wrap, pre);
      wrap.appendChild(pre);
      var btn = document.createElement("button");
      btn.type = "button";
      btn.className = "copy";
      btn.textContent = "Copy";
      btn.addEventListener("click", function () {
        var text = pre.classList.contains("term")
          ? Array.prototype.slice.call(pre.querySelectorAll(".cmd")).map(function (c) { return c.textContent; }).join("\n")
          : pre.textContent;
        navigator.clipboard.writeText(text || pre.textContent).then(function () {
          btn.textContent = "Copied";
          window.setTimeout(function () { btn.textContent = "Copy"; }, 1500);
        });
      });
      wrap.appendChild(btn);
    });
  }

  // the plugin list first: it gives the descriptions of the plugin JARs of the release
  if (window.Promise) loadPlugins().then(function () { loadRelease(); bindDownloads(); }); else loadRelease();
  bindDownloads();
  initInspector();
  initToc();
  initCopy();
})();
