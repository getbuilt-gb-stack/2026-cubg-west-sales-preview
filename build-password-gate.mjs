import { execFileSync } from "node:child_process";
import { createCipheriv, createDecipheriv, pbkdf2Sync, randomBytes } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";

const password = process.env.REPORT_PASSWORD;
if (!password) {
  throw new Error("REPORT_PASSWORD is required");
}

const sourceRef = process.env.REPORT_SOURCE_REF;
const sourceFile = process.env.REPORT_SOURCE_FILE;
const plaintextOutput = process.env.PLAINTEXT_REPORT_OUTPUT;

function decryptPayload(source) {
  const marker = "window.CUBG_REPORT_PAYLOAD=";
  if (!source.startsWith(marker)) return null;
  const payload = JSON.parse(source.slice(marker.length).trim().replace(/;$/, ""));
  const ciphertext = Buffer.from(payload.ciphertext, "base64");
  const decipher = createDecipheriv(
    "aes-256-gcm",
    pbkdf2Sync(password, Buffer.from(payload.salt, "base64"), payload.iterations, 32, "sha256"),
    Buffer.from(payload.iv, "base64")
  );
  decipher.setAuthTag(ciphertext.subarray(-16));
  return Buffer.concat([decipher.update(ciphertext.subarray(0, -16)), decipher.final()]).toString("utf8");
}

function readFromGit(ref) {
  return execFileSync("git", ["show", ref], {
    encoding: "utf8",
    maxBuffer: 20 * 1024 * 1024,
  });
}

let existingPayload = "";
try {
  existingPayload = readFileSync("payload.js", "utf8");
} catch {
  // The first build can start from the plaintext report in Git instead.
}
const reportSource = sourceFile
  ? readFileSync(sourceFile, "utf8")
  : sourceRef
    ? readFromGit(sourceRef)
    : decryptPayload(existingPayload) || readFromGit("HEAD:index.html");

const oldMobileCss = "@media(max-width:960px){body{padding:15px 10px}.layout{display:block}.toc{position:static;width:auto;max-height:none;margin-bottom:12px}.toc ul{display:flex;flex-wrap:wrap;gap:3px}.toc a{padding:5px 7px}.news-grid,.profile-grid{grid-template-columns:1fr}.rep-heading{display:block}.rep-stats{justify-content:flex-start;margin-top:12px;text-align:left}.hero{padding:23px 20px}.hero h1{font-size:25px}.stats{grid-template-columns:repeat(2,minmax(0,1fr))}}";
const newMobileCss = "@media(max-width:960px){body{padding:15px 10px}.layout{display:block}.toc{position:static;width:auto;max-height:none;margin-bottom:14px}.toc ul{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:4px 12px}.toc a,.toc-rep-button{min-height:34px;padding:7px 8px;display:flex;align-items:center;overflow-wrap:anywhere}.toc-subheading{grid-column:1/-1}.news-grid,.profile-grid{grid-template-columns:1fr}.rep-heading{display:block}.rep-stats{justify-content:flex-start;margin-top:12px;text-align:left}.hero{padding:23px 20px}.hero h1{font-size:25px}.stats{grid-template-columns:repeat(2,minmax(0,1fr))}}@media(max-width:560px){.toc ul{grid-template-columns:1fr}.toc a,.toc-rep-button{min-height:36px}}";

let report = reportSource;
if (report.includes(oldMobileCss)) report = report.replace(oldMobileCss, newMobileCss);
if (!report.includes(newMobileCss)) {
  throw new Error("Could not find the expected mobile menu CSS");
}

const extraCss = `<style id="responsive-navigation-enhancements">
.toc-mobile-bar{display:none}.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}.toc-select{width:100%;min-height:40px;padding:8px 34px 8px 11px;border:1px solid #c9d8e2;border-radius:5px;background:#fff;color:#294961;font:600 13px -apple-system,BlinkMacSystemFont,"Segoe UI",Arial,sans-serif}.section{position:sticky;top:18px;z-index:18;isolation:isolate;margin-top:25px;padding-top:10px;background:#f4f7f9;scroll-margin-top:74px;box-shadow:0 3px 0 #f4f7f9;border-bottom:1px solid #d8e0e7}.section::before{content:"";position:absolute;z-index:-1;top:-22px;right:0;bottom:0;left:0;background:#f4f7f9}.context-disclosure>summary,.conversation-more>summary,.opportunity-card>summary{list-style:none}.context-disclosure>summary::-webkit-details-marker,.conversation-more>summary::-webkit-details-marker,.opportunity-card>summary::-webkit-details-marker{display:none}.disclosure-heading{display:flex;align-items:center;gap:8px}.disclosure-chevron{display:inline-block;width:8px;height:8px;flex:none;border-right:2px solid currentColor;border-bottom:2px solid currentColor;transform:rotate(-45deg);transition:transform .16s ease}.context-disclosure[open] .disclosure-chevron{transform:rotate(45deg)}.opportunity-card>summary:before{content:"";display:inline-block;width:8px;height:8px;flex:none;margin:0 3px 0 1px;border-right:2px solid currentColor;border-bottom:2px solid currentColor;transform:rotate(-45deg);transition:transform .16s ease}.opportunity-card[open]>summary:before{transform:rotate(45deg)}.context-disclosure>summary:hover,.conversation-more>summary:hover,.opportunity-card>summary:hover{background:#f1f7f6}.conversation-more{margin-top:12px;border-top:1px solid #d8e1e8}.conversation-more>summary{padding:10px 2px;cursor:pointer;color:#153e5c;font-size:12px;font-weight:800}.conversation-more>summary:before{content:"";display:inline-block;width:8px;height:8px;margin:0 8px 1px 1px;border-right:2px solid currentColor;border-bottom:2px solid currentColor;transform:rotate(-45deg);transition:transform .16s ease}.conversation-more[open]>summary:before{transform:rotate(45deg)}.conversation-more-people{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px;padding:2px 0 4px}.conversation-more .conversation-insight{margin-top:10px}
@media(max-width:960px){.toc{position:sticky;top:0;z-index:50;width:auto;max-height:none;margin:-15px -10px 14px;padding:8px 10px;border-top:0;border-radius:0 0 7px 7px;background:rgba(255,255,255,.97);box-shadow:0 3px 10px rgba(15,35,55,.12)}.toc-mobile-bar{display:block}.toc h5,.toc>ul{display:none}.section{top:61px;margin-top:22px;padding:11px 8px 9px;font-size:20px}.section::before{top:-61px}.conversation-more-people{grid-template-columns:1fr}.toc-select{appearance:auto}}
@media(max-width:560px){.section{top:61px;font-size:19px}}
</style>`;

const repCoverageCss = `<style id="rep-coverage-sticky-enhancements">
.rep-panel .rep-heading{position:sticky;top:58px;z-index:15;margin-bottom:12px;background:#fff;border:1px solid #d8e0e7;border-radius:7px;box-shadow:0 4px 10px rgba(15,35,55,.08)}
@media(max-width:960px){.rep-panel .rep-heading{top:110px}}
@media(max-width:560px){.rep-panel .rep-heading{top:106px}}
</style>`;

const logoCss = `<style id="organization-logo-enhancements">
.organization-logo{display:inline-grid;place-items:center;width:28px;height:28px;flex:none;margin-right:8px;border:1px solid #d7e2e8;border-radius:5px;background:#eef4f6;color:#183e59;font-size:10px;font-weight:800;line-height:1;vertical-align:-8px;overflow:hidden}.organization-logo>span{grid-area:1/1}.organization-logo img{display:none;grid-area:1/1;width:100%;height:100%;padding:3px;object-fit:contain;background:#fff}.organization-logo.has-image>span{display:none}.organization-logo.has-image img{display:block}.conversation-heading h3,.opportunity-heading-label{display:flex;align-items:center}.opportunity-card>summary:before{display:none!important}.conversation-more{margin-top:12px;border-top:1px solid #d8e1e8}.conversation-more-toggle{appearance:none;display:flex;align-items:center;width:100%;padding:10px 2px;border:0;background:transparent;color:#153e5c;font:800 12px -apple-system,BlinkMacSystemFont,"Segoe UI",Arial,sans-serif;text-align:left;cursor:pointer}.conversation-more-toggle:hover{background:#eef7f5}.conversation-more-toggle:focus-visible{outline:2px solid #0f766e;outline-offset:2px}.conversation-more-toggle .disclosure-heading{flex:1}.conversation-more-content{margin-top:0}.conversation-more-content[hidden]{display:none}.conversation-more.is-open .disclosure-chevron{transform:rotate(45deg)}.toc{isolation:isolate}.toc-mobile-bar{background:#fff}.toc-select{background:#fff}@media(max-width:960px){.toc{background:#fff}.toc-mobile-bar{position:relative;background:#fff}.section{background:#f4f7f9}}
</style>`;
const extraCssWithLogos = `${extraCss}${repCoverageCss}${logoCss}`;

const navStart = report.indexOf('<nav class="toc">');
const navEnd = report.indexOf("</nav>", navStart);
if (navStart < 0 || navEnd < 0) throw new Error("Could not find the report navigation");
const nav = report.slice(navStart, navEnd + 6);
const sectionOptions = [...nav.matchAll(/<a href="([^"]+)">([^<]+)<\/a>/g)]
  .map(([, href, label]) => `<option value="${href}">${label}</option>`)
  .join("");
const repOptions = [...nav.matchAll(/<button class="toc-rep-button[^\"]*" type="button" data-target="([^"]+)"[^>]*>([^<]+)<\/button>/g)]
  .map(([, target, label]) => `<option value="#reps" data-rep-target="${target}">${label}</option>`)
  .join("");
const mobileMenu = `<div class="toc-mobile-bar"><label class="sr-only" for="toc-select">Jump to a section</label><select id="toc-select" class="toc-select" aria-label="Jump to a section"><option value="">On this page...</option>${sectionOptions.replace('<option value="#reps">Rep Coverage</option>', `<option value="#reps">Rep Coverage</option><optgroup label="Rep coverage">${repOptions}</optgroup>`).replace('<option value="#roster">Full Roster</option>', "<option value=\"#roster\">Full Roster</option>")}</select></div>`;
const navWithMobileMenu = nav.includes('<div class="toc-mobile-bar">')
  ? nav
  : nav.replace('<h5>On This Page</h5>', `${mobileMenu}<h5>On This Page</h5>`);
report = report.slice(0, navStart) + navWithMobileMenu + report.slice(navEnd + 6);
if (report.includes('id="responsive-navigation-enhancements"')) {
  report = report.replace(/<style id="responsive-navigation-enhancements">[\s\S]*?<\/style>/, extraCssWithLogos);
} else {
  report = report.replace("</head>", `${extraCssWithLogos}</head>`);
}

const behaviorScript = `<script id="responsive-navigation-behavior">
(() => {
  const normalizeAccountName = (value) => value.replace(/\\s+/g, " ").trim().toLowerCase();
  const companyDomains = new Map();
  document.querySelectorAll(".table-wrap td").forEach((cell) => {
    const account = cell.querySelector("strong");
    const website = [...cell.querySelectorAll('a[href^="http"]')].find((link) => !link.classList.contains("linkedin"));
    if (account && website) {
      try {
        companyDomains.set(normalizeAccountName(account.textContent), new URL(website.href).hostname);
      } catch {}
    }
  });
  const initials = (name) => name.split(/\\s+/).filter(Boolean).slice(0, 2).map((part) => part[0]).join("").toUpperCase();
  const addOrganizationLogo = (element, accountName) => {
    if (!element || element.querySelector(".organization-logo")) return;
    const host = companyDomains.get(normalizeAccountName(accountName));
    if (!host) return;
    const logo = document.createElement("span");
    logo.className = "organization-logo";
    const fallback = document.createElement("span");
    fallback.textContent = initials(accountName);
    logo.setAttribute("aria-label", accountName + " logo");
    const image = document.createElement("img");
    image.alt = "";
    image.loading = "lazy";
    image.referrerPolicy = "no-referrer";
    const sources = [
      "https://logo.clearbit.com/" + encodeURIComponent(host),
      "https://icons.duckduckgo.com/ip3/" + encodeURIComponent(host) + ".ico",
      "https://" + host + "/favicon.ico"
    ];
    let sourceIndex = 0;
    const tryNextSource = () => {
      if (sourceIndex >= sources.length) return;
      image.src = sources[sourceIndex++];
    };
    image.addEventListener("load", () => logo.classList.add("has-image"), {once:true});
    image.addEventListener("error", tryNextSource);
    logo.append(fallback, image);
    tryNextSource();
    element.prepend(logo);
  };
  document.querySelectorAll(".conversation-heading h3,.opportunity-heading-label,.news-grid h3").forEach((element) => addOrganizationLogo(element, element.textContent));
  document.querySelectorAll(".profile-head span strong").forEach((element) => addOrganizationLogo(element, element.textContent));
  const tocSelect = document.getElementById("toc-select");
  const scrollToSection = (selector) => {
    const target = document.querySelector(selector);
    if (!target) return;
    target.scrollIntoView({behavior:"smooth", block:"start"});
    history.replaceState(null, "", selector);
  };
  tocSelect?.addEventListener("change", () => {
    const option = tocSelect.selectedOptions[0];
    const repTarget = option?.dataset.repTarget;
    if (repTarget && typeof activateRep === "function") {
      activateRep(repTarget);
      scrollToSection("#reps");
    } else if (tocSelect.value) {
      scrollToSection(tocSelect.value);
    }
  });
  document.querySelectorAll('.conversation-view[data-view="prospect"] .conversation-card').forEach((card, cardIndex) => {
    if (card.dataset.progressiveDisclosure === "true") return;
    const people = card.querySelector(".featured-people");
    const insight = card.querySelector(".conversation-insight");
    const peopleItems = people ? [...people.children].filter((item) => item.classList.contains("featured-person")) : [];
    if (!people || !peopleItems.length) return;
    const body = people.parentElement;
    const more = document.createElement("div");
    more.className = "conversation-more";
    const toggle = document.createElement("button");
    toggle.type = "button";
    toggle.className = "conversation-more-toggle";
    toggle.setAttribute("aria-expanded", "false");
    toggle.innerHTML = '<span class="disclosure-heading"><span class="disclosure-chevron" aria-hidden="true"></span><span>Attendees and Account Context</span></span>';
    const content = document.createElement("div");
    content.className = "conversation-more-content";
    content.id = "conversation-context-" + (cardIndex + 1);
    content.hidden = true;
    toggle.setAttribute("aria-controls", content.id);
    body.insertBefore(more, people);
    content.append(people);
    if (insight) content.append(insight);
    more.append(toggle);
    toggle.addEventListener("click", () => {
      const expanded = toggle.getAttribute("aria-expanded") !== "true";
      toggle.setAttribute("aria-expanded", String(expanded));
      more.classList.toggle("is-open", expanded);
      content.hidden = !expanded;
    });
    more.after(content);
    card.dataset.progressiveDisclosure = "true";
  });
})();
</script>`;
if (report.includes('id="responsive-navigation-behavior"')) {
  report = report.replace(/<script id="responsive-navigation-behavior">[\s\S]*?<\/script>/, behaviorScript);
} else {
  report = report.replace("</body>", `${behaviorScript}</body>`);
}
if (plaintextOutput) writeFileSync(plaintextOutput, report);
const salt = randomBytes(16);
const iv = randomBytes(12);
const iterations = 250000;
const key = pbkdf2Sync(password, salt, iterations, 32, "sha256");
const cipher = createCipheriv("aes-256-gcm", key, iv);
const ciphertext = Buffer.concat([cipher.update(report, "utf8"), cipher.final(), cipher.getAuthTag()]);

const encode = (value) => value.toString("base64");
const payload = `window.CUBG_REPORT_PAYLOAD=${JSON.stringify({
  algorithm: "AES-GCM",
  kdf: "PBKDF2-SHA-256",
  iterations,
  salt: encode(salt),
  iv: encode(iv),
  ciphertext: encode(ciphertext),
})};\n`;

const lockPage = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="robots" content="noindex,nofollow,noarchive">
<meta name="googlebot" content="noindex,nofollow,noarchive">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CUBG West Sales Preview</title>
<style>
:root{color-scheme:light;--navy:#111936;--ink:#17283b;--muted:#5f6f80;--line:#d8e0e7;--accent:#ef5a43;--teal:#138b83}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;background:#f4f6f8;color:var(--ink);font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;display:grid;place-items:center;padding:24px}
.gate-shell{width:min(100%,460px);background:#fff;border:1px solid var(--line);border-top:5px solid var(--accent);box-shadow:0 16px 40px rgba(17,25,54,.12);padding:34px 32px 32px}
.brand{color:var(--navy);font-size:22px;font-weight:800;letter-spacing:.01em;margin-bottom:28px}
.brand-mark{display:inline-block;width:13px;height:18px;background:var(--accent);clip-path:polygon(0 0,100% 25%,100% 100%,0 75%);vertical-align:-2px;margin-right:7px}
.eyebrow{color:var(--teal);font-size:11px;font-weight:800;letter-spacing:.12em;text-transform:uppercase;margin:0 0 10px}
h1{font-size:28px;line-height:1.12;margin:0 0 12px;color:var(--navy)}
.intro{color:var(--muted);font-size:15px;line-height:1.55;margin:0 0 26px}
label{display:block;color:var(--navy);font-size:13px;font-weight:700;margin:0 0 7px}
input{width:100%;height:46px;border:1px solid #b9c6d1;border-radius:4px;padding:0 12px;font:inherit;font-size:16px;color:var(--ink);background:#fff}
input:focus{outline:3px solid rgba(19,139,131,.2);border-color:var(--teal)}
button{width:100%;height:46px;border:0;border-radius:4px;background:var(--navy);color:#fff;font:inherit;font-weight:750;font-size:15px;margin-top:14px;cursor:pointer}
button:hover{background:#1b2b54}
button:disabled{opacity:.65;cursor:wait}
.error{color:#b42318;font-size:13px;line-height:1.4;margin:12px 0 0}
@media(max-width:520px){body{padding:14px}.gate-shell{padding:28px 22px 24px}h1{font-size:25px}}
</style>
</head>
<body>
<main class="gate-shell">
  <div class="brand"><span class="brand-mark" aria-hidden="true"></span>built</div>
  <p class="eyebrow">Built Technologies</p>
  <h1>2026 CUBG West Sales Preview</h1>
  <p class="intro">Enter the access password to view the pre-event sales brief.</p>
  <form id="unlock-form">
    <label for="password">Access password</label>
    <input id="password" name="password" type="password" autocomplete="current-password" required autofocus>
    <button id="unlock-button" type="submit">Unlock report</button>
    <p id="error" class="error" role="alert" hidden>That password did not unlock the report.</p>
  </form>
</main>
<script src="./payload.js?v=${encode(salt).replace(/[^A-Za-z0-9]/g, "")}"></script>
<script>
(() => {
  const form = document.getElementById("unlock-form");
  const input = document.getElementById("password");
  const button = document.getElementById("unlock-button");
  const error = document.getElementById("error");
  const fromBase64 = (value) => Uint8Array.from(atob(value), (char) => char.charCodeAt(0));

  async function unlock(password) {
    const payload = window.CUBG_REPORT_PAYLOAD;
    const material = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(password),
      "PBKDF2",
      false,
      ["deriveKey"]
    );
    const key = await crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: fromBase64(payload.salt),
        iterations: payload.iterations,
        hash: "SHA-256"
      },
      material,
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt"]
    );
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: fromBase64(payload.iv) },
      key,
      fromBase64(payload.ciphertext)
    );
    return new TextDecoder().decode(plaintext);
  }

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    error.hidden = true;
    button.disabled = true;
    button.textContent = "Unlocking...";
    try {
      const html = await unlock(input.value);
      document.open();
      document.write(html);
      document.close();
    } catch {
      input.value = "";
      error.hidden = false;
      input.focus();
      button.disabled = false;
      button.textContent = "Unlock report";
    }
  });
})();
</script>
</body>
</html>
`;

writeFileSync("payload.js", payload);
writeFileSync("index.html", lockPage);
console.log(`Built encrypted report from ${sourceRef || "the existing encrypted payload"}: ${report.length.toLocaleString()} characters`);
