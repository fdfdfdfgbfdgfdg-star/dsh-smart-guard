// dsh-smart-guard -- protective command interceptor for DeepSeek Harness.
//
// Philosophy: do not restrict the agent's work, protect the system from
// destructive actions. The agent may create, read, download, install, run,
// compile and copy anything anywhere. Deleting, formatting and killing
// processes is only allowed inside project folders.
//
// Interception point: the `tools/pre-execute` waterfall of the DSH tool
// registry. Every pwsh/bash tool call passes through it before the command
// body runs. The listener classifies the command:
//
//   ALLOW      - creative or neutral command -> { kind: "allow" }
//   DENY       - destructive command in a protected zone ->
//                { kind: "deny", reason: "BLOCKED: ..." } (logged)
//   ASK        - destructive command outside projects and outside the
//                deny-list -> { kind: "ask", reason: "..." } routed to the
//                approval channel (logged)
//
// Every denial and every confirmation request is appended to
// C:\Users\79881\.dsh\profiles\desktop\dsh-smart-guard.log
//
// Pure ASCII source. Plain Node ESM, no build step, no hard runtime deps:
// the YAML config is parsed by a tiny built-in reader that supports the
// flat `key:` / `- item` lists this plugin uses.

import { appendFile, mkdir, readFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const name = "dsh-smart-guard";
export const inject = ["tools"];

// --- configuration --------------------------------------------------------

const HERE = dirname(fileURLToPath(import.meta.url));
const LOG_PATH = "C:\\Users\\79881\\.dsh\\profiles\\desktop\\dsh-smart-guard.log";

const DEFAULT_CONFIG = {
  projects: [
    "C:\\Users\\79881\\Desktop\\MyClaudeProjects\\",
    "C:\\Users\\79881\\Desktop\\MyGame\\",
    "C:\\Users\\79881\\Desktop\\dsh-auto-retry\\",
    "C:\\Users\\79881\\Desktop\\dsh-smart-guard\\",
  ],
  deny_delete: [
    "C:\\Windows\\",
    "C:\\Program Files\\",
    "C:\\Program Files (x86)\\",
    "C:\\ProgramData\\",
    "C:\\Users\\79881\\AppData\\",
    "C:\\Users\\79881\\Documents\\",
    "C:\\Users\\79881\\Downloads\\",
  ],
  deny_delete_patterns: [
    "MetaTrader",
    "MT4",
    "MT5",
    "terminal.exe",
    "terminal64.exe",
    "Chrome\\User Data",
    "Mozilla\\Firefox",
    "Edge\\User Data",
    "Opera",
    "Brave",
    "Yandex",
  ],
  deny_processes_kill: [
    "terminal.exe",
    "terminal64.exe",
    "chrome.exe",
    "firefox.exe",
    "explorer.exe",
    "winlogon.exe",
    "services.exe",
    "lsass.exe",
  ],
  require_confirmation: [
    "delete_outside_projects",
    "taskkill_unknown",
    "setx",
  ],
};

/** Minimal flat YAML reader: `key:` followed by `- item` lines. */
function parseSimpleYaml(text) {
  const result = {};
  let currentKey = null;
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.replace(/#.*$/, "").trim();
    if (line === "") continue;
    const listItem = line.match(/^-\s*(.+)$/);
    if (listItem && currentKey) {
      if (!Array.isArray(result[currentKey])) result[currentKey] = [];
      result[currentKey].push(stripQuotes(listItem[1].trim()));
      continue;
    }
    const keyMatch = line.match(/^([A-Za-z0-9_-]+):\s*(.*)$/);
    if (keyMatch) {
      currentKey = keyMatch[1];
      const inline = keyMatch[2].trim();
      if (inline === "") {
        result[currentKey] = [];
      } else {
        result[currentKey] = stripQuotes(inline);
        currentKey = null;
      }
    }
  }
  return result;
}

function stripQuotes(value) {
  if (value.length >= 2 && ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'")))) {
    return value.slice(1, -1);
  }
  return value;
}

async function loadConfig() {
  try {
    const text = await readFile(join(HERE, "dsh-smart-guard.yml"), "utf8");
    const parsed = parseSimpleYaml(text);
    // merge: config file values win, defaults fill gaps
    const merged = { ...DEFAULT_CONFIG };
    for (const key of Object.keys(DEFAULT_CONFIG)) {
      if (Array.isArray(parsed[key]) && parsed[key].length > 0) merged[key] = parsed[key];
    }
    return merged;
  } catch {
    return DEFAULT_CONFIG;
  }
}

// --- logging --------------------------------------------------------------

async function log(line) {
  try {
    await mkdir(dirname(LOG_PATH), { recursive: true });
    const stamp = new Date().toISOString();
    await appendFile(LOG_PATH, `[${stamp}] ${line}\n`, "utf8");
  } catch (error) {
    console.error(`[smart-guard] log write failed: ${error instanceof Error ? error.message : String(error)}`);
  }
}

// --- command classification ----------------------------------------------

// Destructive command heads (PowerShell + CMD + POSIX aliases).
// NOTE: bare `format` is matched only at a command head or after /c or a
// separator, so yt-dlp options like `--merge-output-format` or `-f ...`
// never trigger the disk-formatting rule.
const DELETE_HEADS = /(^|[;|&\n]|\bcmd\s+\/c\s+|\bpowershell\s+-c\s+)\s*(remove-item|ri|del|erase|rd|rmdir|rm|-rm|rm-rf|format|format-volume|diskpart|clear-disk|initialize-disk|remove-partition)\b/i;

// Process-killing heads.
const KILL_HEADS = /\b(taskkill|stop-process|kill|pkill|net\s+stop|stop-service|sc\s+stop|nssm\s+stop)\b/i;

// Registry mutation heads.
const REGISTRY_HEADS = /\b(reg\s+delete|reg\s+add|remove-itemproperty|new-itemproperty|set-itemproperty)\b/i;

// Service deletion heads.
const SERVICE_DELETE_HEADS = /\b(sc\s+delete|remove-service|nssm\s+remove)\b/i;

// Environment-variable mutation heads.
const ENV_HEADS = /\b(setx|\[environment\]::setenvironmentvariable)\b/i;

// System-protection heads (Defender / firewall / accounts).
const SYSTEM_HEADS = /\b(set-mppreference|add-mpreference|remove-mpreference|set-netfirewallprofile|netsh\s+(advfirewall|firewall)|disable-netfirewall|net\s+user\s+.*\/delete|net\s+localgroup\s+.*\/delete|wmic\s+useraccount\s+.*delete)\b/i;

// Account / password-reset heads.
const ACCOUNT_HEADS = /\b(net\s+user\s+\S+\s+\/delete|net\s+user\s+\S+\s+\*|set-localuser\s+-password)\b/i;

// Executables downloaded by the agent itself (installers) that may be removed
// from Downloads even though Downloads is otherwise denied.
const AGENT_DOWNLOADER_HEADS = /\b(invoke-webrequest|iwr|curl|wget|start-bitstransfer|invoke-restmethod)\b/i;

/** Extract Windows-style paths from a command string. */
function extractPaths(command) {
  const paths = new Set();
  // quoted paths first
  const quoted = command.match(/"([^"]+)"/g) || [];
  for (const raw of quoted) {
    const inner = raw.slice(1, -1);
    if (looksLikePath(inner)) paths.add(inner);
  }
  // unquoted tokens that look like paths (drive letter or UNC or ~)
  const tokens = command.split(/\s+|;|=|,|\(|\)|\{|\}|\||&/g);
  for (const token of tokens) {
    const cleaned = stripQuotes(token.trim());
    if (cleaned === "") continue;
    if (looksLikePath(cleaned)) paths.add(cleaned);
  }
  return [...paths];
}

function looksLikePath(value) {
  if (value.length < 3) return false;
  return /^[a-zA-Z]:[\\/]/.test(value) || /^\\\\/.test(value) || /^~[\\/]/.test(value) || /^\/(home|root|tmp|var|opt|usr)\//.test(value);
}

/** Normalize a path for comparison: forward slashes, lowercase, no trailing separator. */
function normPath(value) {
  return value.replace(/\//g, "\\").replace(/\\+$/, "").toLowerCase();
}

function pathMatchesPattern(path, pattern) {
  return normPath(path).includes(normPath(pattern));
}

function isInsideFolder(path, folder) {
  const p = normPath(path);
  const f = normPath(folder);
  return p === f || p.startsWith(f + "\\");
}

function isProjectPath(path, projects) {
  return projects.some((project) => isInsideFolder(path, project));
}

function isDeniedPath(path, denyList) {
  return denyList.some((entry) => isInsideFolder(path, entry));
}

function matchesDenyPattern(path, patterns) {
  const p = normPath(path);
  return patterns.some((pattern) => p.includes(normPath(pattern)));
}

/** Extract process image names from kill commands. */
function extractKillTargets(command) {
  const targets = new Set();
  // taskkill /IM name.exe /PID 123
  const imMatches = command.match(/\/im\s+([^\s/]+)/gi) || [];
  for (const raw of imMatches) {
    targets.add(raw.replace(/^\/im\s+/i, "").toLowerCase());
  }
  // Stop-Process -Name name
  const nameMatches = command.match(/-name\s+([^\s,;)]+)/gi) || [];
  for (const raw of nameMatches) {
    targets.add(raw.replace(/^-name\s+/i, "").toLowerCase());
  }
  // taskkill /PID handled elsewhere; plain `kill name` tokens
  if (/\b(kill|pkill)\b/i.test(command)) {
    const tokens = command.split(/\s+/);
    let afterKill = false;
    for (const token of tokens) {
      if (/^(kill|pkill|-9|\/f)$/i.test(token)) { afterKill = true; continue; }
      if (afterKill && /^[a-z0-9_.-]+(\.exe)?$/i.test(token)) {
        targets.add(token.toLowerCase());
      }
    }
  }
  // net stop / sc stop <name>
  const stopMatches = command.match(/(?:net\s+stop|sc\s+stop|stop-service\s+-name)\s+([^\s/]+)/gi) || [];
  for (const raw of stopMatches) {
    targets.add(raw.replace(/^(net\s+stop|sc\s+stop|stop-service\s+-name)\s+/i, "").toLowerCase());
  }
  return [...targets];
}

function isDeniedProcess(target, denyProcesses) {
  const t = target.toLowerCase();
  return denyProcesses.some((p) => t === p.toLowerCase() || t === p.toLowerCase().replace(/\.exe$/, ""));
}

/** True when the command only deletes agent-downloaded installers from Downloads. */
function isAgentInstallerCleanup(command) {
  if (!AGENT_DOWNLOADER_HEADS.test(command)) return false;
  // deletion + download in one compound command: allow the download part;
  // the delete part still targets Downloads, handled by the general rules.
  return false;
}

// --- verdict construction --------------------------------------------------

const ALLOW = { kind: "allow" };

function deny(reason) {
  return { kind: "deny", reason };
}

function ask(reason) {
  return { kind: "ask", reason };
}

// --- classifier ------------------------------------------------------------

/**
 * Classify one shell command.
 * @param {string} command
 * @param {object} config
 * @returns {{kind: string, reason?: string, why: string}}
 */
function classify(command, config) {
  const cmd = String(command ?? "");
  if (cmd.trim() === "") return { ...ALLOW, why: "empty command" };

  // Split compound commands so each segment is judged on its own.
  const segments = cmd
    .split(/(?:^|&&|\|\||;|\|\s*\n?|\n)/g)
    .map((s) => s.trim())
    .filter((s) => s !== "");

  // Per-segment verdicts: the first DENY wins; the first ASK is remembered
  // when no segment is denied.
  let pendingAsk = null;
  for (const segment of segments) {
    const verdict = classifySegment(segment, config);
    if (verdict.kind === "deny") return verdict;
    if (verdict.kind === "ask" && pendingAsk === null) pendingAsk = verdict;
  }
  if (pendingAsk !== null) return pendingAsk;
  return { ...ALLOW, why: "no destructive segment" };
}

function classifySegment(segment, config) {
  // Strip quoted string literals before head-matching, so prose like
  // Write-Output "taskkill test:" never counts as a kill command.
  const code = segment.replace(/"(?:[^"\\]|\\.)*"/g, ' "" ').replace(/'(?:[^'\\]|\\.)*'/g, " '' ");
  const destructive =
    DELETE_HEADS.test(code) ||
    KILL_HEADS.test(code) ||
    REGISTRY_HEADS.test(code) ||
    SERVICE_DELETE_HEADS.test(code) ||
    ENV_HEADS.test(code) ||
    SYSTEM_HEADS.test(code) ||
    ACCOUNT_HEADS.test(code);

  if (!destructive) return { ...ALLOW, why: "creative or neutral command" };

  const paths = extractPaths(segment);

  // --- category: deletion / formatting -----------------------------------
  if (DELETE_HEADS.test(code)) {
    // raw disk formatting / partitioning is always denied, anywhere
    if (/(^|\s)(format|format-volume|diskpart|clear-disk|initialize-disk|remove-partition)(\s|$)/i.test(code) && !/--\S*format/i.test(segment)) {
      return deny(
        "BLOCKED: disk formatting or partitioning is permanently denied. " +
        "Reason: format / diskpart destroys whole volumes and cannot be scoped to a project."
      );
    }
    if (paths.length > 0) {
      for (const path of paths) {
        if (isDeniedPath(path, config.deny_delete)) {
          return deny(
            "BLOCKED: path '" + path + "' is in a protected zone. " +
            "Reason: deletion of system or personal zones is permanently denied " +
            "(C:\\Windows, Program Files, ProgramData, AppData, Documents, Downloads)."
          );
        }
        if (matchesDenyPattern(path, config.deny_delete_patterns)) {
          return deny(
            "BLOCKED: path '" + path + "' matches a protected pattern. " +
            "Reason: MetaTrader / browser profile / terminal data must never be deleted."
          );
        }
        if (isProjectPath(path, config.projects)) continue; // allowed
        // outside projects and outside deny-list
        if (config.require_confirmation.includes("delete_outside_projects")) {
          return ask(
            "CONFIRM: delete '" + path + "' outside project folders. " +
            "Reply through the approval prompt to allow or reject this operation."
          );
        }
        return { ...ALLOW, why: "deletion outside projects without confirmation rule" };
      }
      // every path checked, none denied
      return { ...ALLOW, why: "deletion targets project paths only" };
    }
    // deletion without any recognizable path (e.g. relative paths, variables)
    if (config.require_confirmation.includes("delete_outside_projects")) {
      return ask(
        "CONFIRM: a delete command without an absolute path could remove anything. " +
        "Reply through the approval prompt to allow or reject this operation."
      );
    }
    return { ...ALLOW, why: "delete without absolute path" };
  }

  // --- category: process killing -----------------------------------------
  if (KILL_HEADS.test(code)) {
    const targets = extractKillTargets(segment);
    for (const target of targets) {
      if (isDeniedProcess(target, config.deny_processes_kill)) {
        return deny(
          "BLOCKED: killing process '" + target + "' is permanently denied. " +
          "Reason: terminals, browsers, and Windows core processes must stay alive."
        );
      }
    }
    if (targets.length === 0 && /\b(taskkill|pkill)\b/i.test(code)) {
      // taskkill without /IM or /PID: ambiguous
      if (config.require_confirmation.includes("taskkill_unknown")) {
        return ask("CONFIRM: process kill command with no explicit target.");
      }
    }
    if (config.require_confirmation.includes("taskkill_unknown")) {
      // any kill of a non-listed process still asks the user
      return ask(
        "CONFIRM: stopping process '" + (targets.join(", ") || "unknown") + "' not related to a project. " +
        "Reply through the approval prompt to allow or reject this operation."
      );
    }
    return { ...ALLOW, why: "kill of non-protected process" };
  }

  // --- category: registry mutation ---------------------------------------
  if (REGISTRY_HEADS.test(code)) {
    return deny(
      "BLOCKED: registry modification is permanently denied. " +
      "Reason: reg add / reg delete can break the system."
    );
  }

  // --- category: service deletion ----------------------------------------
  if (SERVICE_DELETE_HEADS.test(code)) {
    return deny(
      "BLOCKED: service deletion is permanently denied. " +
      "Reason: sc delete removes system services."
    );
  }

  // --- category: environment variables -----------------------------------
  if (ENV_HEADS.test(code)) {
    if (config.require_confirmation.includes("setx")) {
      return ask(
        "CONFIRM: environment variable modification. " +
        "Reply through the approval prompt to allow or reject this operation."
      );
    }
    return { ...ALLOW, why: "environment change without confirmation rule" };
  }

  // --- category: Defender / firewall / accounts ---------------------------
  if (SYSTEM_HEADS.test(code)) {
    return deny(
      "BLOCKED: disabling Windows Defender, the firewall, or deleting accounts is permanently denied."
    );
  }

  if (ACCOUNT_HEADS.test(code)) {
    return deny(
      "BLOCKED: account deletion or password reset is permanently denied."
    );
  }

  return { ...ALLOW, why: "unrecognized destructive pattern passed through" };
}

// --- plugin entry -----------------------------------------------------------

export { classify, loadConfig };

export function apply(ctx) {
  let disposed = false;

  const boot = async (toolCtx) => {
    const config = await loadConfig();
    console.info("[smart-guard] started: protective interception of destructive commands active");

    const disposeListener = toolCtx.on("tools/pre-execute", async (exec) => {
      const toolName = exec?.name;
      // Intercept every shell-style tool (pwsh, bash and persistent variants).
      if (toolName !== "pwsh" && toolName !== "bash" && toolName !== "pwsh_persistent" && toolName !== "bash_persistent") {
        return ALLOW;
      }
      const command = exec?.arguments?.command;
      if (typeof command !== "string") return ALLOW;

      const verdict = classify(command, config);
      if (verdict.kind === "allow") return ALLOW;

      const preview = command.length > 200 ? command.slice(0, 200) + "..." : command;
      const logLine =
        verdict.kind === "deny"
          ? "DENIED  tool=" + toolName + " reason=" + verdict.reason + " command=" + JSON.stringify(preview)
          : "ASK     tool=" + toolName + " reason=" + verdict.reason + " command=" + JSON.stringify(preview);
      await log(logLine);

      if (verdict.kind === "deny") {
        return deny(verdict.reason);
      }
      // 'ask' routes through the DSH approval channel.
      return ask(verdict.reason);
    });

    return () => {
      disposeListener?.();
    };
  };

  // The tools service is a hard dependency (inject above), so apply runs
  // once it is available. ctx.on registers the waterfall listener.
  const start = async () => {
    const disposer = await boot(ctx);
    const dispose = () => {
      if (disposed) return;
      disposed = true;
      try {
        disposer?.();
      } catch (error) {
        console.error(`[smart-guard] dispose failed: ${error instanceof Error ? error.message : String(error)}`);
      }
    };
    ctx.effect(() => dispose);
    return dispose;
  };

  start().catch((error) => {
    console.error(`[smart-guard] failed to start: ${error instanceof Error ? error.message : String(error)}`);
  });
}

export default { name, apply };
