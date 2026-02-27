/**
 * Permissions Extension
 *
 * Claude Code-style permission modes for pi. Controls when the agent
 * needs approval for file writes, edits, and bash commands.
 *
 * Modes (matching Claude Code naming):
 *   - default:            Confirm every write, edit, and bash command
 *   - acceptEdits:        Auto-approve write/edit, confirm bash
 *   - fullAuto:           Auto-approve write/edit/bash, confirm dangerous bash only
 *   - bypassPermissions:  Allow everything, but always block catastrophic commands
 *
 * Commands:
 *   /permissions           - Show/change permission mode
 *   /permissions <mode>    - Set mode directly
 *   /permissions:status    - Show current mode
 *
 * Keyboard shortcut: Ctrl+Shift+P - Cycle through modes
 *
 * CLI flags:
 *   --permission-mode <mode>         Set permission mode (default, acceptEdits, fullAuto, bypassPermissions, plan)
 *   --dangerously-skip-permissions   Shortcut for --permission-mode bypassPermissions
 *
 * Configuration:
 *   ~/.pi/agent/extensions/permissions.json (global)
 *   .pi/extensions/permissions.json (project-local, overrides global)
 */

import type { ExtensionAPI } from "@mariozechner/pi-coding-agent";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { homedir } from "node:os";

// --- Types ---

type PermissionMode = "default" | "acceptEdits" | "fullAuto" | "bypassPermissions";

interface SessionAllow {
  tools: Set<string>;       // Tool names auto-approved for session
  commands: Set<string>;    // Exact bash commands approved for session
}

interface PermissionsConfig {
  mode?: PermissionMode;
  dangerousPatterns?: { pattern: string; description: string }[];
  catastrophicPatterns?: { pattern: string; description: string }[];
  protectedPaths?: string[];
}

// --- Constants ---

const MODES: { id: PermissionMode; label: string; description: string }[] = [
  { id: "default", label: "Default", description: "Confirm every write, edit, and bash command" },
  { id: "acceptEdits", label: "Accept Edits", description: "Allow write/edit silently, confirm bash" },
  { id: "fullAuto", label: "Full Auto", description: "Allow write/edit/bash, confirm dangerous only" },
  { id: "bypassPermissions", label: "Bypass Permissions", description: "Allow everything, block catastrophic commands" },
];

/**
 * Dangerous patterns: require confirmation in default, acceptEdits, and fullAuto modes.
 * In bypassPermissions mode these are allowed without confirmation.
 */
const DEFAULT_DANGEROUS = [
  { pattern: "rm -rf", description: "recursive force delete" },
  { pattern: "chmod -R 777", description: "insecure recursive permissions" },
  { pattern: "chown -R", description: "recursive ownership change" },
  { pattern: "> /dev/", description: "direct device write" },
];

/**
 * Catastrophic patterns: ALWAYS blocked in every mode, including bypassPermissions.
 * These can destroy the system, are never needed for normal development,
 * and cannot be overridden via session approval.
 *
 * Note: rm -rf is NOT here — it's handled by the critical directory check below,
 * which only blocks rm -rf targeting system/root directories while allowing it
 * on normal project paths (e.g. rm -rf ./build, rm -rf node_modules).
 */
const DEFAULT_CATASTROPHIC = [
  { pattern: "sudo mkfs", description: "sudo filesystem format" },
  { pattern: "mkfs.", description: "filesystem format" },
  { pattern: "dd if=", description: "raw disk write" },
  { pattern: ":(){ :|:& };:", description: "fork bomb" },
  { pattern: "> /dev/sda", description: "overwrite disk" },
  { pattern: "> /dev/nvme", description: "overwrite disk" },
  { pattern: "sudo dd", description: "sudo raw disk operation" },
];

/**
 * Critical directories: rm -rf targeting these is ALWAYS blocked.
 * Paths are checked after resolving ~ to $HOME. A command like
 * `rm -rf /home/user/project/build` is fine, but `rm -rf /` or
 * `rm -rf /etc` is catastrophic.
 */
const CRITICAL_DIRS = [
  "/",
  "/bin",
  "/boot",
  "/dev",
  "/etc",
  "/home",
  "/lib",
  "/lib64",
  "/opt",
  "/proc",
  "/root",
  "/run",
  "/sbin",
  "/srv",
  "/sys",
  "/tmp",
  "/usr",
  "/var",
];

/**
 * Protected paths: writes/edits to these are ALWAYS blocked, every mode.
 * Resolved relative to home directory. Matches if the target path starts
 * with any of these.
 */
const DEFAULT_PROTECTED_PATHS = [
  "~/.ssh",
  "~/.aws",
  "~/.gnupg",
  "~/.gpg",
  "~/.bashrc",
  "~/.bash_profile",
  "~/.profile",
  "~/.zshrc",
  "~/.zprofile",
  "~/.config/git/credentials",
  "~/.netrc",
  "~/.npmrc",
  "~/.docker/config.json",
  "~/.kube/config",
  "~/.pi/agent/auth.json",
];

/**
 * Shell trick patterns: commands containing these are treated as dangerous
 * because they can hide arbitrary commands inside substitutions, eval, or
 * pipe-to-shell constructs. Matched against the raw command string.
 */
const SHELL_TRICK_PATTERNS = [
  { pattern: /\$\(/, description: "command substitution $(…)" },
  { pattern: /`[^`]+`/, description: "backtick command substitution" },
  { pattern: /\beval\b/, description: "eval execution" },
  { pattern: /\bbash\s+-c\b/, description: "bash -c execution" },
  { pattern: /\bsh\s+-c\b/, description: "sh -c execution" },
  { pattern: /\|\s*(ba)?sh\b/, description: "pipe to shell" },
  { pattern: /\bexec\b/, description: "exec execution" },
  { pattern: /\bsource\b/, description: "source execution" },
  { pattern: />\(/, description: "process substitution >(…)" },
  { pattern: /<\(/, description: "process substitution <(…)" },
];

const GATED_TOOLS = new Set(["write", "edit", "bash"]);

// --- Config loading ---

async function loadConfig(): Promise<PermissionsConfig> {
  const globalPath = resolve(homedir(), ".pi/agent/extensions/permissions.json");
  const localPath = resolve(process.cwd(), ".pi/extensions/permissions.json");

  let global: PermissionsConfig = {};
  let local: PermissionsConfig = {};

  try { global = JSON.parse(await readFile(globalPath, "utf-8")); } catch {}
  try { local = JSON.parse(await readFile(localPath, "utf-8")); } catch {}

  return {
    mode: local.mode ?? global.mode ?? "acceptEdits",
    dangerousPatterns: local.dangerousPatterns ?? global.dangerousPatterns ?? DEFAULT_DANGEROUS,
    catastrophicPatterns: local.catastrophicPatterns ?? global.catastrophicPatterns ?? DEFAULT_CATASTROPHIC,
    protectedPaths: local.protectedPaths ?? global.protectedPaths ?? DEFAULT_PROTECTED_PATHS,
  };
}

// --- Extension ---

export default async function (pi: ExtensionAPI) {
  // Register CLI flags (Claude Code compatible)
  pi.registerFlag("permission-mode", {
    description: "Permission mode (default, acceptEdits, fullAuto, bypassPermissions)",
    type: "string",
    default: "",
  });
  pi.registerFlag("dangerously-skip-permissions", {
    description: "Bypass all permission checks (shortcut for --permission-mode bypassPermissions)",
    type: "boolean",
    default: false,
  });

  const config = await loadConfig();

  let mode: PermissionMode = config.mode!;
  const dangerousPatterns = config.dangerousPatterns!;
  const catastrophicPatterns = config.catastrophicPatterns!;
  const home = homedir();
  const resolvedProtectedPaths = config.protectedPaths!.map((p) =>
    p.startsWith("~/") ? resolve(home, p.slice(2)) : resolve(p)
  );
  const sessionAllow: SessionAllow = { tools: new Set(), commands: new Set() };

  // Reset session allows on new session, apply CLI flags
  pi.on("session_start", async () => {
    sessionAllow.tools.clear();
    sessionAllow.commands.clear();

    // CLI flags override config (Claude Code compatible)
    if (pi.getFlag("dangerously-skip-permissions") === true) {
      mode = "bypassPermissions";
    } else {
      const permMode = pi.getFlag("permission-mode");
      if (permMode && typeof permMode === "string") {
        const found = MODES.find((m) => m.id === permMode);
        if (found) mode = found.id;
      }
    }
  });

  // --- Permission gate ---

  pi.on("tool_call", async (event, ctx) => {
    if (!GATED_TOOLS.has(event.toolName)) return;

    const toolName = event.toolName;

    // CATASTROPHIC CHECK — always runs, every mode, no override
    if (toolName === "bash") {
      const command = String(event.input.command ?? "");

      // Check critical rm -rf (only blocks system/root dirs, allows project paths)
      const criticalRm = checkCriticalRmRf(command);
      if (criticalRm) {
        if (ctx.hasUI) {
          ctx.ui.notify(`🚫 Blocked catastrophic command: ${criticalRm}`, "error");
        }
        return { block: true, reason: `Catastrophic command blocked: ${criticalRm}. This cannot be overridden.` };
      }

      // Check other catastrophic patterns (mkfs, dd, fork bomb, etc.)
      const catastrophe = findMatch(command, catastrophicPatterns);
      if (catastrophe) {
        if (ctx.hasUI) {
          ctx.ui.notify(`🚫 Blocked catastrophic command: ${catastrophe.description}`, "error");
        }
        return { block: true, reason: `Catastrophic command blocked: ${catastrophe.description}. This cannot be overridden.` };
      }
    }

    // PROTECTED PATH CHECK — always runs, every mode, no override
    if (toolName === "write" || toolName === "edit") {
      const targetPath = resolve(String(event.input.path ?? ""));
      const blocked = resolvedProtectedPaths.find((p) => targetPath === p || targetPath.startsWith(p + "/"));
      if (blocked) {
        if (ctx.hasUI) {
          ctx.ui.notify(`🚫 Blocked write to protected path: ${targetPath}`, "error");
        }
        return { block: true, reason: `Protected path blocked: ${targetPath}. This cannot be overridden.` };
      }
    }

    // Also catch bash commands targeting protected paths
    if (toolName === "bash") {
      const command = String(event.input.command ?? "");
      const blocked = resolvedProtectedPaths.find((p) => command.includes(p) || command.includes(p.replace(home, "~")));
      if (blocked) {
        const readable = blocked.replace(home, "~");
        if (ctx.hasUI) {
          ctx.ui.notify(`🚫 Blocked bash targeting protected path: ${readable}`, "error");
        }
        return { block: true, reason: `Bash command references protected path ${readable}. This cannot be overridden.` };
      }
    }

    // SHELL TRICK CHECK — always confirm (except bypassPermissions), no session override
    if (toolName === "bash" && mode !== "bypassPermissions") {
      const command = String(event.input.command ?? "");
      const trick = SHELL_TRICK_PATTERNS.find((p) => p.pattern.test(command));
      if (trick) {
        if (!ctx.hasUI) {
          return { block: true, reason: `Blocked shell trick: ${trick.description} (no UI for confirmation)` };
        }
        const displayCmd = command.length > 200 ? command.slice(0, 200) + "…" : command;
        const options = ["Allow once", "Deny"];
        const choice = await ctx.ui.select(`⚠️ bash: ${displayCmd}\n   ⚠️  SHELL TRICK: ${trick.description}`, options);
        if (choice !== options[0]) {
          return { block: true, reason: `User denied shell trick: ${trick.description}` };
        }
        return; // allowed once, no session override for shell tricks
      }
    }

    // BYPASS PERMISSIONS: everything else is allowed
    if (mode === "bypassPermissions") return;

    // acceptEdits: skip approval for write/edit
    if (mode === "acceptEdits" && (toolName === "write" || toolName === "edit")) return;

    // fullAuto: skip approval for write/edit, and non-dangerous bash
    if (mode === "fullAuto") {
      if (toolName === "write" || toolName === "edit") return;
      if (toolName === "bash") {
        const command = String(event.input.command ?? "");
        const danger = findMatch(command, dangerousPatterns);
        if (!danger) return; // safe bash, allow
      }
    }

    // Check session-level allows
    if (toolName === "bash") {
      const command = String(event.input.command ?? "");
      if (sessionAllow.commands.has(command)) return;
    }
    if (sessionAllow.tools.has(toolName)) return;

    // Need confirmation
    if (!ctx.hasUI) {
      return { block: true, reason: `Blocked ${toolName} (no UI for confirmation, mode: ${mode})` };
    }

    return promptApproval(toolName, event.input, ctx, dangerousPatterns, catastrophicPatterns, sessionAllow);
  });

  // --- Status widget ---

  function updateStatus(ctx: { ui: { setStatus: (id: string, text: string | undefined) => void } }) {
    const m = MODES.find((m) => m.id === mode)!;
    const arrows = mode === "bypassPermissions" ? "⏵⏵⏵⏵" : mode === "fullAuto" ? "⏵⏵⏵" : mode === "acceptEdits" ? "⏵⏵" : "⏵";
    ctx.ui.setStatus("permissions", `${arrows} ${m.label}`);
  }

  pi.on("session_start", async (_event, ctx) => {
    updateStatus(ctx);
  });

  // --- Commands ---

  pi.registerCommand("permissions", {
    description: "Show or change permission mode",
    getArgumentCompletions: (prefix) => {
      const items = MODES.map((m) => ({ value: m.id, label: `${m.id} — ${m.description}` }));
      const filtered = items.filter((i) => i.value.startsWith(prefix));
      return filtered.length > 0 ? filtered : null;
    },
    handler: async (args, ctx) => {
      if (args && args.trim()) {
        const target = args.trim() as PermissionMode;
        const found = MODES.find((m) => m.id === target);
        if (!found) {
          ctx.ui.notify(`Unknown mode: ${target}. Use: ${MODES.map((m) => m.id).join(", ")}`, "error");
          return;
        }
        mode = target;
        sessionAllow.tools.clear();
        sessionAllow.commands.clear();
        updateStatus(ctx);
        ctx.ui.notify(`Permission mode: ${found.label}`, "info");
        return;
      }

      // Interactive selection
      const choices = MODES.map((m) => {
        const current = m.id === mode ? " (current)" : "";
        const arrows = m.id === "bypassPermissions" ? "⏵⏵⏵⏵" : m.id === "fullAuto" ? "⏵⏵⏵" : m.id === "acceptEdits" ? "⏵⏵" : "⏵";
        return `${arrows} ${m.label}${current} — ${m.description}`;
      });

      const choice = await ctx.ui.select("Permission Mode", choices);
      if (choice === undefined) return;

      const idx = choices.indexOf(choice);
      if (idx >= 0) {
        mode = MODES[idx]!.id;
        sessionAllow.tools.clear();
        sessionAllow.commands.clear();
        updateStatus(ctx);
        ctx.ui.notify(`Permission mode: ${MODES[idx]!.label}`, "info");
      }
    },
  });

  pi.registerCommand("permissions:status", {
    description: "Show current permission mode",
    handler: async (_args, ctx) => {
      const m = MODES.find((m) => m.id === mode)!;
      const sessionTools = sessionAllow.tools.size > 0
        ? `\nSession-approved tools: ${[...sessionAllow.tools].join(", ")}`
        : "";
      const sessionCmds = sessionAllow.commands.size > 0
        ? `\nSession-approved commands: ${sessionAllow.commands.size}`
        : "";
      ctx.ui.notify(`Mode: ${m.label} (${m.id})\n${m.description}${sessionTools}${sessionCmds}`, "info");
    },
  });

  // --- Keyboard shortcut: cycle modes ---

  pi.registerShortcut("ctrl+shift+p", {
    description: "Cycle permission mode",
    handler: async (ctx) => {
      const idx = MODES.findIndex((m) => m.id === mode);
      const next = MODES[(idx + 1) % MODES.length]!;
      mode = next.id;
      sessionAllow.tools.clear();
      sessionAllow.commands.clear();
      updateStatus(ctx);
      ctx.ui.notify(`Permission mode: ${next.label}`, "info");
    },
  });
}

// --- Helpers ---

/**
 * Check if a command contains rm -rf (or variants like rm -r -f, rm -fr)
 * targeting a critical system directory. Returns description if catastrophic,
 * null if safe.
 */
function checkCriticalRmRf(command: string): string | null {
  // Match rm with -r and -f flags in any order, then capture the target path(s)
  const rmPatterns = [
    /\brm\s+(?:-[a-z]*r[a-z]*f[a-z]*|-[a-z]*f[a-z]*r[a-z]*)\s+(.*)/i,  // rm -rf, rm -fr, rm -rfi, etc.
    /\brm\s+-r\s+-f\s+(.*)/i,   // rm -r -f
    /\brm\s+-f\s+-r\s+(.*)/i,   // rm -f -r
  ];

  for (const pattern of rmPatterns) {
    const match = command.match(pattern);
    if (!match) continue;

    const targets = match[1]!.trim().split(/\s+/).filter((t) => !t.startsWith("-"));
    const home = homedir();

    for (const target of targets) {
      // Resolve the target path
      const resolved = target === "~" ? home
        : target.startsWith("~/") ? resolve(home, target.slice(2))
        : target === "/*" ? "/"
        : target.startsWith("/") ? target
        : null; // relative paths are fine

      if (!resolved) continue;

      // Check exact match or direct child of root (e.g. /etc, /usr)
      // But NOT deeper paths like /home/user/project
      const normalized = resolved.replace(/\/+$/, "") || "/";

      if (normalized === "/") {
        return `rm -rf / — recursive delete root`;
      }

      // Check against critical dirs (exact match only)
      for (const dir of CRITICAL_DIRS) {
        if (normalized === dir) {
          return `rm -rf ${dir} — recursive delete critical system directory`;
        }
      }

      // Also block rm -rf ~ (entire home)
      if (normalized === home) {
        return `rm -rf ~ — recursive delete entire home directory`;
      }
    }
  }

  // Also check sudo variants
  if (/\bsudo\s+/.test(command)) {
    const withoutSudo = command.replace(/\bsudo\s+/, "");
    const result = checkCriticalRmRf(withoutSudo);
    if (result) return `sudo ${result}`;
  }

  return null;
}

function findMatch(
  command: string,
  patterns: { pattern: string; description: string }[],
): { pattern: string; description: string } | undefined {
  for (const p of patterns) {
    if (command.includes(p.pattern)) {
      return p;
    }
  }
  return undefined;
}

async function promptApproval(
  toolName: string,
  input: Record<string, unknown>,
  ctx: { ui: any },
  dangerousPatterns: { pattern: string; description: string }[],
  catastrophicPatterns: { pattern: string; description: string }[],
  sessionAllow: SessionAllow,
): Promise<{ block: true; reason: string } | undefined> {
  let description: string;
  let icon = "🔒";

  if (toolName === "bash") {
    const command = String(input.command ?? "");
    const catastrophe = findMatch(command, catastrophicPatterns);
    const danger = findMatch(command, dangerousPatterns);
    const displayCmd = command.length > 200 ? command.slice(0, 200) + "…" : command;

    if (catastrophe) {
      icon = "🚫";
      description = `bash: ${displayCmd}\n   🚫 CATASTROPHIC: ${catastrophe.description}`;
    } else if (danger) {
      icon = "⚠️";
      description = `bash: ${displayCmd}\n   ⚠️  DANGEROUS: ${danger.description}`;
    } else {
      description = `bash: ${displayCmd}`;
    }
  } else if (toolName === "write") {
    description = `write: ${input.path}`;
  } else if (toolName === "edit") {
    description = `edit: ${input.path}`;
  } else {
    description = `${toolName}`;
  }

  const options = [
    "Allow once",
    toolName === "bash" ? "Allow this command for session" : `Allow all ${toolName} for session`,
    "Deny",
  ];

  const choice = await ctx.ui.select(`${icon} ${description}`, options);

  if (choice === options[0]) {
    return undefined;
  }

  if (choice === options[1]) {
    if (toolName === "bash") {
      sessionAllow.commands.add(String(input.command ?? ""));
    } else {
      sessionAllow.tools.add(toolName);
    }
    return undefined;
  }

  // Denied or cancelled
  return { block: true, reason: `User denied ${toolName}` };
}
