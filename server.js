/**
 * Sumo-API Webhook Receiver
 * Handles: newBasho, newMatches, matchResults
 *
 * Setup:
 *   npm install
 *   cp .env.example .env   # fill in your secret
 *   node server.js
 */

import express from "express";
import crypto from "crypto";
import fs from "fs";
import path from "path";
import { parse as csvParse } from "csv-parse/sync";
import { stringify as csvStringify } from "csv-stringify/sync";
import { fileURLToPath } from "url";
import dotenv from "dotenv";

dotenv.config();

// ─── Config ──────────────────────────────────────────────────────────────────

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = process.env.PORT || 3000;
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET || "";
const DATA_DIR = path.join(__dirname, "data");
const STATE_FILE = path.join(DATA_DIR, "state.json");

if (!WEBHOOK_SECRET) {
  console.warn(
    "⚠️  WEBHOOK_SECRET is not set in .env — signature verification will FAIL all requests."
  );
}

// ─── Ensure data directory exists ────────────────────────────────────────────

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

// ─── State persistence ────────────────────────────────────────────────────────
// Keeps bashoId across restarts.

function loadState() {
  if (fs.existsSync(STATE_FILE)) {
    try {
      return JSON.parse(fs.readFileSync(STATE_FILE, "utf8"));
    } catch {
      console.error("Could not parse state.json — starting fresh.");
    }
  }
  return { bashoId: null };
}

function saveState(state) {
  fs.writeFileSync(STATE_FILE, JSON.stringify(state, null, 2), "utf8");
}

let state = loadState();
console.log(
  `📂  Loaded state — current bashoId: ${state.bashoId ?? "(none)"}`
);

// ─── CSV helpers ──────────────────────────────────────────────────────────────

function csvPath(bashoId) {
  return path.join(DATA_DIR, `basho_${bashoId}_matches.csv`);
}

/**
 * Read all existing rows from a CSV file.
 * Returns an empty array if the file doesn't exist.
 */
function readCsv(filePath) {
  if (!fs.existsSync(filePath)) return [];
  const raw = fs.readFileSync(filePath, "utf8");
  return csvParse(raw, { columns: true, skip_empty_lines: true });
}

/**
 * Write rows to a CSV file, creating the file if necessary.
 * Always writes a header row.
 */
function writeCsv(filePath, rows) {
  if (rows.length === 0) return;
  const csv = csvStringify(rows, { header: true });
  fs.writeFileSync(filePath, csv, "utf8");
}

// ─── HMAC signature verification ─────────────────────────────────────────────
// Mirrors the Go verification example in the sumo-api docs:
//   hmac-sha256( secret, url + body )

function verifySignature(req, rawBody) {
  const incoming = req.headers["x-webhook-signature"];
  if (!incoming) return false;

  const url = `${req.protocol}://${req.get("host")}${req.originalUrl}`;
  const mac = crypto.createHmac("sha256", WEBHOOK_SECRET);
  mac.update(url);
  mac.update(rawBody);
  const calculated = mac.digest("hex");

  return crypto.timingSafeEqual(
    Buffer.from(incoming, "hex"),
    Buffer.from(calculated, "hex")
  );
}

// ─── Express setup ────────────────────────────────────────────────────────────

const app = express();

// Capture raw body for HMAC verification BEFORE json parsing.
app.use(
  express.json({
    verify: (req, _res, buf) => {
      req.rawBody = buf;
    },
  })
);

// ─── Webhook endpoint ─────────────────────────────────────────────────────────

app.post("/webhook", (req, res) => {
  // 1. Verify signature
  if (!verifySignature(req, req.rawBody)) {
    console.warn("❌  Invalid webhook signature — request rejected.");
    return res.status(401).json({ error: "Invalid signature" });
  }

  const { type, payload } = req.body;

  if (!type || !payload) {
    console.warn("⚠️  Malformed webhook body — missing type or payload.");
    return res.status(400).json({ error: "Missing type or payload" });
  }

  console.log(`\n📨  Received webhook: ${type}`);

  switch (type) {
    case "newBasho":
      handleNewBasho(payload);
      break;
    case "newMatches":
      handleNewMatches(payload);
      break;
    case "matchResults":
      handleMatchResults(payload);
      break;
    case "endBasho":
      // Not in scope but log it so you know it arrived.
      console.log("ℹ️  endBasho received — no action configured.", payload);
      break;
    default:
      console.warn(`⚠️  Unknown webhook type: ${type}`);
  }

  // Acknowledge receipt as required by sumo-api.
  res.sendStatus(204);
});

// ─── Handlers ─────────────────────────────────────────────────────────────────

/**
 * newBasho — update the stored bashoId.
 * Payload shape: { bashoId, startDate, endDate, ... }
 */
function handleNewBasho(payload) {
  const newId = payload.bashoId;
  if (!newId) {
    console.error("newBasho payload missing bashoId:", payload);
    return;
  }

  const previous = state.bashoId;
  state.bashoId = newId;
  saveState(state);

  console.log(`🏆  New basho detected!`);
  console.log(`    Previous bashoId : ${previous ?? "(none)"}`);
  console.log(`    New bashoId      : ${newId}`);
  if (payload.startDate) console.log(`    Start date       : ${payload.startDate}`);
  if (payload.endDate)   console.log(`    End date         : ${payload.endDate}`);
}

/**
 * Build a stable deduplication key for a match object.
 *
 * A sumo match is uniquely defined by the day it is fought and the two
 * rikishi involved. The sumo-api torikumi endpoint exposes fighter identity
 * through several possible field names depending on context:
 *
 *   - eastId / westId          (torikumi / newMatches webhook)
 *   - rikishiId / opponentId   (per-rikishi match history)
 *
 * We collect whichever of those fields are present and sort them so that
 * the key is stable regardless of which wrestler appears on which side.
 * The `bashoId` is implicit (each CSV is already scoped to one basho) but
 * is included for safety.
 *
 * If none of the expected ID fields are present the function falls back to
 * a full JSON fingerprint of the row so we never silently drop data.
 */
function matchKey(row) {
  const day = row.day ?? "";
  const basho = row.bashoId ?? state.bashoId ?? "";

  // Collect every fighter-ID value that is present in this row.
  const ids = [
    row.eastId,
    row.westId,
    row.rikishiId,
    row.opponentId,
  ]
    .filter((v) => v !== undefined && v !== null && v !== "")
    .map(String)
    .sort(); // sort so east/west order doesn't matter

  if (ids.length >= 2) {
    return `${basho}|${day}|${ids.join("|")}`;
  }

  // Fallback: fingerprint the whole row (excludes result fields that differ
  // between newMatches and matchResults to avoid false duplicates).
  const stable = JSON.stringify(
    Object.fromEntries(
      Object.entries(row).filter(
        ([k]) => !["winner", "winnerId", "kimarite"].includes(k)
      )
    )
  );
  return `${basho}|${day}|${stable}`;
}

/**
 * newMatches — append new scheduled matches to the current basho CSV,
 * skipping any matches that are already recorded.
 * Payload shape: array of match objects.
 */
function handleNewMatches(payload) {
  if (!state.bashoId) {
    console.error(
      "newMatches received but bashoId is not set — ignoring. Wait for a newBasho webhook first."
    );
    return;
  }

  const incoming = Array.isArray(payload) ? payload : [payload];
  if (incoming.length === 0) {
    console.warn("newMatches payload is empty — nothing to write.");
    return;
  }

  const file = csvPath(state.bashoId);
  const existing = readCsv(file);

  // Build a set of keys for every match already in the CSV.
  const existingKeys = new Set(existing.map(matchKey));

  // Only keep incoming rows whose key is not already present.
  const newRows = incoming.filter((row) => {
    const key = matchKey(row);
    if (existingKeys.has(key)) return false;
    existingKeys.add(key); // guard against duplicates within the payload itself
    return true;
  });

  const skipped = incoming.length - newRows.length;

  if (newRows.length === 0) {
    console.log(
      `📋  ${path.basename(file)} — all ${incoming.length} incoming match(es) already exist, nothing written.`
    );
    return;
  }

  const merged = [...existing, ...newRows];
  writeCsv(file, merged);

  const created = existing.length === 0 ? "Created" : "Appended to";
  console.log(`📋  ${created} ${path.basename(file)}.`);
  console.log(`    Incoming  : ${incoming.length} match(es)`);
  if (skipped > 0) {
    console.log(`    Skipped   : ${skipped} duplicate(s)`);
  }
  console.log(`    Written   : ${newRows.length} new match(es)`);
  console.log(`    Total rows: ${merged.length}`);
}

/**
 * matchResults — overwrite today's matches with the result-enriched versions.
 * Payload shape: array of match objects including winner / winnerId.
 *
 * Strategy: results are identified by their `day` field.
 * All existing rows for that day are removed and replaced with the incoming rows.
 */
function handleMatchResults(payload) {
  if (!state.bashoId) {
    console.error(
      "matchResults received but bashoId is not set — ignoring."
    );
    return;
  }

  const incoming = Array.isArray(payload) ? payload : [payload];
  if (incoming.length === 0) {
    console.warn("matchResults payload is empty — nothing to update.");
    return;
  }

  // Determine which day(s) are being updated.
  const days = [...new Set(incoming.map((m) => String(m.day)).filter(Boolean))];

  if (days.length === 0) {
    console.warn(
      "matchResults rows have no `day` field — cannot identify which rows to overwrite. Writing as-is."
    );
  }

  const file = csvPath(state.bashoId);
  const existing = readCsv(file);

  // Remove old rows for the incoming day(s), then append the new result rows.
  const retained = days.length
    ? existing.filter((row) => !days.includes(String(row.day)))
    : existing;

  const updated = [...retained, ...incoming];
  writeCsv(file, updated);

  console.log(
    `✅  matchResults applied to ${path.basename(file)}.`
  );
  console.log(
    `    Day(s) updated : ${days.join(", ") || "(unknown)"}`
  );
  console.log(
    `    Rows replaced  : ${existing.length - retained.length} → ${incoming.length} new result rows.`
  );
  console.log(`    Total rows now : ${updated.length}`);
}

// ─── Health check ─────────────────────────────────────────────────────────────

app.get("/health", (_req, res) => {
  res.json({ status: "ok", bashoId: state.bashoId });
});

// ─── Start ────────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`\n🚀  Sumo webhook server listening on port ${PORT}`);
  console.log(`    POST http://localhost:${PORT}/webhook`);
  console.log(`    GET  http://localhost:${PORT}/health\n`);
});
