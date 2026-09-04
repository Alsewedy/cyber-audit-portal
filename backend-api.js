const express = require('express');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const { execFile } = require('child_process');

const app = express();
app.set("trust proxy", "172.16.10.10/32");
app.use((req, res, next) => {
    console.log(`${new Date().toISOString()} ${req.method} ${req.path} client_ip=${req.ip}`);
    next();
});
app.use(cors());
app.use(express.json());
const PORT = 3050;

// --- Setup Multer for File Storage ---
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir);
}

const storage = multer.diskStorage({
  destination: function (req, file, cb) { cb(null, uploadDir); },
  filename: function (req, file, cb) { cb(null, Date.now() + '-' + file.originalname); }
});
const upload = multer({ storage: storage });

// Simulated in-memory audit workflow data
let auditItems = [
    {
        id: "AUD-001",
        criterion_id: "NET-CRIT-001",
        title: "Outbound HTTPS must pass through PROXY01",
        description: "Verify that APP01 outbound HTTPS traffic is restricted to the approved proxy unless an authorized exception exists.",
        owner: "Network Team",
        status: "IN_REVIEW",
        determination_draft: "OTHER_THAN_SATISFIED",
        determination_draft_rationale: "The legacy direct-access rule conflicts with the approved proxy criterion.",
        determination_drafted_by: "analyst1",
        determination_drafted_date: "2026-07-06T08:30:00.000Z",
        determination: null,
        determination_rationale: null,
        conclusion_cause: null,
        created_by: "manager2",
        created_date: "2026-07-01T09:00:00.000Z",
        concluded_by: null,
        concluded_date: null
    },
    {
        id: "AUD-002",
        criterion_id: "IAM-CRIT-001",
        title: "Privileged access must use MFA",
        description: "Verify that administrative access requires an approved MFA method.",
        owner: "Identity Team",
        status: "EVIDENCE_REQUESTED",
        determination_draft: "INSUFFICIENT_EVIDENCE",
        determination_draft_rationale: "The outstanding privileged-access records prevent a supported conclusion.",
        determination_drafted_by: "analyst1",
        determination_drafted_date: "2026-07-06T10:30:00.000Z",
        determination: null,
        determination_rationale: null,
        conclusion_cause: null,
        created_by: "manager2",
        created_date: "2026-07-02T09:00:00.000Z",
        concluded_by: null,
        concluded_date: null
    }
];

let evidenceRequests = [
    {
        id: "ERQ-001",
        audit_item_id: "AUD-001",
        title: "Provide outbound firewall and proxy configuration",
        description: "Upload firewall rules, proxy configuration, and approved exceptions.",
        requested_from: "Network Team",
        assigned_to: "alice",
        drafted_by: "analyst1",
        drafted_date: "2026-07-03T08:30:00.000Z",
        approved_by: "manager1",
        approved_date: "2026-07-03T09:00:00.000Z",
        requested_by: "manager1",
        requested_date: "2026-07-03T09:00:00.000Z",
        due_date: "2026-07-31",
        status: "CLOSED",
        response_note: "Initial network evidence package uploaded."
    },
    {
        id: "ERQ-002",
        audit_item_id: "AUD-002",
        title: "Provide privileged MFA enforcement evidence",
        description: "Upload the MFA policy and a current privileged-access configuration export.",
        requested_from: "Identity Team",
        assigned_to: "bob",
        drafted_by: "analyst1",
        drafted_date: "2026-07-04T08:30:00.000Z",
        approved_by: "manager1",
        approved_date: "2026-07-04T09:00:00.000Z",
        requested_by: "manager1",
        requested_date: "2026-07-04T09:00:00.000Z",
        due_date: "2026-08-07",
        status: "OPEN",
        response_note: null
    },
    {
        id: "ERQ-003",
        audit_item_id: "AUD-002",
        title: "Provide privileged access review records",
        description: "Provide the latest privileged account review and exception approvals.",
        requested_from: "Identity Team",
        assigned_to: "bob",
        drafted_by: "analyst1",
        drafted_date: "2026-07-06T09:30:00.000Z",
        approved_by: null,
        approved_date: null,
        requested_by: null,
        requested_date: null,
        due_date: "2026-08-14",
        status: "DRAFT",
        response_note: null
    },
    {
        id: "ERQ-004",
        audit_item_id: "AUD-001",
        title: "Provide outbound firewall rule export",
        description: "Upload the current rules governing APP01 outbound production traffic.",
        requested_from: "Network Team",
        assigned_to: "alice",
        drafted_by: "analyst1",
        drafted_date: "2026-07-03T08:40:00.000Z",
        approved_by: "manager3",
        approved_date: "2026-07-03T09:10:00.000Z",
        requested_by: "manager3",
        requested_date: "2026-07-03T09:10:00.000Z",
        due_date: "2026-07-31",
        status: "SUBMITTED",
        response_note: "Firewall rule export uploaded."
    },
    {
        id: "ERQ-005",
        audit_item_id: "AUD-001",
        title: "Provide approved proxy exception register",
        description: "Upload the current approved outbound proxy exception register.",
        requested_from: "Network Team",
        assigned_to: "alice",
        drafted_by: "analyst1",
        drafted_date: "2026-07-03T08:50:00.000Z",
        approved_by: "manager3",
        approved_date: "2026-07-03T09:20:00.000Z",
        requested_by: "manager3",
        requested_date: "2026-07-03T09:20:00.000Z",
        due_date: "2026-07-31",
        status: "SUBMITTED",
        response_note: "Proxy exception register uploaded."
    }
];

let evidenceItems = [
    {
        id: "EVD-001",
        audit_item_id: "AUD-001",
        evidence_request_id: "ERQ-001",
        description: "Approved proxy configuration export.",
        submitted_note: "Configuration exported from PROXY01.",
        author: "alice",
        filename: "proxy-config.txt",
        date: "2026-07-05T10:00:00.000Z",
        status: "ACCEPTED",
        sensitivity: "low",
        region: "AU",
        validated_by: "analyst1",
        validated_date: "2026-07-05T11:00:00.000Z",
        review_note: "Configuration identifies the approved outbound proxy.",
        accepted_date: "2026-07-05T12:00:00.000Z",
        accepted_by: "manager3"
    },
    {
        id: "EVD-002",
        audit_item_id: "AUD-001",
        evidence_request_id: "ERQ-004",
        description: "Outbound firewall rule export.",
        submitted_note: "Rules covering APP01 production traffic.",
        author: "alice",
        filename: "firewall-rules.txt",
        date: "2026-07-05T10:05:00.000Z",
        status: "SUBMITTED",
        sensitivity: "high",
        region: "AU",
        validated_by: null,
        validated_date: null,
        review_note: null,
        accepted_date: null,
        accepted_by: null
    },
    {
        id: "EVD-003",
        audit_item_id: "AUD-001",
        evidence_request_id: "ERQ-005",
        description: "Approved proxy exception register.",
        submitted_note: "Current exception register for audit analyst review.",
        author: "alice",
        filename: "proxy-exceptions.txt",
        date: "2026-07-05T10:10:00.000Z",
        status: "VALIDATED",
        sensitivity: "high",
        region: "AU",
        validated_by: "analyst1",
        validated_date: "2026-07-05T11:10:00.000Z",
        review_note: "Exceptions are authorized and in date.",
        accepted_date: null,
        accepted_by: null
    }
];

let findings = [
    {
        id: "FND-001",
        audit_item_id: "AUD-001",
        condition: "One legacy outbound rule permits direct HTTPS access.",
        criteria: "NET-CRIT-001 requires outbound HTTPS to use PROXY01.",
        cause: "Legacy migration rule was not removed.",
        effect: "A workload could bypass approved proxy inspection.",
        recommendation: "Remove the legacy rule and verify traffic through PROXY01.",
        owner: "Network Team",
        assigned_to: "alice",
        due_date: "2026-08-31",
        status: "OPEN",
        drafted_by: "analyst1",
        drafted_date: "2026-07-06T08:45:00.000Z",
        approved_by: "manager1",
        approved_date: "2026-07-06T09:00:00.000Z",
        remediation_note: null,
        remediated_by: null,
        remediation_started_date: null,
        ready_for_retest_date: null,
        retest_note: null,
        retested_by: null,
        retested_date: null,
        override_history: []
    },
    {
        id: "FND-002",
        audit_item_id: "AUD-002",
        condition: "One privileged service account has no recorded MFA exception review.",
        criteria: "IAM-CRIT-001 requires approved MFA for privileged access.",
        cause: "The service account predates the current exception workflow.",
        effect: "Privileged access may occur without an approved compensating control.",
        recommendation: "Review the account and record an approved MFA exception or remediate access.",
        owner: "Identity Team",
        assigned_to: "bob",
        due_date: "2026-09-15",
        status: "DRAFT",
        drafted_by: "analyst1",
        drafted_date: "2026-07-06T10:00:00.000Z",
        approved_by: null,
        approved_date: null,
        remediation_note: null,
        remediated_by: null,
        remediation_started_date: null,
        ready_for_retest_date: null,
        retest_note: null,
        retested_by: null,
        retested_date: null,
        override_history: []
    }
];

// --- Middleware ---
const verifyToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(401).json({ error: 'No token provided' });

    const token = authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Malformed token' });
    
    const decoded = jwt.decode(token);
    if (!decoded || typeof decoded !== "object") {
        return res.status(401).json({ error: "Invalid bearer token." });
    }
    req.token = token;
    req.user = decoded;
    next(); 
};

function requireAnyRole(requiredRoles = []) {
  return (req, res, next) => {
    const roles = req.user.realm_access?.roles || [];
    const hasOne = requiredRoles.some(r => roles.includes(r));
    if (!hasOne) return res.status(403).json({ error: "Access denied: Required role missing." });
    next();
  };
}

// --- ABAC Helper Functions ---

const clearanceRank = {
  low: 1,
  medium: 2,
  high: 3
};

function hasSufficientClearance(userClearance, evidenceSensitivity) {
  return (clearanceRank[userClearance] || 0) >= (clearanceRank[evidenceSensitivity] || 0);
}

function getRequestSource(req) {
  return req.user.azp || req.user.client_id || "unknown";
}

function isFrontendRequest(req) {
  return getRequestSource(req) === "cyber-audit-portal-spa";
}

function isVerifierServiceRequest(req) {
  return getRequestSource(req) === "audit-validator-client";
}

function hasMfa(req) {
  return Array.isArray(req.user.amr) && req.user.amr.includes("otp");
}

function denyAbac(res, reason) {
  return res.status(403).json({
    error: "ABAC denied",
    reason: reason
  });
}

const DETERMINATIONS = ["SATISFIED", "OTHER_THAN_SATISFIED", "INSUFFICIENT_EVIDENCE"];
const FINDING_STATUSES = ["DRAFT", "OPEN", "REMEDIATION_IN_PROGRESS", "READY_FOR_RETEST", "CLOSED"];

function nextId(collection, prefix) {
  const highest = collection.reduce((max, item) => {
    const value = Number.parseInt(item.id.replace(`${prefix}-`, ""), 10);
    return Number.isNaN(value) ? max : Math.max(max, value);
  }, 0);

  return `${prefix}-${String(highest + 1).padStart(3, "0")}`;
}

function isManagerWorkflowRequestAllowed(req, res, { requireMfa = false } = {}) {
  if (req.user.department !== "cybersecurity-audit") {
    denyAbac(res, "Only authorized GRC Lab audit managers can perform this action.");
    return false;
  }

  if (!isFrontendRequest(req)) {
    denyAbac(res, "Manager workflow actions must come from the audit dashboard.");
    return false;
  }

  if (requireMfa && !hasMfa(req)) {
    denyAbac(res, "MFA/OTP is required to conclude an audit item.");
    return false;
  }

  return true;
}

function isAuditAnalystWorkflowRequestAllowed(req, res) {
  if (!isFrontendRequest(req)) {
    denyAbac(res, "Analyst workflow actions must come from the audit dashboard.");
    return false;
  }
  return true;
}

function isControlOwnerWorkflowRequestAllowed(req, res) {
  if (req.user.department !== "cybersecurity-audit") {
    denyAbac(res, "Only authorized GRC Lab control owners can perform this action.");
    return false;
  }
  if (!isFrontendRequest(req)) {
    denyAbac(res, "Control-owner actions must come from the audit dashboard.");
    return false;
  }
  return true;
}

function isEvidenceRequestAssignedToUser(evidenceRequest, user) {
  return evidenceRequest.assigned_to === user.preferred_username;
}

function enrichEvidenceRequest(evidenceRequest) {
  const auditItem = auditItems.find(item => item.id === evidenceRequest.audit_item_id);
  return {
    ...evidenceRequest,
    criterion_id: auditItem?.criterion_id || null
  };
}

function enrichEvidence(evidence) {
  const auditItem = auditItems.find(item => item.id === evidence.audit_item_id);
  return {
    ...evidence,
    criterion_id: auditItem?.criterion_id || null
  };
}

function markAuditItemInReview(auditItemId) {
  const auditItem = auditItems.find(item => item.id === auditItemId);
  if (auditItem && auditItem.status !== "CONCLUDED") {
    auditItem.status = "IN_REVIEW";
  }
}

function closeEvidenceRequestIfComplete(evidenceRequestId) {
  if (!evidenceRequestId) return false;

  const evidenceRequest = evidenceRequests.find(item => item.id === evidenceRequestId);
  if (!evidenceRequest) return false;

  const linkedEvidence = evidenceItems.filter(item => item.evidence_request_id === evidenceRequestId);
  if (linkedEvidence.length === 0 || !linkedEvidence.every(item => item.status === "ACCEPTED")) {
    return false;
  }

  evidenceRequest.status = "CLOSED";
  return true;
}

function removeUploadedFile(file) {
  if (file?.path && fs.existsSync(file.path)) {
    fs.unlinkSync(file.path);
  }
}

function hasRequiredAudience(req) {
  const aud = req.user.aud;

  if (Array.isArray(aud)) {
    return aud.includes("cyber-audit-api");
  }

  return aud === "cyber-audit-api";
}

function requireApiAudience(req, res, next) {
  if (!hasRequiredAudience(req)) {
    return res.status(403).json({
      error: "Invalid token audience",
      reason: "Access token is not intended for the Cyber Audit API."
    });
  }

  next();
}


// --- Token Introspection for High-Risk Endpoints ---
const KEYCLOAK_INTROSPECTION_URL = "http://192.168.40.10:8080/realms/cyber-audit-portal/protocol/openid-connect/token/introspect";
const INTROSPECTION_CLIENT_ID = "audit-validator-client";

async function introspectAccessToken(token) {
  const clientSecret = process.env.AUDIT_VALIDATOR_CLIENT_SECRET;

  if (!clientSecret) {
    throw new Error("Missing AUDIT_VALIDATOR_CLIENT_SECRET environment variable.");
  }

  const body = new URLSearchParams();
  body.append("client_id", INTROSPECTION_CLIENT_ID);
  body.append("client_secret", clientSecret);
  body.append("token", token);

  const response = await fetch(KEYCLOAK_INTROSPECTION_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body: body
  });

  if (!response.ok) {
    throw new Error(`Token introspection failed with HTTP ${response.status}`);
  }

  return response.json();
}

async function requireActiveToken(req, res, next) {
  try {
    const result = await introspectAccessToken(req.token);

    if (!result.active) {
      return res.status(401).json({
        error: "Inactive token",
        reason: "Keycloak introspection reported that this token is no longer active."
      });
    }

    req.introspection = result;
    next();
  } catch (err) {
    return res.status(500).json({
      error: "Token introspection error",
      reason: err.message
    });
  }
}


// --- Simple Risk-Based Access Control for Acceptance Endpoint ---
const KEYCLOAK_ADMIN_TOKEN_URL = "http://192.168.40.10:8080/realms/master/protocol/openid-connect/token";
const KEYCLOAK_ADMIN_USERS_URL = "http://192.168.40.10:8080/admin/realms/cyber-audit-portal/users";
const KEYCLOAK_EVENTS_URL = "http://192.168.40.10:8080/admin/realms/cyber-audit-portal/events";
const RISK_DENY_THRESHOLD = 70;
const RISK_EVENT_WINDOW_MS = 10 * 60 * 1000; // last 10 minutes

async function getKeycloakAdminToken() {
  const adminUsername = process.env.KEYCLOAK_ADMIN_USERNAME;
  const adminPassword = process.env.KEYCLOAK_ADMIN_PASSWORD;

  if (!adminUsername || !adminPassword) {
    throw new Error("Missing KEYCLOAK_ADMIN_USERNAME or KEYCLOAK_ADMIN_PASSWORD environment variable.");
  }

  const body = new URLSearchParams();
  body.append("grant_type", "password");
  body.append("client_id", "admin-cli");
  body.append("username", adminUsername);
  body.append("password", adminPassword);

  const response = await fetch(KEYCLOAK_ADMIN_TOKEN_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body: body
  });

  if (!response.ok) {
    throw new Error(`Failed to get Keycloak admin token. HTTP ${response.status}`);
  }

  const data = await response.json();
  return data.access_token;
}

async function getKeycloakUserId(username, adminToken) {
  const url = `${KEYCLOAK_ADMIN_USERS_URL}?username=${encodeURIComponent(username)}&exact=true`;

  const response = await fetch(url, {
    headers: {
      "Authorization": `Bearer ${adminToken}`
    }
  });

  if (!response.ok) {
    throw new Error(`Failed to search Keycloak user. HTTP ${response.status}`);
  }

  const users = await response.json();
  if (!users.length) {
    return null;
  }

  return users[0].id;
}

async function countRecentLoginErrors(username) {
  const adminToken = await getKeycloakAdminToken();
  const userId = await getKeycloakUserId(username, adminToken);

  if (!userId) {
    return 0;
  }

  const url = `${KEYCLOAK_EVENTS_URL}?type=LOGIN_ERROR&user=${encodeURIComponent(userId)}&max=50`;

  const response = await fetch(url, {
    headers: {
      "Authorization": `Bearer ${adminToken}`
    }
  });

  if (!response.ok) {
    throw new Error(`Failed to read Keycloak events. HTTP ${response.status}`);
  }

  const events = await response.json();
  const since = Date.now() - RISK_EVENT_WINDOW_MS;

  return events.filter(e => e.time >= since).length;
}

async function calculateAcceptanceRisk(req, evidence) {
  const username = req.user.preferred_username;
  const recentLoginErrors = await countRecentLoginErrors(username);

  let riskScore = 0;

  // Acceptance is always a sensitive operation
  riskScore += 30;

  // High-sensitivity evidence adds more risk
  if (evidence.sensitivity === "high") {
    riskScore += 30;
  }

  // Each recent failed login increases the risk
  riskScore += recentLoginErrors * 30;

  return {
    riskScore: riskScore,
    decision: riskScore >= RISK_DENY_THRESHOLD ? "DENY" : "ALLOW",
    riskFactors: {
      username: username,
      operation: "accept-evidence",
      operationSensitivityScore: 30,
      evidenceSensitivity: evidence.sensitivity,
      evidenceSensitivityScore: evidence.sensitivity === "high" ? 30 : 0,
      recentLoginErrors: recentLoginErrors,
      loginErrorScore: recentLoginErrors * 30,
      threshold: RISK_DENY_THRESHOLD
    }
  };
}

// -------------------------------------------------------
// ENDPOINTS
// -------------------------------------------------------

app.get('/api/public', (req, res) => {
   res.send({ message: 'Welcome to the Cyber Audit Portal' });
});

// Audit Item Endpoints
app.get('/api/audit-items', verifyToken, requireApiAudience, requireActiveToken, requireAnyRole(['audit-manager', 'audit-analyst']), (req, res) => {
  res.json(auditItems);
});

app.get('/api/audit-items/:auditItemID', verifyToken, requireApiAudience, requireActiveToken, requireAnyRole(['audit-manager']), (req, res) => {
  if (!isManagerWorkflowRequestAllowed(req, res)) return;

  const auditItem = auditItems.find(item => item.id === req.params.auditItemID);
  if (!auditItem) return res.status(404).json({ error: "Audit item not found." });

  res.json({
    audit_item: auditItem,
    evidence_requests: evidenceRequests.filter(item => item.audit_item_id === auditItem.id),
    evidence: evidenceItems.filter(item =>
      item.audit_item_id === auditItem.id &&
      (!item.region || item.region === req.user.region) &&
      hasSufficientClearance(req.user.clearanceLevel, item.sensitivity)
    ).map(enrichEvidence),
    findings: findings.filter(item => item.audit_item_id === auditItem.id)
  });
});

app.post('/api/audit-items', verifyToken, requireApiAudience, requireActiveToken, requireAnyRole(['audit-manager']), (req, res) => {
  if (!isManagerWorkflowRequestAllowed(req, res)) return;

  const { criterion_id, title, description, owner } = req.body || {};
  if (![criterion_id, title, description, owner].every(value => typeof value === "string" && value.trim())) {
    return res.status(400).json({ error: "criterion_id, title, description, and owner are required." });
  }

  const newAuditItem = {
    id: nextId(auditItems, "AUD"),
    criterion_id: criterion_id.trim(),
    title: title.trim(),
    description: description.trim(),
    owner: owner.trim(),
    status: "OPEN",
    determination_draft: null,
    determination_draft_rationale: null,
    determination_drafted_by: null,
    determination_drafted_date: null,
    determination: null,
    determination_rationale: null,
    conclusion_cause: null,
    created_by: req.user.preferred_username,
    created_date: new Date().toISOString(),
    concluded_by: null,
    concluded_date: null
  };

  auditItems.push(newAuditItem);
  res.status(201).json({
    message: `Audit item ${newAuditItem.id} created successfully.`,
    audit_item: newAuditItem
  });
});

app.patch('/api/audit-items/:auditItemID/conclude', verifyToken, requireApiAudience, requireActiveToken, requireAnyRole(['audit-manager']), (req, res) => {
  if (!isManagerWorkflowRequestAllowed(req, res, { requireMfa: true })) return;

  const auditItem = auditItems.find(item => item.id === req.params.auditItemID);
  if (!auditItem) return res.status(404).json({ error: "Audit item not found." });
  if (auditItem.status === "CONCLUDED") {
    return res.status(409).json({ error: "This audit item is already concluded and its determination cannot be changed." });
  }
  if (auditItem.created_by === req.user.preferred_username) {
    return denyAbac(res, "A manager cannot conclude an audit item they created. Independent manager review is required.");
  }
  if (!auditItem.determination_draft || !auditItem.determination_draft_rationale) {
    return res.status(409).json({ error: "An audit analyst determination draft is required before manager conclusion." });
  }
  if (auditItem.determination_drafted_by === req.user.preferred_username) {
    return denyAbac(res, "The determination drafter cannot finalize the same audit item.");
  }

  const determination = typeof req.body?.determination === "string" ? req.body.determination.trim() : "";
  const rationale = typeof req.body?.rationale === "string" ? req.body.rationale.trim() : "";
  if (!DETERMINATIONS.includes(determination)) {
    return res.status(400).json({ error: `determination must be one of: ${DETERMINATIONS.join(", ")}.` });
  }
  if (!rationale) return res.status(400).json({ error: "A determination rationale is required." });

  const linkedEvidence = evidenceItems.filter(item => item.audit_item_id === auditItem.id);
  const linkedRequests = evidenceRequests.filter(item => item.audit_item_id === auditItem.id);
  const linkedFindings = findings.filter(item => item.audit_item_id === auditItem.id && item.status !== "DRAFT");
  const managerReviewedAllEvidence = linkedEvidence.length > 0 && linkedEvidence.every(item =>
    item.validated_by === req.user.preferred_username || item.accepted_by === req.user.preferred_username
  );

  if (managerReviewedAllEvidence) {
    return denyAbac(res, "A manager who validated or accepted all linked evidence cannot conclude the audit item.");
  }

  if (determination === "SATISFIED") {
    if (!linkedEvidence.some(item => item.status === "ACCEPTED")) {
      return res.status(409).json({ error: "SATISFIED requires at least one ACCEPTED evidence item." });
    }
    if (!linkedRequests.every(item => item.status === "CLOSED")) {
      return res.status(409).json({ error: "SATISFIED requires all evidence requests to be CLOSED." });
    }
  }

  if (determination === "OTHER_THAN_SATISFIED" && linkedFindings.length === 0) {
    return res.status(409).json({ error: "OTHER_THAN_SATISFIED requires at least one linked finding." });
  }

  auditItem.status = "CONCLUDED";
  auditItem.determination = determination;
  auditItem.determination_rationale = rationale;
  auditItem.conclusion_cause = determination === "INSUFFICIENT_EVIDENCE" ? "INSUFFICIENT_EVIDENCE" : null;
  auditItem.concluded_by = req.user.preferred_username;
  auditItem.concluded_date = new Date().toISOString();

  res.json({
    message: `Audit item ${auditItem.id} concluded as ${determination}.`,
    audit_item: auditItem,
    insufficient_evidence: determination === "INSUFFICIENT_EVIDENCE"
  });
});

app.patch('/api/audit-items/:auditItemID/determination-draft', verifyToken, requireApiAudience, requireActiveToken, requireAnyRole(['audit-analyst']), (req, res) => {
  if (!isAuditAnalystWorkflowRequestAllowed(req, res)) return;

  const auditItem = auditItems.find(item => item.id === req.params.auditItemID);
  if (!auditItem) return res.status(404).json({ error: "Audit item not found." });
  if (auditItem.status === "CONCLUDED") {
    return res.status(409).json({ error: "Cannot draft a determination for a concluded audit item." });
  }

  const determination = typeof req.body?.determination === "string" ? req.body.determination.trim() : "";
  const rationale = typeof req.body?.rationale === "string" ? req.body.rationale.trim() : "";
  if (!DETERMINATIONS.includes(determination)) {
    return res.status(400).json({ error: `determination must be one of: ${DETERMINATIONS.join(", ")}.` });
  }
  if (!rationale) return res.status(400).json({ error: "A draft determination rationale is required." });

  auditItem.determination_draft = determination;
  auditItem.determination_draft_rationale = rationale;
  auditItem.determination_drafted_by = req.user.preferred_username;
  auditItem.determination_drafted_date = new Date().toISOString();

  res.json({
    message: `Draft determination saved for ${auditItem.id}.`,
    audit_item: auditItem
  });
});

// Evidence Request Endpoints
// Compatibility route retained, but it now follows the audit analyst DRAFT workflow.
app.post('/api/audit-items/:auditItemID/evidence-requests', verifyToken, requireApiAudience, requireActiveToken, requireAnyRole(['audit-analyst']), createEvidenceRequestDraft);

app.get('/api/audit-items/:auditItemID/evidence-requests', verifyToken, requireApiAudience, requireActiveToken, requireAnyRole(['audit-manager', 'audit-analyst']), (req, res) => {
  const auditItem = auditItems.find(item => item.id === req.params.auditItemID);
  if (!auditItem) return res.status(404).json({ error: "Audit item not found." });

  res.json(evidenceRequests.filter(item => item.audit_item_id === auditItem.id));
});

app.get('/api/evidence-requests', verifyToken, requireApiAudience, requireActiveToken, requireAnyRole(['audit-manager', 'audit-analyst']), (req, res) => {
  res.json(evidenceRequests.map(enrichEvidenceRequest));
});

app.get('/api/evidence-requests/drafts', verifyToken, requireApiAudience, requireActiveToken, requireAnyRole(['audit-manager', 'audit-analyst']), (req, res) => {
  res.json(evidenceRequests.filter(item => item.status === "DRAFT").map(enrichEvidenceRequest));
});

function createEvidenceRequestDraft(req, res) {
  if (!isAuditAnalystWorkflowRequestAllowed(req, res)) return;

  const auditItem = auditItems.find(item => item.id === req.params.auditItemID);
  if (!auditItem) return res.status(404).json({ error: "Audit item not found." });
  if (auditItem.status === "CONCLUDED") {
    return res.status(409).json({ error: "Cannot draft an evidence request for a concluded audit item." });
  }

  const { title, description, requested_from, assigned_to, due_date } = req.body || {};
  if (![title, description, requested_from, assigned_to, due_date].every(value => typeof value === "string" && value.trim())) {
    return res.status(400).json({ error: "title, description, requested_from, assigned_to, and due_date are required." });
  }

  const newRequest = {
    id: nextId(evidenceRequests, "ERQ"),
    audit_item_id: auditItem.id,
    title: title.trim(),
    description: description.trim(),
    requested_from: requested_from.trim(),
    assigned_to: assigned_to.trim(),
    drafted_by: req.user.preferred_username,
    drafted_date: new Date().toISOString(),
    approved_by: null,
    approved_date: null,
    requested_by: null,
    requested_date: null,
    due_date: due_date.trim(),
    status: "DRAFT",
    response_note: null,
    issuance_mode: "ANALYST_DRAFT"
  };

  evidenceRequests.push(newRequest);
  res.status(201).json({
    message: `Evidence request draft ${newRequest.id} created for ${auditItem.id}.`,
    evidence_request: enrichEvidenceRequest(newRequest)
  });
}

app.post('/api/audit-items/:auditItemID/evidence-request-drafts', verifyToken, requireApiAudience, requireActiveToken, requireAnyRole(['audit-analyst']), createEvidenceRequestDraft);

app.patch('/api/evidence-requests/:evidenceRequestID/issue', verifyToken, requireApiAudience, requireActiveToken, requireAnyRole(['audit-manager']), (req, res) => {
  if (!isManagerWorkflowRequestAllowed(req, res)) return;

  const evidenceRequest = evidenceRequests.find(item => item.id === req.params.evidenceRequestID);
  if (!evidenceRequest) return res.status(404).json({ error: "Evidence request not found." });
  if (evidenceRequest.status !== "DRAFT") {
    return res.status(409).json({ error: "Only DRAFT evidence requests may be issued." });
  }
  if (evidenceRequest.drafted_by === req.user.preferred_username) {
    return denyAbac(res, "A user cannot issue an evidence request they drafted.");
  }

  const auditItem = auditItems.find(item => item.id === evidenceRequest.audit_item_id);
  if (!auditItem || auditItem.status === "CONCLUDED") {
    return res.status(409).json({ error: "The linked audit item is unavailable or concluded." });
  }

  evidenceRequest.status = "OPEN";
  evidenceRequest.approved_by = req.user.preferred_username;
  evidenceRequest.approved_date = new Date().toISOString();
  evidenceRequest.requested_by = req.user.preferred_username;
  evidenceRequest.requested_date = evidenceRequest.approved_date;
  if (auditItem.status === "OPEN") auditItem.status = "EVIDENCE_REQUESTED";

  res.json({
    message: `Evidence request ${evidenceRequest.id} issued successfully.`,
    evidence_request: enrichEvidenceRequest(evidenceRequest)
  });
});

app.get('/api/evidence-requests/open', verifyToken, requireApiAudience, requireActiveToken, requireAnyRole(['control-owner']), (req, res) => {
  if (!isControlOwnerWorkflowRequestAllowed(req, res)) return;

  const assignedRequests = evidenceRequests
    .filter(item => item.status === "OPEN" && isEvidenceRequestAssignedToUser(item, req.user))
    .map(enrichEvidenceRequest);

  res.json(assignedRequests);
});

app.patch('/api/evidence-requests/:evidenceRequestID/close', verifyToken, requireApiAudience, requireActiveToken, requireAnyRole(['audit-manager']), (req, res) => {
  if (!isManagerWorkflowRequestAllowed(req, res)) return;

  const evidenceRequest = evidenceRequests.find(item => item.id === req.params.evidenceRequestID);
  if (!evidenceRequest) return res.status(404).json({ error: "Evidence request not found." });
  if (evidenceRequest.status === "CLOSED") return res.json({ message: "Evidence request is already CLOSED.", evidence_request: evidenceRequest });

  if (!closeEvidenceRequestIfComplete(evidenceRequest.id)) {
    return res.status(409).json({ error: "Evidence request can close only when it has linked evidence and all linked evidence is ACCEPTED." });
  }

  res.json({
    message: `Evidence request ${evidenceRequest.id} closed successfully.`,
    evidence_request: evidenceRequest
  });
});

// Finding Endpoints
app.get('/api/findings', verifyToken, requireApiAudience, requireActiveToken, requireAnyRole(['audit-manager', 'audit-analyst']), (req, res) => {
  res.json(findings);
});

app.get('/api/audit-items/:auditItemID/findings', verifyToken, requireApiAudience, requireActiveToken, requireAnyRole(['audit-manager', 'audit-analyst']), (req, res) => {
  const auditItem = auditItems.find(item => item.id === req.params.auditItemID);
  if (!auditItem) return res.status(404).json({ error: "Audit item not found." });
  res.json(findings.filter(item => item.audit_item_id === auditItem.id));
});

function createFindingDraft(req, res) {
  if (!isAuditAnalystWorkflowRequestAllowed(req, res)) return;
  const auditItem = auditItems.find(item => item.id === req.params.auditItemID);
  if (!auditItem) return res.status(404).json({ error: "Audit item not found." });
  if (auditItem.status === "CONCLUDED") {
    return res.status(409).json({ error: "Cannot draft a finding for a concluded audit item." });
  }

  const { condition, criteria, cause, effect, recommendation, owner, assigned_to, due_date } = req.body || {};
  if (![condition, criteria, cause, effect, recommendation, owner, assigned_to, due_date].every(value => typeof value === "string" && value.trim())) {
    return res.status(400).json({ error: "condition, criteria, cause, effect, recommendation, owner, assigned_to, and due_date are required." });
  }

  const draftedDate = new Date().toISOString();
  const newFinding = {
    id: nextId(findings, "FND"),
    audit_item_id: auditItem.id,
    condition: condition.trim(),
    criteria: criteria.trim(),
    cause: cause.trim(),
    effect: effect.trim(),
    recommendation: recommendation.trim(),
    owner: owner.trim(),
    assigned_to: assigned_to.trim(),
    due_date: due_date.trim(),
    status: "DRAFT",
    drafted_by: req.user.preferred_username,
    drafted_date: draftedDate,
    approved_by: null,
    approved_date: null,
    remediation_note: null,
    remediated_by: null,
    remediation_started_date: null,
    ready_for_retest_date: null,
    retest_note: null,
    retested_by: null,
    retested_date: null,
    override_history: []
  };

  findings.push(newFinding);
  res.status(201).json({
    message: `Finding draft ${newFinding.id} created for ${auditItem.id}.`,
    finding: newFinding
  });
}

app.post('/api/audit-items/:auditItemID/finding-drafts', verifyToken, requireApiAudience, requireActiveToken, requireAnyRole(['audit-analyst']), createFindingDraft);

// Compatibility alias: finding creation now follows the audit analyst DRAFT workflow.
app.post('/api/audit-items/:auditItemID/findings', verifyToken, requireApiAudience, requireActiveToken, requireAnyRole(['audit-analyst']), createFindingDraft);

app.patch('/api/findings/:findingID/approve', verifyToken, requireApiAudience, requireActiveToken, requireAnyRole(['audit-manager']), (req, res) => {
  if (!isManagerWorkflowRequestAllowed(req, res)) return;

  const finding = findings.find(item => item.id === req.params.findingID);
  if (!finding) return res.status(404).json({ error: "Finding not found." });
  if (finding.status !== "DRAFT") {
    return res.status(409).json({ error: "Only DRAFT findings may be approved." });
  }
  if (finding.drafted_by === req.user.preferred_username) {
    return denyAbac(res, "A user cannot approve a finding they drafted.");
  }

  finding.status = "OPEN";
  finding.approved_by = req.user.preferred_username;
  finding.approved_date = new Date().toISOString();

  res.json({
    message: `Finding ${finding.id} approved and opened.`,
    finding: finding
  });
});

app.get('/api/findings/assigned', verifyToken, requireApiAudience, requireActiveToken, requireAnyRole(['control-owner']), (req, res) => {
  if (!isControlOwnerWorkflowRequestAllowed(req, res)) return;
  res.json(findings.filter(item =>
    item.status !== "DRAFT" && item.assigned_to === req.user.preferred_username
  ));
});

app.patch('/api/findings/:findingID/remediation', verifyToken, requireApiAudience, requireActiveToken, requireAnyRole(['control-owner']), (req, res) => {
  if (!isControlOwnerWorkflowRequestAllowed(req, res)) return;

  const finding = findings.find(item => item.id === req.params.findingID);
  if (!finding) return res.status(404).json({ error: "Finding not found." });
  if (finding.assigned_to !== req.user.preferred_username) {
    return denyAbac(res, "This finding is not assigned to the current control owner.");
  }

  const targetStatus = typeof req.body?.status === "string" ? req.body.status.trim() : "";
  const remediationNote = typeof req.body?.remediation_note === "string" ? req.body.remediation_note.trim() : "";
  if (!remediationNote) return res.status(400).json({ error: "A remediation_note is required." });

  const validTransition =
    (finding.status === "OPEN" && targetStatus === "REMEDIATION_IN_PROGRESS") ||
    (finding.status === "REMEDIATION_IN_PROGRESS" && targetStatus === "READY_FOR_RETEST");
  if (!validTransition) {
    return res.status(409).json({ error: `Invalid control-owner transition: ${finding.status} -> ${targetStatus}.` });
  }

  finding.status = targetStatus;
  finding.remediation_note = remediationNote;
  finding.remediated_by = req.user.preferred_username;
  if (targetStatus === "REMEDIATION_IN_PROGRESS") {
    finding.remediation_started_date = new Date().toISOString();
  } else {
    finding.ready_for_retest_date = new Date().toISOString();
  }

  res.json({
    message: `Finding ${finding.id} moved to ${targetStatus}.`,
    finding: finding
  });
});

app.patch('/api/findings/:findingID/retest', verifyToken, requireApiAudience, requireActiveToken, requireAnyRole(['audit-analyst']), (req, res) => {
  if (!isAuditAnalystWorkflowRequestAllowed(req, res)) return;

  const finding = findings.find(item => item.id === req.params.findingID);
  if (!finding) return res.status(404).json({ error: "Finding not found." });
  if (finding.status !== "READY_FOR_RETEST") {
    return res.status(409).json({ error: "Only READY_FOR_RETEST findings may be closed after retest." });
  }
  if (finding.remediated_by === req.user.preferred_username) {
    return denyAbac(res, "The remediation owner cannot perform the independent audit analyst retest.");
  }

  const retestNote = typeof req.body?.retest_note === "string" ? req.body.retest_note.trim() : "";
  if (!retestNote) return res.status(400).json({ error: "A retest_note is required before closure." });

  finding.status = "CLOSED";
  finding.retest_note = retestNote;
  finding.retested_by = req.user.preferred_username;
  finding.retested_date = new Date().toISOString();

  res.json({
    message: `Finding ${finding.id} closed after audit analyst retest.`,
    finding: finding
  });
});

app.patch('/api/findings/:findingID/status', verifyToken, requireApiAudience, requireActiveToken, requireAnyRole(['audit-manager']), (req, res) => {
  if (!isManagerWorkflowRequestAllowed(req, res)) return;

  const finding = findings.find(item => item.id === req.params.findingID);
  if (!finding) return res.status(404).json({ error: "Finding not found." });

  const status = typeof req.body?.status === "string" ? req.body.status.trim() : "";
  const reason = typeof req.body?.reason === "string" ? req.body.reason.trim() : "";
  if (!FINDING_STATUSES.includes(status)) {
    return res.status(400).json({ error: `status must be one of: ${FINDING_STATUSES.join(", ")}.` });
  }
  if (!reason) return res.status(400).json({ error: "A manager override reason is required." });
  if (finding.status === "DRAFT" || status === "DRAFT") {
    return res.status(409).json({ error: "DRAFT findings must use the approval workflow and cannot be manager-overridden." });
  }
  if (status === "CLOSED") {
    return res.status(409).json({ error: "Only an audit analyst may close a finding through the retest workflow." });
  }

  const previousStatus = finding.status;
  finding.status = status;
  finding.override_history = Array.isArray(finding.override_history) ? finding.override_history : [];
  finding.override_history.push({
    from: previousStatus,
    to: status,
    reason: reason,
    overridden_by: req.user.preferred_username,
    overridden_date: new Date().toISOString()
  });
  res.json({
    message: `Finding ${finding.id} status overridden to ${status}.`,
    finding: finding
  });
});

// Upload Endpoint (Status becomes SUBMITTED)
app.post('/api/upload/report', verifyToken, requireApiAudience, requireActiveToken, requireAnyRole(['control-owner']), upload.single('reportDoc'), (req, res) => {
  const requestSource = getRequestSource(req);

  if (!isControlOwnerWorkflowRequestAllowed(req, res)) {
    removeUploadedFile(req.file);
    return;
  }

  if (!req.file) return res.status(400).json({ error: "No file was uploaded." });

  const evidenceRequestId = typeof req.body?.evidence_request_id === "string"
    ? req.body.evidence_request_id.trim()
    : "";
  if (!evidenceRequestId) {
    removeUploadedFile(req.file);
    return res.status(400).json({ error: "An OPEN evidence_request_id is required." });
  }

  const evidenceRequest = evidenceRequests.find(item => item.id === evidenceRequestId);
  if (!evidenceRequest) {
    removeUploadedFile(req.file);
    return res.status(404).json({ error: "Evidence request not found." });
  }
  if (evidenceRequest.status !== "OPEN") {
    removeUploadedFile(req.file);
    return res.status(409).json({ error: "Evidence can only be uploaded against an OPEN evidence request." });
  }
  if (!isEvidenceRequestAssignedToUser(evidenceRequest, req.user)) {
    removeUploadedFile(req.file);
    return denyAbac(res, "This evidence request is not assigned to the current user.");
  }

  const auditItem = auditItems.find(item => item.id === evidenceRequest.audit_item_id);
  if (!auditItem) {
    removeUploadedFile(req.file);
    return res.status(409).json({ error: "The evidence request is not linked to a valid audit item." });
  }
  if (auditItem.status === "CONCLUDED") {
    removeUploadedFile(req.file);
    return res.status(409).json({ error: "Evidence cannot be uploaded for a concluded audit item." });
  }

  const submittedNote = typeof req.body?.submitted_note === "string" ? req.body.submitted_note.trim() : "";
  const description = typeof req.body?.description === "string" ? req.body.description.trim() : "";

  const newEvidence = {
        id: nextId(evidenceItems, "EVD"),
        audit_item_id: auditItem.id,
        evidence_request_id: evidenceRequest.id,
        description: description,
        submitted_note: submittedNote,
        author: req.user.preferred_username,
        filename: req.file.filename,
        date: new Date().toISOString(),
        status: "SUBMITTED",
        sensitivity: "medium",
        region: req.user.region || "AU",
        validated_by: null,
        validated_date: null,
        review_note: null,
        accepted_date: null,
        accepted_by: null
  };

  evidenceItems.push(newEvidence);
  evidenceRequest.status = "SUBMITTED";
  evidenceRequest.response_note = submittedNote || null;
  if (auditItem.status === "OPEN") auditItem.status = "EVIDENCE_REQUESTED";

  res.json({
      message: "Success! Audit evidence uploaded securely and is SUBMITTED for validation.",
      evidence: enrichEvidence(newEvidence),
      evidence_request: evidenceRequest,
      abacDecision: "Allowed by hybrid RBAC + ABAC policy",
      checkedAttributes: {
          department: req.user.department,
          userRegion: req.user.region,
          evidenceRegion: newEvidence.region,
          evidenceSensitivity: newEvidence.sensitivity,
          requestSource: requestSource,
          evidenceStatus: newEvidence.status,
          auditItemId: newEvidence.audit_item_id,
          evidenceRequestId: newEvidence.evidence_request_id
      }
  });
});

app.get('/api/evidence/mine', verifyToken, requireApiAudience, requireActiveToken, requireAnyRole(['control-owner']), (req, res) => {
  if (!isControlOwnerWorkflowRequestAllowed(req, res)) return;
  const ownEvidence = evidenceItems
    .filter(item => item.author === req.user.preferred_username && (!item.region || item.region === req.user.region))
    .map(enrichEvidence);
  res.json(ownEvidence);
});

// View ACCEPTED Evidence
app.get('/api/view/report', verifyToken, requireApiAudience, requireActiveToken, requireAnyRole(['audit-manager', 'audit-analyst']), (req, res) => {
    if (!isFrontendRequest(req)) {
        return denyAbac(res, "Accepted evidence must be viewed through the audit dashboard.");
    }
    const accepted = evidenceItems.filter(r =>
        r.status === "ACCEPTED" &&
        (!r.region || req.user.region === r.region) &&
        hasSufficientClearance(req.user.clearanceLevel, r.sensitivity)
    ).map(enrichEvidence);

    res.json(accepted);
});

// View VALIDATED Evidence
app.get('/api/verified/report', verifyToken, requireApiAudience, requireActiveToken, requireAnyRole(['audit-manager']), (req, res) => {
    if (req.user.department !== "cybersecurity-audit") {
        return denyAbac(res, "Only authorized GRC Lab team members can view validated audit evidence.");
    }

    if (!isFrontendRequest(req)) {
        return denyAbac(res, "Validated evidence must be viewed through the audit dashboard.");
    }

    const validated = evidenceItems.filter(r =>
        r.status === "VALIDATED" &&
        req.user.region === r.region &&
        hasSufficientClearance(req.user.clearanceLevel, r.sensitivity)
    ).map(enrichEvidence);

    res.json(validated);
});

// View SUBMITTED Evidence
app.get('/api/pending/report', verifyToken, requireApiAudience, requireActiveToken, requireAnyRole(['audit-analyst', 'automated-validator']), (req, res) => {
    const roles = req.user.realm_access?.roles || [];

    // Machine/service path: automated validator
    if (roles.includes('automated-validator')) {
        if (!isVerifierServiceRequest(req)) {
            return denyAbac(res, "Automated-validator access must come from the automated audit validator service.");
        }

        const submitted = evidenceItems.filter(r => r.status === "SUBMITTED").map(enrichEvidence);
        return res.json(submitted);
    }

    // Human path: audit analyst
    if (roles.includes('audit-analyst')) {
        if (!isFrontendRequest(req)) {
            return denyAbac(res, "Analyst submitted evidence access must come from the audit dashboard.");
        }

        const submitted = evidenceItems.filter(r =>
            r.status === "SUBMITTED" &&
            req.user.region === r.region &&
            hasSufficientClearance(req.user.clearanceLevel, r.sensitivity)
        ).map(enrichEvidence);

        return res.json(submitted);
    }

    return denyAbac(res, "No valid ABAC path for submitted evidence access.");
});

// View ALL Evidence
app.get('/api/all/report', verifyToken, requireApiAudience, requireActiveToken, requireAnyRole(['audit-manager']), (req, res) => {
    if (req.user.department !== "cybersecurity-audit") {
        return denyAbac(res, "Only authorized GRC Lab team members can view all audit evidence.");
    }

    if (req.user.clearanceLevel !== "high") {
        return denyAbac(res, "High clearance is required to view all evidence states.");
    }

    if (!isFrontendRequest(req)) {
        return denyAbac(res, "All-evidence access must come from the audit dashboard.");
    }

    const scopedEvidence = evidenceItems.filter(r => req.user.region === r.region).map(enrichEvidence);
    res.json(scopedEvidence);
});

// Manager Acceptance Endpoint (Status VALIDATED -> ACCEPTED)
app.patch('/api/approve/report/:reportID', verifyToken, requireApiAudience, requireActiveToken, requireAnyRole(['audit-manager']), async (req, res) => {
    const evidenceIndex = evidenceItems.findIndex(r => r.id === req.params.reportID);

    if (evidenceIndex === -1) {
        return res.status(404).json({ error: "Evidence not found." });
    }

    const evidence = evidenceItems[evidenceIndex];
    const requestSource = getRequestSource(req);

    if (evidence.author === req.user.preferred_username) {
        return denyAbac(res, "A manager cannot accept evidence they authored.");
    }
    if (evidence.validated_by === req.user.preferred_username) {
        return denyAbac(res, "A user cannot validate and accept the same evidence.");
    }

    // Resource attribute check: only VALIDATED evidence can be accepted
    if (evidence.status !== "VALIDATED") {
        return denyAbac(res, "Only VALIDATED evidence can be accepted.");
    }

    // Subject attribute check: user must belong to the configured audit department
    if (req.user.department !== "cybersecurity-audit") {
        return denyAbac(res, "User department is not allowed to accept audit evidence.");
    }

    // Subject + Resource attribute check: user clearance must match evidence sensitivity
    if (!hasSufficientClearance(req.user.clearanceLevel, evidence.sensitivity)) {
        return denyAbac(res, "User clearance level is not sufficient for this evidence sensitivity.");
    }

    // Subject + Resource attribute check: user region must match evidence region
    if (req.user.region !== evidence.region) {
        return denyAbac(res, "User region does not match the evidence region.");
    }

    // Environment attribute check: acceptance must come from the human frontend client
    if (!isFrontendRequest(req)) {
        return denyAbac(res, "Acceptance must come from the audit dashboard, not from a service client.");
    }

    // Environment attribute check: acceptance requires successful OTP/MFA evidence
    if (!hasMfa(req)) {
        return denyAbac(res, "MFA/OTP is required before accepting audit evidence.");
    }

    // Risk-based access check: suspicious login behaviour can block acceptance
    const risk = await calculateAcceptanceRisk(req, evidence);

    if (risk.decision === "DENY") {
        return res.status(403).json({
            error: "High risk acceptance denied",
            riskDecision: "Denied by risk-based access control",
            riskScore: risk.riskScore,
            riskFactors: risk.riskFactors
        });
    }

    evidence.status = "ACCEPTED";
    evidence.accepted_by = req.user.preferred_username;
    evidence.accepted_date = new Date().toISOString();
    const evidenceRequestClosed = closeEvidenceRequestIfComplete(evidence.evidence_request_id);

    res.json({
        message: `Evidence ${req.params.reportID} successfully ACCEPTED by ${req.user.preferred_username}.`,
        evidence: enrichEvidence(evidence),
        evidenceRequestClosed: evidenceRequestClosed,
        abacDecision: "Allowed by hybrid RBAC + ABAC policy",
        checkedAttributes: {
            department: req.user.department,
            clearanceLevel: req.user.clearanceLevel,
            userRegion: req.user.region,
            evidenceSensitivity: evidence.sensitivity,
            evidenceRegion: evidence.region,
            requestSource: requestSource,
            mfaVerified: hasMfa(req),
            evidenceStatusBeforeAcceptance: "VALIDATED"
        },
        riskDecision: "Allowed by risk-based access control",
        riskScore: risk.riskScore,
        riskFactors: risk.riskFactors
    });
});

// Script Validation Endpoint (Status SUBMITTED -> VALIDATED)
app.patch('/api/system/verify/:reportID', verifyToken, requireApiAudience, requireActiveToken, requireAnyRole(['automated-validator']), async (req, res) => {
    const evidence = evidenceItems.find(item => item.id === req.params.reportID);
    if (!evidence) {
        return res.status(404).json({ error: "Evidence not found." });
    }

    const requestSource = getRequestSource(req);

    // Environment attribute check: validation must come from the automated service client
    if (!isVerifierServiceRequest(req)) {
        return denyAbac(res, "Validation must come from the automated audit validator service.");
    }

    // Resource attribute check: only SUBMITTED evidence can be validated
    if (evidence.status !== "SUBMITTED") {
        return denyAbac(res, "Only SUBMITTED evidence can be validated by the automated service.");
    }

    const attemptedDate = new Date().toISOString();
    const storedFilename = path.basename(evidence.filename || "");
    const evidencePath = path.resolve(uploadDir, storedFilename);
    const uploadsRoot = path.resolve(uploadDir) + path.sep;

    evidence.validation_attempted_date = attemptedDate;

    if (
        !storedFilename ||
        storedFilename !== evidence.filename ||
        !evidencePath.startsWith(uploadsRoot)
    ) {
        evidence.validation_output = "";
        evidence.validation_error = "Invalid stored evidence filename.";
        evidence.validation_exit_status = null;
        evidence.validation_signal = null;

        return res.status(400).json({
            error: "Invalid stored evidence filename.",
            evidence: enrichEvidence(evidence)
        });
    }

    if (path.extname(storedFilename).toLowerCase() !== ".sh") {
        evidence.validation_output = "";
        evidence.validation_error = "Automated Phase 1 validation supports only .sh files.";
        evidence.validation_exit_status = null;
        evidence.validation_signal = null;

        return res.status(422).json({
            error: evidence.validation_error,
            evidence: enrichEvidence(evidence)
        });
    }

    try {
        const stats = await fs.promises.stat(evidencePath);
        if (!stats.isFile()) {
            throw new Error("Resolved evidence path is not a regular file.");
        }
    } catch (error) {
        evidence.validation_output = "";
        evidence.validation_error = error.message;
        evidence.validation_exit_status = null;
        evidence.validation_signal = null;

        return res.status(404).json({
            error: "Uploaded evidence file is unavailable.",
            reason: error.message,
            evidence: enrichEvidence(evidence)
        });
    }

    const execution = await new Promise(resolve => {
        execFile(
            "/bin/sh",
            [evidencePath],
            {
                cwd: uploadDir,
                timeout: 30_000,
                maxBuffer: 1024 * 1024,
                shell: false,
                env: {
                    PATH: "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
                }
            },
            (error, stdout, stderr) => {
                resolve({ error, stdout, stderr });
            }
        );
    });

    const exitStatus = execution.error
        ? execution.error.killed
            ? 124
            : Number.isInteger(execution.error.code)
                ? execution.error.code
                : 1
        : 0;

    evidence.validation_output = execution.stdout || "";
    evidence.validation_error = execution.stderr || (execution.error ? execution.error.message : "");
    evidence.validation_exit_status = exitStatus;
    evidence.validation_signal = execution.error?.signal || null;

    if (exitStatus !== 0) {
        return res.status(422).json({
            message: `Automated validation failed for evidence ${evidence.id}.`,
            evidence: enrichEvidence(evidence),
            execution: {
                exitStatus: exitStatus,
                signal: evidence.validation_signal,
                stdout: evidence.validation_output,
                stderr: evidence.validation_error
            }
        });
    }

    evidence.status = "VALIDATED";
    evidence.validated_by = req.user.preferred_username || "audit-validator-client";
    evidence.validated_date = attemptedDate;
    evidence.review_note = "Validated by automated compliance script.";
    markAuditItemInReview(evidence.audit_item_id);

    return res.json({
        message: `Evidence ${evidence.id} successfully VALIDATED by automated compliance script.`,
        evidence: enrichEvidence(evidence),
        execution: {
            exitStatus: exitStatus,
            signal: null,
            stdout: evidence.validation_output,
            stderr: evidence.validation_error
        },
        abacDecision: "Allowed by hybrid RBAC + ABAC policy",
        checkedAttributes: {
            requestSource: requestSource,
            evidenceStatusBeforeValidation: "SUBMITTED",
            evidenceSensitivity: evidence.sensitivity,
            evidenceRegion: evidence.region
        }
    });
});

// Analyst Validation Endpoint (Status SUBMITTED -> VALIDATED)
app.patch('/api/analyst/validate/:reportID', verifyToken, requireApiAudience, requireActiveToken, requireAnyRole(['audit-analyst']), (req, res) => {
    const evidenceIndex = evidenceItems.findIndex(r => r.id === req.params.reportID);
    if (evidenceIndex === -1) return res.status(404).json({ error: "Evidence not found." });

    const evidence = evidenceItems[evidenceIndex];
    const requestSource = getRequestSource(req);

    if (evidence.author === req.user.preferred_username) {
        return denyAbac(res, "An evidence author cannot validate their own evidence.");
    }
    if (evidence.status !== "SUBMITTED") {
        return denyAbac(res, "Only SUBMITTED evidence can be validated by an audit analyst.");
    }
    if (!isFrontendRequest(req)) {
        return denyAbac(res, "Analyst validation must come from the audit dashboard.");
    }
    if (req.user.region !== evidence.region) {
        return denyAbac(res, "Analyst region does not match the evidence region.");
    }
    if (!hasSufficientClearance(req.user.clearanceLevel, evidence.sensitivity)) {
        return denyAbac(res, "Analyst clearance level is not sufficient for this evidence sensitivity.");
    }

    const reviewNote = typeof req.body?.review_note === "string" ? req.body.review_note.trim() : "";

    evidence.status = "VALIDATED";
    evidence.validated_by = req.user.preferred_username;
    evidence.validated_date = new Date().toISOString();
    evidence.review_note = reviewNote;
    markAuditItemInReview(evidence.audit_item_id);

    res.json({
        message: `Evidence ${req.params.reportID} successfully VALIDATED by ${req.user.preferred_username}.`,
        evidence: enrichEvidence(evidence),
        abacDecision: "Allowed by hybrid RBAC + ABAC policy",
        checkedAttributes: {
            clearanceLevel: req.user.clearanceLevel,
            userRegion: req.user.region,
            evidenceSensitivity: evidence.sensitivity,
            evidenceRegion: evidence.region,
            requestSource: requestSource,
            evidenceStatusBeforeValidation: "SUBMITTED"
        }
    });
});

app.listen(PORT, () => console.log(`Cyber Audit API running on http://localhost:${PORT}`));
