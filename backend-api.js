const express = require('express');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const multer = require('multer');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(cors());
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

// Simulated Database with Resource Attributes
let evidenceItems = [
    {
        id: "EVD-001",
        author: "alice",
        filename: "evidence1.txt",
        date: "2026-03-02T17:15:00.000Z",
        status: "ACCEPTED",
        sensitivity: "low",
        region: "AU",
        accepted_date: "2026-03-02T17:20:00.000Z",
        accepted_by: "MANAGER"
    },
    {
        id: "EVD-002",
        author: "bob",
        filename: "evidence2.txt",
        date: "2026-04-05T17:15:00.000Z",
        status: "SUBMITTED",
        sensitivity: "high",
        region: "AU",
        accepted_date: "",
        accepted_by: ""
    },
    {
        id: "EVD-003",
        author: "alice",
        filename: "evidence3.txt",
        date: "2026-01-06T17:15:00.000Z",
        status: "VALIDATED",
        sensitivity: "high",
        region: "AU",
        accepted_date: "",
        accepted_by: ""
    }
];

// --- Middleware ---
const verifyToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(401).json({ error: 'No token provided' });

    const token = authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Malformed token' });
    
    const decoded = jwt.decode(token);
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
  return getRequestSource(req) === "finance-portal-spa";
}

function isVerifierServiceRequest(req) {
  return getRequestSource(req) === "report-verifier-client";
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

function hasRequiredAudience(req) {
  const aud = req.user.aud;

  if (Array.isArray(aud)) {
    return aud.includes("financial-reporting-api");
  }

  return aud === "financial-reporting-api";
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
const KEYCLOAK_INTROSPECTION_URL = "http://192.168.30.10:8080/realms/secure-finance/protocol/openid-connect/token/introspect";
const INTROSPECTION_CLIENT_ID = "report-verifier-client";

async function introspectAccessToken(token) {
  const clientSecret = process.env.REPORT_VERIFIER_CLIENT_SECRET;

  if (!clientSecret) {
    throw new Error("Missing REPORT_VERIFIER_CLIENT_SECRET environment variable.");
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
const KEYCLOAK_ADMIN_TOKEN_URL = "http://192.168.30.10:8080/realms/master/protocol/openid-connect/token";
const KEYCLOAK_ADMIN_USERS_URL = "http://192.168.30.10:8080/admin/realms/secure-finance/users";
const KEYCLOAK_EVENTS_URL = "http://192.168.30.10:8080/admin/realms/secure-finance/events";
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

// Upload Endpoint (Status becomes SUBMITTED)
app.post('/api/upload/report', verifyToken, requireApiAudience, requireAnyRole(['accountant', 'finance-manager']), upload.single('reportDoc'), (req, res) => {
  const requestSource = getRequestSource(req);

  // Subject attribute check: only finance department users can upload audit evidence
  if (req.user.department !== "finance") {
    return denyAbac(res, "Only authorized GRC Lab team members can upload audit evidence.");
  }

  // Environment attribute check: upload must come from the human frontend
  if (!isFrontendRequest(req)) {
    return denyAbac(res, "Evidence upload must come from the audit dashboard.");
  }

  if (!req.file) return res.status(400).json({ error: "No file was uploaded." });

  const newEvidence = {
        id: `EVD-${String(evidenceItems.length + 1).padStart(3, '0')}`,
        author: req.user.preferred_username,
        filename: req.file.filename,
        date: new Date().toISOString(),
        status: "SUBMITTED",
        sensitivity: "medium",
        region: req.user.region || "AU",
        accepted_date: "",
        accepted_by: ""
  };

  evidenceItems.push(newEvidence);

  res.json({
      message: "Success! Audit evidence uploaded securely and is SUBMITTED for validation.",
      abacDecision: "Allowed by hybrid RBAC + ABAC policy",
      checkedAttributes: {
          department: req.user.department,
          userRegion: req.user.region,
          evidenceRegion: newEvidence.region,
          evidenceSensitivity: newEvidence.sensitivity,
          requestSource: requestSource,
          evidenceStatus: newEvidence.status
      }
  });
});

// View ACCEPTED Evidence
app.get('/api/view/report', verifyToken, requireApiAudience, requireAnyRole(['accountant', 'finance-manager', 'analyst', 'auditor', 'department-head']), (req, res) => {
    const accepted = evidenceItems.filter(r =>
        r.status === "ACCEPTED" &&
        (!r.region || req.user.region === r.region)
    );

    res.json(accepted);
});

// View VALIDATED Evidence
app.get('/api/verified/report', verifyToken, requireApiAudience, requireActiveToken, requireAnyRole(['finance-manager']), (req, res) => {
    if (req.user.department !== "finance") {
        return denyAbac(res, "Only authorized GRC Lab team members can view validated audit evidence.");
    }

    if (!isFrontendRequest(req)) {
        return denyAbac(res, "Validated evidence must be viewed through the audit dashboard.");
    }

    const validated = evidenceItems.filter(r =>
        r.status === "VALIDATED" &&
        req.user.region === r.region &&
        hasSufficientClearance(req.user.clearanceLevel, r.sensitivity)
    );

    res.json(validated);
});

// View SUBMITTED Evidence
app.get('/api/pending/report', verifyToken, requireApiAudience, requireActiveToken, requireAnyRole(['finance-manager','system-auditor']), (req, res) => {
    const roles = req.user.realm_access?.roles || [];

    // Machine/service path: automated validator
    if (roles.includes('system-auditor')) {
        if (!isVerifierServiceRequest(req)) {
            return denyAbac(res, "System-auditor access must come from the automated audit verifier service.");
        }

        const submitted = evidenceItems.filter(r => r.status === "SUBMITTED");
        return res.json(submitted);
    }

    // Human path: finance manager
    if (roles.includes('finance-manager')) {
        if (req.user.department !== "finance") {
            return denyAbac(res, "Only authorized GRC Lab team members can view submitted audit evidence.");
        }

        if (!isFrontendRequest(req)) {
            return denyAbac(res, "Manager submitted evidence access must come from the audit dashboard.");
        }

        const submitted = evidenceItems.filter(r =>
            r.status === "SUBMITTED" &&
            req.user.region === r.region &&
            hasSufficientClearance(req.user.clearanceLevel, r.sensitivity)
        );

        return res.json(submitted);
    }

    return denyAbac(res, "No valid ABAC path for submitted evidence access.");
});

// View ALL Evidence
app.get('/api/all/report', verifyToken, requireApiAudience, requireActiveToken, requireAnyRole(['finance-manager']), (req, res) => {
    if (req.user.department !== "finance") {
        return denyAbac(res, "Only authorized GRC Lab team members can view all audit evidence.");
    }

    if (req.user.clearanceLevel !== "high") {
        return denyAbac(res, "High clearance is required to view all evidence states.");
    }

    if (!isFrontendRequest(req)) {
        return denyAbac(res, "All-evidence access must come from the audit dashboard.");
    }

    const scopedEvidence = evidenceItems.filter(r => req.user.region === r.region);
    res.json(scopedEvidence);
});

// Manager Acceptance Endpoint (Status VALIDATED -> ACCEPTED)
app.patch('/api/approve/report/:reportID', verifyToken, requireApiAudience, requireActiveToken, requireAnyRole(['finance-manager']), async (req, res) => {
    const evidenceIndex = evidenceItems.findIndex(r => r.id === req.params.reportID);

    if (evidenceIndex === -1) {
        return res.status(404).json({ error: "Evidence not found." });
    }

    const evidence = evidenceItems[evidenceIndex];
    const requestSource = getRequestSource(req);

    // Resource attribute check: only VALIDATED evidence can be accepted
    if (evidence.status !== "VALIDATED") {
        return denyAbac(res, "Only VALIDATED evidence can be accepted.");
    }

    // Subject attribute check: user must belong to the finance department
    if (req.user.department !== "finance") {
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

    res.json({
        message: `Evidence ${req.params.reportID} successfully ACCEPTED by ${req.user.preferred_username}.`,
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
app.patch('/api/system/verify/:reportID', verifyToken, requireApiAudience, requireActiveToken, requireAnyRole(['system-auditor']), (req, res) => {
    const evidenceIndex = evidenceItems.findIndex(r => r.id === req.params.reportID);
    if (evidenceIndex === -1) return res.status(404).json({ error: "Evidence not found." });

    const evidence = evidenceItems[evidenceIndex];
    const requestSource = getRequestSource(req);

    // Environment attribute check: validation must come from the automated service client
    if (!isVerifierServiceRequest(req)) {
        return denyAbac(res, "Validation must come from the automated audit verifier service.");
    }

    // Resource attribute check: only SUBMITTED evidence can be validated
    if (evidence.status !== "SUBMITTED") {
        return denyAbac(res, "Only SUBMITTED evidence can be validated by the automated service.");
    }

    evidence.status = "VALIDATED";

    res.json({
        message: `Evidence ${req.params.reportID} successfully VALIDATED by automated controls check.`,
        abacDecision: "Allowed by hybrid RBAC + ABAC policy",
        checkedAttributes: {
            requestSource: requestSource,
            evidenceStatusBeforeValidation: "SUBMITTED",
            evidenceSensitivity: evidence.sensitivity,
            evidenceRegion: evidence.region
        }
    });
});

app.listen(PORT, () => console.log(`Cyber Audit API running on http://localhost:${PORT}`));
