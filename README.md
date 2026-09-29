# AegisGap AI

**AegisGap AI** is a keyless, air-gapped, zero-trust edge-client Web Application Firewall (WAF) and SIEM engine designed to run entirely inside the user's browser context. It intercepts, sanitizes, and evaluates outbound AI prompts and inbound LLM replies locally—dropping threats before network egress occurs.

## 🚀 Core Execution Modes

### 1. Programmatic Check (Client API Integration)
Evaluate text payloads directly within your client runtime context using the native rule validation matrix.
```javascript
// Run a programmatic check manually
const evaluation = window.AISentinelCheck("Your prompt text here");
console.log(evaluation.allowed ? "Clean Payload" : "Blocked by WAF: " + evaluation.reason);
```

### 2. Local Proxy Guard (Interceptor Mode)
Hooks into global network entrypoints to inspect and intercept outgoing traffic bound for upstream AI providers (OpenAI, Anthropic, Gemini) right before it leaves the machine.
```javascript
// Initialize Global Interceptor Guard
AISentinel.guard();
```

### 3. Integrated Diagnostics & Self-Test
Runs the foundational rules catalogue against weaponized reverse shells and indirect injection strings to check browser/runtime environment capabilities.
```javascript
// Run the built-in validation framework
const suite = AISentinel.selfTest();
console.log("Diagnostic status:", suite.passed);
```

## 📋 Finding Policy Validation States

- **ALLOW:** Clean payload compliance check validation passed.
- **WARN:** Triggered minor sensitivity threshold metrics; payload passed but flagged in SIEM audit log.
- **BLOCK:** Direct structural threat confirmed. Dropped locally with a synthetic `403 Forbidden` network response.
## 🧪 Troubleshooting, Diagnostics & CI/CD Automation

AegisGap AI includes an offline validation framework and architectural diagnostics engine to ensure runtime security layers remain fully operational without generating external tracking overhead.

### 1. Manual Diagnostic Verification
Developers can execute a localized diagnostic run at any point within the client sandbox environment to verify rule matrix functionality, fetch interception layers, and data shielding states.

```javascript
if (window.AISentinel) {
  // Triggers the baseline evaluation test cycle internally
  const diagnosticReport = window.AISentinel.selfTest();
  
  if (diagnosticReport.passed) {
    console.log("✅ WAF operational. Target rule structures verified clean.");
  } else {
    console.warn("❌ Interception mismatch detected. Check environment storage parameters.");
  }
}
```

### 2. Automated Headless CI/CD Testing (Playwright / Puppeteer)
To prevent build configurations from bypassing security controls during deployment phases, integrate a headless browser assertion loop into your automated integration testing pipeline:

```javascript
import { test, expect } from '@playwright/test';

test('Security Baseline: Client WAF must drop weaponized payloads', async ({ page }) => {
  await page.goto('http://localhost:3000/app');
  
  // 1. Inject an active threat simulation payload string via console evaluation
  const runVerification = await page.evaluate(() => {
    return window.AISentinel.selfTest();
  });
  
  // 2. Assert that the core protection engine drops inputs cleanly
  expect(runVerification.passed).toBe(true);
});
```

### 3. Simulating Runtime Failures (Chaos Drills)
To verify your application's resiliency under stress, you can intentionally inject an artificial engine crash state. This allows you to test whether your network layer defaults to a lock down (`FAIL-SECURE`) or tracking fallback loop (`FAIL-OPEN`).

```javascript
// Triggers an intentional system engine fault to monitor application behavior
window.AISentinel.injectFault();

// Expected behavior under FAIL-SECURE: 
// Immediate drop of all outbound AI requests returning a localized: 
// 403 Forbidden [ai_sentinel_engine_fault]
```

---

## 🔒 Security Posture Disclaimer & Boundaries

AegisGap AI operates entirely within the client-side browser context—requiring **zero keys, zero cloud telemetry pipelines, and zero CDN latency hooks**. 

While local, edge-client enforcement provides an elite front-line filter to prevent unnecessary model API bills, prompt injection attacks, and client data exfiltration vectors, a determined attacker who retains native access to browser Developer Tools can bypass client-side restrictions. 

**Production Recommendation:** For defense-in-depth enforcement, always use a two-pass validation model. Import and execute the identical matching logic engine within your server-side endpoint controller layer (Layer D layout guidelines) to maintain an authoritative security perimeter.
