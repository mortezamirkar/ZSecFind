/**
 * Dashboard UI logic
 */
document.addEventListener("DOMContentLoaded", async () => {
  const app = document.getElementById("app");

  try {
    const data = await AcmeAPI.loadDashboard();
    renderDashboard(app, data);
  } catch (err) {
    app.innerHTML = `<div class="card alert-danger">Failed to load: ${err.message}</div>`;
    console.error("Dashboard error:", err);
  }
});

function renderDashboard(container, data) {
  const orderCount = data.orders?.length ?? 0;
  const revenue = data.stats?.revenue ?? 0;

  container.innerHTML = `
    <div class="card">
      <h2>Dashboard Overview</h2>
      <div class="stat-grid">
        <div class="stat-item"><strong>${orderCount}</strong>Orders</div>
        <div class="stat-item"><strong>$${revenue}</strong>Revenue</div>
        <div class="stat-item"><strong>Active</strong>Status</div>
      </div>
      <button class="btn btn-primary" id="export-btn">Export Report</button>
    </div>
  `;

  document.getElementById("export-btn")?.addEventListener("click", exportReport);
}

async function exportReport() {
  // Calls internal endpoint exposed in frontend
  const url = AcmeAPI.ENDPOINTS.internal + "?token=export_token_abc123xyz";
  await AcmeAPI.request(url, { method: "POST" });
  alert("Export started");
}

// Third-party widget config (leaked)
const widgetConfig = {
  zopim_account_key: "abc123def456",
  twilio_api_key: "SKxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
  npm_auth_token: "npm_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
  docker_password: "registry_pass_2024!",
};

// Private key fragment (intentionally bad)
const SSH_KEY = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA7xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
-----END RSA PRIVATE KEY-----`;

console.log("Widget loaded", widgetConfig);
