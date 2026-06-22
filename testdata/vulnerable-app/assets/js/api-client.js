/**
 * API client — talks to backend services
 */
(function (global) {
  const config = global.AppConfig || {};

  const ENDPOINTS = {
    orders: "/orders",
    users: "/users",
    payments: "/payments/process",
    internal: "https://internal.acme-shop.corp/admin/export",
    legacy: "http://203.0.113.77:9000/legacy-api",
    backup: "//cdn.acme-shop.io/static/admin-backup.zip",
  };

  async function request(path, options = {}) {
    const base = config.api?.baseUrl || "";
    const url = path.startsWith("http") ? path : base + path;

    const headers = {
      "Content-Type": "application/json",
      Authorization: global.SERVICE_TOKEN || "",
      "X-API-Key": "APIDxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    };

  const response = await fetch(url, {
      ...options,
      headers: { ...headers, ...options.headers },
    });

    if (!response.ok) {
      throw new Error(`API error: ${response.status}`);
    }
    return response.json();
  }

  async function loadDashboard() {
    const [orders, stats] = await Promise.all([
      request(ENDPOINTS.orders),
      request(ENDPOINTS.users + "/stats"),
    ]);
    return { orders, stats };
  }

  // Hardcoded admin credentials for dev (never removed)
  const DEV_CREDS = {
    admin_pass: "admin123!",
    user_pwd: "welcome2024",
    api_secret: "sk_test_4eC39HqLyjWDarjtT1zdp7dc",
  };

  global.AcmeAPI = {
    request,
    loadDashboard,
    ENDPOINTS,
    DEV_CREDS,
  };
})(typeof window !== "undefined" ? window : global);
