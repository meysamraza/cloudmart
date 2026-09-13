// =============================================================================
// CloudMart — app.js (Frontend Controller - Minimal Aesthetic Accents)
// =============================================================================

const token = localStorage.getItem("token");
let currentUser = null;

try {
  currentUser = JSON.parse(localStorage.getItem("user") || "null");
} catch (e) {
  currentUser = null;
}

// Redirect unauthenticated visitors to login page
if (!token && window.location.pathname !== "/login") {
  window.location.href = "/login";
}

// Ensure cookie is in sync with localStorage for direct browser address bar navigation
if (token) {
  document.cookie = `token=${token}; path=/; max-age=86400`;
}

// Helper: standard fetch wrapper with JWT Authorization header
async function apiFetch(url, options = {}) {
  const headers = {
    "Authorization": `Bearer ${token}`,
    "Content-Type": "application/json",
    ...(options.headers || {})
  };

  const response = await fetch(url, { ...options, headers });
  
  if (response.status === 401 && !url.includes("/login")) {
    showFlash("Session expired. Please log in again.", "error");
    setTimeout(() => {
      logout();
    }, 1500);
  }

  return response;
}

// Notification flash banner
function showFlash(message, type = "success") {
  const banner = document.getElementById("flash-banner");
  if (!banner) return;
  banner.textContent = message;
  banner.className = `flash-banner flash-${type}`;
  setTimeout(() => {
    banner.className = "flash-banner hidden";
  }, 3500);
}

// Logout handler
function logout() {
  localStorage.removeItem("token");
  localStorage.removeItem("user");
  document.cookie = "token=; path=/; max-age=0";
  window.location.href = "/login";
}

// =============================================================================
// UI INITIALIZATION
// =============================================================================

document.addEventListener("DOMContentLoaded", () => {
  // Populate user profile info in navbar
  if (currentUser) {
    const usernameEl = document.getElementById("current-username");
    const roleEl = document.getElementById("current-role");
    if (usernameEl) usernameEl.textContent = currentUser.username;
    if (roleEl) roleEl.textContent = currentUser.role;
  }

  // Logout button
  const logoutBtn = document.getElementById("logout-btn");
  if (logoutBtn) {
    logoutBtn.addEventListener("click", logout);
  }

  // Search form
  const searchForm = document.getElementById("search-form");
  const searchInput = document.getElementById("search-input");
  const searchReset = document.getElementById("search-reset");

  if (searchForm) {
    searchForm.addEventListener("submit", (e) => {
      e.preventDefault();
      searchProducts(searchInput.value.trim());
    });
  }

  if (searchReset) {
    searchReset.addEventListener("click", () => {
      searchInput.value = "";
      const feedback = document.getElementById("search-feedback");
      if (feedback) feedback.className = "search-feedback hidden";
      loadProducts();
    });
  }

  // Admin users check modal
  const adminBtn = document.getElementById("admin-check-btn");
  const adminModal = document.getElementById("admin-modal");
  const closeModalBtn = document.getElementById("close-modal");

  if (adminBtn) {
    adminBtn.addEventListener("click", openAdminUsersModal);
  }

  if (closeModalBtn) {
    closeModalBtn.addEventListener("click", () => {
      if (adminModal) adminModal.classList.add("hidden");
    });
  }

  if (adminModal) {
    adminModal.addEventListener("click", (e) => {
      if (e.target === adminModal) adminModal.classList.add("hidden");
    });
  }

  // Initial data loading
  loadProducts();
  loadOrders();

  // Start polling live request log every 2 seconds
  loadRequestLog();
  setInterval(loadRequestLog, 2000);
});


// =============================================================================
// PRODUCT CATALOG & SEARCH
// =============================================================================

async function loadProducts() {
  const container = document.getElementById("product-list");
  if (!container) return;

  try {
    const res = await fetch("/products");
    const products = await res.json();
    renderProducts(products);
  } catch (err) {
    container.innerHTML = `<div class="text-muted">Failed to load catalog: ${escapeHtml(err.message)}</div>`;
  }
}

async function searchProducts(query) {
  const container = document.getElementById("product-list");
  const feedback = document.getElementById("search-feedback");
  if (!container) return;

  container.innerHTML = `<div class="text-muted">Executing search...</div>`;

  try {
    const res = await fetch(`/products/search?q=${encodeURIComponent(query)}`);
    const data = await res.json();

    if (!res.ok) {
      // VULN: Backend leaks raw SQL error details (CWE-209)
      feedback.className = "search-feedback search-error";
      feedback.innerHTML = `
        Database Error: ${escapeHtml(data.details || data.error)}<br>
        <code>${escapeHtml(data.executed_query || '')}</code>
      `;
      container.innerHTML = `<div class="text-muted">No products returned due to SQL error.</div>`;
      return;
    }

    // Success response
    feedback.className = "search-feedback";
    feedback.innerHTML = `Results for "<code>${escapeHtml(query)}</code>" (${data.length} found):`;
    renderProducts(data);
  } catch (err) {
    container.innerHTML = `<div class="text-muted">Search failed: ${escapeHtml(err.message)}</div>`;
  }
}

function renderProducts(products) {
  const container = document.getElementById("product-list");
  if (!container) return;

  if (!products || products.length === 0) {
    container.innerHTML = `<div class="text-muted" style="grid-column: 1 / -1; padding: 12px 0;">No products found.</div>`;
    return;
  }

  container.innerHTML = products.map(prod => `
    <div class="product-card">
      <div>
        <h3 class="product-title">${escapeHtml(prod.name || 'Custom Result')}</h3>
        <p class="product-desc">${escapeHtml(prod.description || (prod.password ? `Password: ${prod.password}` : ''))}</p>
      </div>
      <div class="product-footer">
        <span class="product-price">$${Number(prod.price || 0).toFixed(2)}</span>
        <button class="btn btn-primary btn-sm" onclick="buyProduct(${prod.id}, '${escapeHtml(prod.name)}')">
          Order
        </button>
      </div>
    </div>
  `).join("");
}

// Purchase product (calls POST /orders)
async function buyProduct(productId, productName) {
  try {
    const res = await apiFetch("/orders", {
      method: "POST",
      body: JSON.stringify({ product_id: productId, quantity: 1 })
    });

    const data = await res.json();
    if (res.ok) {
      showFlash(`Created Order #${data.order.id} for "${productName}"`, "success");
      loadOrders();
    } else {
      showFlash(data.error || "Failed to create order", "error");
    }
  } catch (err) {
    showFlash(`Order failed: ${err.message}`, "error");
  }
}


// =============================================================================
// MY ORDERS (BOLA / IDOR DEMO)
// =============================================================================

async function loadOrders() {
  const tbody = document.getElementById("orders-tbody");
  if (!tbody) return;

  try {
    const res = await apiFetch("/orders");
    if (!res.ok) return;

    const orders = await res.json();

    if (orders.length === 0) {
      tbody.innerHTML = `<tr><td colspan="5" class="text-muted">No orders yet. Click "Order" on any product above.</td></tr>`;
      return;
    }

    tbody.innerHTML = orders.map(ord => {
      const isDelivered = ord.status === "Delivered";
      return `
        <tr>
          <td>#${ord.id}</td>
          <td>${escapeHtml(ord.product_name)}</td>
          <td>${ord.quantity}</td>
          <td class="${isDelivered ? 'status-2xx' : ''}">${ord.status}</td>
          <td>
            <a href="/orders/${ord.id}" target="_blank">
              /orders/${ord.id}
            </a>
          </td>
        </tr>
      `;
    }).join("");
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="5" class="text-muted">Failed to load orders.</td></tr>`;
  }
}


// =============================================================================
// ADMIN USERS (BROKEN FUNCTION-LEVEL AUTHORIZATION)
// =============================================================================

async function openAdminUsersModal() {
  const modal = document.getElementById("admin-modal");
  const tbody = document.getElementById("admin-users-tbody");

  if (!modal || !tbody) return;

  modal.classList.remove("hidden");
  tbody.innerHTML = `<tr><td colspan="5" class="text-muted">Loading GET /admin/users...</td></tr>`;

  try {
    const res = await apiFetch("/admin/users");
    const users = await res.json();

    if (!res.ok) {
      tbody.innerHTML = `<tr><td colspan="5" class="status-err">${escapeHtml(users.error || "Request failed")}</td></tr>`;
      return;
    }

    tbody.innerHTML = users.map(u => `
      <tr>
        <td>${u.id}</td>
        <td><strong>${escapeHtml(u.username)}</strong></td>
        <td>${escapeHtml(u.email)}</td>
        <td class="status-err">${escapeHtml(u.password)}</td>
        <td>${escapeHtml(u.role)}</td>
      </tr>
    `).join("");
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="5" class="status-err">${escapeHtml(err.message)}</td></tr>`;
  }
}


// =============================================================================
// LIVE REQUEST LOG (POLLING GET /api/request-log)
// =============================================================================

async function loadRequestLog() {
  const tbody = document.getElementById("request-log-tbody");
  if (!tbody) return;

  try {
    const res = await fetch("/api/request-log");
    if (!res.ok) return;

    const logs = await res.json();

    if (!logs || logs.length === 0) {
      tbody.innerHTML = `<tr><td colspan="4" class="text-muted">No recent requests.</td></tr>`;
      return;
    }

    tbody.innerHTML = logs.map(entry => {
      let statusClass = "status-2xx";
      if (entry.status_code >= 200 && entry.status_code < 300) {
        statusClass = "status-2xx";
      } else if (entry.status_code >= 300 && entry.status_code < 400) {
        statusClass = "status-3xx";
      } else {
        statusClass = "status-err";
      }

      return `
        <tr>
          <td>${entry.timestamp}</td>
          <td>${entry.method}</td>
          <td><code>${escapeHtml(entry.endpoint)}</code></td>
          <td class="${statusClass}">${entry.status_code}</td>
        </tr>
      `;
    }).join("");
  } catch (err) {
    // Fail silently on poll error
  }
}


// =============================================================================
// UTILITIES
// =============================================================================

function escapeHtml(str) {
  if (str === null || str === undefined) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
