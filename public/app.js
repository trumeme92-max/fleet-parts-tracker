// app.js
let currentUser = null;
let authToken = localStorage.getItem("fleet_token");
let currentRepairParts = [];
let availableParts = [];
let currentVehicleId = null;
const API = window.location.origin;

document.addEventListener("DOMContentLoaded", function () {
  initEventListeners();
  if (authToken) validateToken();
});

function initEventListeners() {
  // Login
  document
    .getElementById("toggle-password")
    .addEventListener("click", togglePasswordVisibility);
  document
    .getElementById("login-username")
    .addEventListener("input", clearLoginErrors);
  document
    .getElementById("login-password")
    .addEventListener("input", clearLoginErrors);
  document.getElementById("login-form").addEventListener("submit", handleLogin);

  // Navigation
  document.querySelectorAll(".nav-item[data-page]").forEach((item) => {
    item.addEventListener("click", function () {
      navigateToPage(this.dataset.page, this);
    });
  });
  document.getElementById("nav-logout").addEventListener("click", logout);

  // Buttons
  document
    .getElementById("btn-add-part")
    .addEventListener("click", () => openModal("part-modal"));
  document.getElementById("btn-save-part").addEventListener("click", savePart);
  document
    .getElementById("btn-add-vehicle")
    .addEventListener("click", () => openModal("truck-modal"));
  document
    .getElementById("btn-save-truck")
    .addEventListener("click", saveTruck);
  document
    .getElementById("btn-add-user")
    .addEventListener("click", () => openModal("user-modal"));
  document.getElementById("btn-save-user").addEventListener("click", saveUser);
  document
    .getElementById("btn-log-repair")
    .addEventListener("click", () => openRepairModal());
  document
    .getElementById("btn-quick-repair")
    .addEventListener("click", quickRepair);
  document
    .getElementById("btn-save-repair")
    .addEventListener("click", saveRepair);
  document
    .getElementById("btn-add-part-to-repair")
    .addEventListener("click", addPartToRepair);
  document
    .getElementById("btn-back-to-fleet")
    .addEventListener("click", () => navigateToPage("fleet", null));

  // Modals close buttons
  document
    .querySelectorAll(".modal-close, .btn-secondary[data-modal]")
    .forEach((btn) => {
      btn.addEventListener("click", function () {
        closeModal(this.dataset.modal);
      });
    });

  // Labor inputs for calculation
  document.querySelectorAll(".labor-input").forEach((input) => {
    input.addEventListener("change", calculateRepairTotal);
  });

  // Tables delegation
  document
    .getElementById("parts-table")
    .addEventListener("click", handlePartsTableClick);
  document
    .getElementById("fleet-grid")
    .addEventListener("click", handleFleetGridClick);
  document
    .getElementById("repairs-list")
    .addEventListener("click", handleRepairsListClick);
  document
    .getElementById("users-table")
    .addEventListener("click", handleUsersTableClick);
  document
    .getElementById("top-vehicles-table")
    .addEventListener("click", handleTopVehiclesClick);

  // Keyboard
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      document
        .querySelectorAll(".modal-overlay")
        .forEach((m) => m.classList.remove("active"));
    }
  });
}

function handlePartsTableClick(e) {
  const btn = e.target.closest('button[data-action="delete-part"]');
  if (btn) {
    e.stopPropagation();
    deletePart(btn.dataset.id);
  }
}

function handleFleetGridClick(e) {
  const card = e.target.closest(".vehicle-card");
  const deleteBtn = e.target.closest('button[data-action="delete-truck"]');

  if (deleteBtn) {
    e.stopPropagation();
    deleteTruck(deleteBtn.dataset.id, deleteBtn.dataset.name);
  } else if (card) {
    viewVehicle(card.dataset.truckid);
  }
}

function handleTopVehiclesClick(e) {
  const row = e.target.closest("tr[data-truckid]");
  if (row) {
    viewVehicle(row.dataset.truckid);
  }
}

function handleRepairsListClick(e) {
  // Handle any repair item actions if needed
}

function handleUsersTableClick(e) {
  const toggleBtn = e.target.closest('button[data-action="toggle-user"]');
  const deleteBtn = e.target.closest('button[data-action="delete-user"]');

  if (toggleBtn) {
    toggleUser(toggleBtn.dataset.id, toggleBtn.dataset.active === "true");
  } else if (deleteBtn) {
    deleteUser(deleteBtn.dataset.id);
  }
}

async function handleLogin(e) {
  e.preventDefault();
  const username = document.getElementById("login-username").value;
  const password = document.getElementById("login-password").value;
  const loginButton = document.getElementById("login-button");

  clearLoginErrors();
  loginButton.disabled = true;
  loginButton.classList.add("btn-loading");
  const originalText = loginButton.innerHTML;
  loginButton.innerHTML = '<i class="fas fa-spinner"></i> Signing in...';

  try {
    const res = await fetch(`${API}/api/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });

    const data = await res.json();

    if (res.ok) {
      authToken = data.token;
      currentUser = data.user;
      localStorage.setItem("fleet_token", authToken);
      showApp();
    } else {
      document.getElementById("login-password").value = "";
      document.getElementById("login-password").focus();
      showLoginError(data.error || "Login failed");

      if (data.locked) {
        showLoginWarning(data.error);
        document.getElementById("login-attempts").classList.add("hidden");
      } else if (data.remainingAttempts !== undefined) {
        showLoginAttempts(data.remainingAttempts);
      }
    }
  } catch (e) {
    document.getElementById("login-password").value = "";
    showLoginError("Network error");
  } finally {
    loginButton.disabled = false;
    loginButton.classList.remove("btn-loading");
    loginButton.innerHTML = originalText;
  }
}

function togglePasswordVisibility() {
  const passwordInput = document.getElementById("login-password");
  const toggleBtn = document.getElementById("toggle-password");
  const icon = toggleBtn.querySelector("i");

  if (passwordInput.type === "password") {
    passwordInput.type = "text";
    icon.classList.remove("fa-eye");
    icon.classList.add("fa-eye-slash");
    toggleBtn.title = "Hide Password";
  } else {
    passwordInput.type = "password";
    icon.classList.remove("fa-eye-slash");
    icon.classList.add("fa-eye");
    toggleBtn.title = "Show Password";
  }
  passwordInput.focus();
}

function clearLoginErrors() {
  document.getElementById("login-error").classList.add("hidden");
  document.getElementById("login-warning").classList.add("hidden");
  document.getElementById("login-attempts").classList.add("hidden");
}

function showLoginError(msg) {
  const el = document.getElementById("login-error");
  document.getElementById("login-error-text").textContent = msg;
  el.classList.remove("hidden");
}

function showLoginWarning(msg) {
  const el = document.getElementById("login-warning");
  document.getElementById("login-warning-text").textContent = msg;
  el.classList.remove("hidden");
}

function showLoginAttempts(remaining) {
  const el = document.getElementById("login-attempts");
  const text = document.getElementById("attempts-text");

  if (remaining === 0) {
    text.textContent = "This is your last attempt before temporary lockout!";
    el.classList.add("danger");
  } else {
    text.textContent = `${remaining} login attempt${remaining !== 1 ? "s" : ""} remaining`;
    el.classList.remove("danger");
  }
  el.classList.remove("hidden");
}

async function validateToken() {
  try {
    const res = await fetch(`${API}/api/auth/me`, {
      headers: { Authorization: `Bearer ${authToken}` },
    });
    if (res.ok) {
      currentUser = await res.json();
      showApp();
    } else {
      logout();
    }
  } catch (e) {
    logout();
  }
}

function showApp() {
  document.getElementById("login-page").style.display = "none";
  document.getElementById("app-container").classList.add("active");

  document.getElementById("current-user-name").textContent =
    currentUser.name || currentUser.username;
  document.getElementById("user-avatar").textContent = (
    currentUser.name || currentUser.username
  )
    .charAt(0)
    .toUpperCase();

  const roleEl = document.getElementById("current-user-role");
  const roleIcon =
    currentUser.role === "admin"
      ? "fa-shield-alt"
      : currentUser.role === "mechanic"
        ? "fa-wrench"
        : currentUser.role === "driver"
          ? "fa-truck"
          : "fa-eye";
  roleEl.innerHTML = `<i class="fas ${roleIcon}"></i> ${currentUser.role}`;
  roleEl.className = `user-role role-${currentUser.role}`;

  setupRoleBasedAccess();
  loadDashboard();
}

function setupRoleBasedAccess() {
  const role = currentUser.role;
  if (role === "admin") {
    document
      .querySelectorAll(".admin-only")
      .forEach((el) => el.classList.remove("hidden"));
  }
  if (role === "admin" || role === "mechanic") {
    document
      .querySelectorAll(".mechanic-only")
      .forEach((el) => el.classList.remove("hidden"));
  }
  if (role === "driver" || role === "viewer") {
    document
      .querySelectorAll(".admin-only, .mechanic-only")
      .forEach((el) => el.classList.add("hidden"));
  }
}

function logout() {
  localStorage.removeItem("fleet_token");
  currentUser = null;
  authToken = null;
  location.reload();
}

async function api(url, opts = {}) {
  const res = await fetch(`${API}${url}`, {
    ...opts,
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${authToken}`,
      ...opts.headers,
    },
  });

  if (res.status === 401 || res.status === 403) {
    logout();
    return;
  }

  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.error || "API Error");
  }

  return res.json();
}

function navigateToPage(page, element) {
  document.querySelectorAll(".page").forEach((p) => p.classList.add("hidden"));
  const targetPage = document.getElementById(`page-${page}`);
  if (targetPage) targetPage.classList.remove("hidden");

  if (element && element.classList) {
    document
      .querySelectorAll(".nav-item")
      .forEach((n) => n.classList.remove("active"));
    element.classList.add("active");
  }

  if (page === "dashboard") loadDashboard();
  if (page === "parts") loadParts();
  if (page === "fleet") loadFleet();
  if (page === "repairs") loadRepairs();
  if (page === "users" && currentUser.role === "admin") loadUsers();
  if (page === "logs" && currentUser.role === "admin") loadLogs();
}

async function loadDashboard() {
  try {
    const stats = await api("/api/stats");
    document.getElementById("stat-total-parts").textContent = stats.totalParts;
    document.getElementById("stat-low-stock").textContent = stats.lowStock;
    document.getElementById("stat-fleet-size").textContent = stats.fleetSize;
    document.getElementById("stat-month-cost").textContent =
      "$" + Math.round(stats.monthCost).toLocaleString();

    const tbody = document.getElementById("top-vehicles-table");
    if (stats.topVehicles && stats.topVehicles.length) {
      tbody.innerHTML = stats.topVehicles
        .map(
          (v) => `
        <tr data-truckid="${v.truckId}" style="cursor: pointer;">
          <td><strong>${v.truckId}</strong><br><small style="color: var(--text-secondary);">${v.name}</small></td>
          <td><span class="badge badge-info"><i class="fas fa-wrench"></i> ${v.repairCount}</span></td>
          <td>$${Math.round(v.totalRepairCost * 0.7).toLocaleString()}</td>
          <td>$${Math.round(v.totalRepairCost * 0.3).toLocaleString()}</td>
          <td style="font-weight: bold; color: var(--danger);">$${Math.round(v.totalRepairCost).toLocaleString()}</td>
          <td><button class="btn btn-sm btn-secondary"><i class="fas fa-eye"></i> View</button></td>
        </tr>
      `,
        )
        .join("");
    } else {
      tbody.innerHTML =
        '<tr><td colspan="6" style="text-align: center;">No data available</td></tr>';
    }
  } catch (e) {
    console.error("Dashboard load error:", e);
  }
}

async function loadParts() {
  try {
    const parts = await api("/api/parts");
    availableParts = parts;
    const tbody = document.getElementById("parts-table");

    if (!parts || parts.length === 0) {
      tbody.innerHTML =
        '<tr><td colspan="8" style="text-align: center; padding: 2rem;">No parts in inventory</td></tr>';
      return;
    }

    tbody.innerHTML = parts
      .map((p) => {
        const low = p.quantity <= p.minStock;
        const stockIcon = low
          ? '<i class="fas fa-exclamation-triangle" style="color: var(--danger);"></i>'
          : p.quantity === 0
            ? '<i class="fas fa-times-circle" style="color: var(--danger);"></i>'
            : '<i class="fas fa-check-circle" style="color: var(--success);"></i>';
        return `
        <tr class="${low ? "low-stock" : ""}">
          <td><strong><i class="fas fa-cog" style="color: var(--primary); margin-right: 0.5rem;"></i>${p.partNumber}</strong></td>
          <td>${p.description}</td>
          <td><span class="badge badge-info">${p.category}</span></td>
          <td>${stockIcon} ${p.quantity}</td>
          <td>${p.minStock}</td>
          <td><i class="fas fa-map-marker-alt" style="color: var(--text-secondary);"></i> ${p.location || "-"}</td>
          <td>$${p.cost || 0}</td>
          <td>
            ${
              currentUser.role !== "driver" && currentUser.role !== "viewer"
                ? `<button class="btn btn-sm btn-danger" data-action="delete-part" data-id="${p._id}"><i class="fas fa-trash"></i></button>`
                : "-"
            }
          </td>
        </tr>
      `;
      })
      .join("");
  } catch (e) {
    console.error("Parts load error:", e);
    showAlert("Failed to load parts", "error");
  }
}

async function savePart() {
  const form = document.getElementById("part-form");
  const data = Object.fromEntries(new FormData(form));
  data.quantity = parseInt(data.quantity);
  data.minStock = parseInt(data.minStock);
  data.cost = parseFloat(data.cost) || 0;

  try {
    await api("/api/parts", { method: "POST", body: JSON.stringify(data) });
    closeModal("part-modal");
    form.reset();
    loadParts();
    loadDashboard();
    showAlert("Part added successfully!", "success");
  } catch (e) {
    showAlert(e.message, "error");
  }
}

async function deletePart(partId) {
  if (!confirm("Are you sure you want to delete this part?")) return;
  try {
    await api(`/api/parts/${partId}`, { method: "DELETE" });
    loadParts();
    loadDashboard();
    showAlert("Part deleted successfully!", "success");
  } catch (e) {
    showAlert("Failed to delete part: " + e.message, "error");
  }
}

async function loadFleet() {
  try {
    const trucks = await api("/api/trucks");
    const grid = document.getElementById("fleet-grid");

    if (!trucks || trucks.length === 0) {
      grid.innerHTML =
        '<div style="text-align: center; padding: 4rem; color: var(--text-secondary);"><i class="fas fa-truck" style="font-size: 3rem; margin-bottom: 1rem; opacity: 0.3;"></i><h3>No Vehicles</h3><p>Add your first vehicle to get started</p></div>';
      return;
    }

    grid.innerHTML = trucks
      .map((t) => {
        const typeIcon = t.type === "truck" ? "fa-truck-moving" : "fa-trailer";
        const statusColor =
          t.status === "active"
            ? "var(--success)"
            : t.status === "maintenance"
              ? "var(--warning)"
              : "var(--danger)";
        return `
        <div class="vehicle-card" data-truckid="${t.truckId}">
          <div class="vehicle-card-header">
            <div class="vehicle-type-icon"><i class="fas ${typeIcon}"></i></div>
            <div class="vehicle-id"><i class="fas fa-fingerprint"></i> ${t.truckId}</div>
            <div class="vehicle-name">${t.name}</div>
            <div class="vehicle-meta">
              ${t.year || ""} ${t.make || ""} ${t.model || ""}
              <span style="float: right; color: ${statusColor};">
                <i class="fas fa-circle" style="font-size: 0.5rem; vertical-align: middle; margin-right: 0.25rem;"></i>
                ${t.status}
              </span>
            </div>
          </div>
          <div class="vehicle-stats">
            <div class="vehicle-stat">
              <div class="vehicle-stat-value"><i class="fas fa-wrench" style="font-size: 1rem; color: var(--primary);"></i> ${t.repairCount || 0}</div>
              <div class="vehicle-stat-label">Repairs</div>
            </div>
            <div class="vehicle-stat">
              <div class="vehicle-stat-value danger">$${Math.round(t.totalRepairCost || 0).toLocaleString()}</div>
              <div class="vehicle-stat-label">Total Cost</div>
            </div>
          </div>
          ${
            currentUser.role === "admin"
              ? `
          <div style="padding: 0 1.5rem 1.5rem; text-align: right;">
            <button class="btn btn-sm btn-danger" data-action="delete-truck" data-id="${t._id}" data-name="${t.truckId}">
              <i class="fas fa-trash"></i> Delete
            </button>
          </div>`
              : ""
          }
        </div>
      `;
      })
      .join("");
  } catch (e) {
    console.error("Fleet load error:", e);
    showAlert("Failed to load fleet", "error");
  }
}

async function saveTruck() {
  const form = document.getElementById("truck-form");
  const data = Object.fromEntries(new FormData(form));
  try {
    await api("/api/trucks", { method: "POST", body: JSON.stringify(data) });
    closeModal("truck-modal");
    form.reset();
    loadFleet();
    loadDashboard();
    showAlert("Vehicle added successfully!", "success");
  } catch (e) {
    showAlert(e.message, "error");
  }
}

async function deleteTruck(truckId, truckName) {
  if (!confirm(`Delete ${truckName}? All history will be lost!`)) return;
  try {
    await api(`/api/trucks/${truckId}?force=true`, { method: "DELETE" });
    loadFleet();
    loadDashboard();
    showAlert("Vehicle deleted successfully!", "success");
  } catch (e) {
    showAlert("Failed to delete vehicle: " + e.message, "error");
  }
}

async function viewVehicle(truckId) {
  try {
    currentVehicleId = truckId;
    const stats = await api(`/api/vehicles/${truckId}/stats`);

    document
      .querySelectorAll(".page")
      .forEach((p) => p.classList.add("hidden"));
    document.getElementById("page-vehicle-detail").classList.remove("hidden");

    const typeIcon =
      stats.truck.type === "truck" ? "fa-truck-moving" : "fa-trailer";
    const content = document.getElementById("vehicle-detail-content");

    const repairsHtml =
      stats.repairs && stats.repairs.length > 0
        ? stats.repairs
            .map(
              (r) => `
      <tr>
        <td><i class="fas fa-calendar-day" style="color: var(--text-secondary);"></i> ${new Date(r.date).toLocaleDateString()}</td>
        <td>${r.issue}</td>
        <td><span class="badge badge-info"><i class="fas fa-cog"></i> ${r.partsUsed ? r.partsUsed.length : 0}</span></td>
        <td>$${Math.round(r.partsTotalCost || 0)}</td>
        <td>$${Math.round(r.laborCost || 0)}</td>
        <td style="font-weight: bold;">$${Math.round(r.totalCost || 0)}</td>
      </tr>
    `,
            )
            .join("")
        : '<tr><td colspan="6" style="text-align: center; padding: 2rem;">No repair history</td></tr>';

    content.innerHTML = `
      <div style="background: linear-gradient(135deg, #f8fafc 0%, #ffffff 100%); padding: 1.5rem; border-radius: var(--radius); margin-bottom: 2rem; border: 1px solid var(--border);">
        <div style="display: flex; align-items: center; gap: 1rem; margin-bottom: 1rem;">
          <div style="width: 64px; height: 64px; background: linear-gradient(135deg, var(--primary) 0%, #8b5cf6 100%); border-radius: 16px; display: flex; align-items: center; justify-content: center; color: white; font-size: 2rem;">
            <i class="fas ${typeIcon}"></i>
          </div>
          <div>
            <div style="font-size: 1.5rem; font-weight: 700; margin-bottom: 0.25rem;">${stats.truck.name}</div>
            <div style="color: var(--text-secondary); font-size: 0.9rem;">
              <span style="margin-right: 1rem;"><i class="fas fa-fingerprint"></i> ${stats.truck.truckId}</span>
              <span style="margin-right: 1rem;"><i class="fas fa-car-side"></i> ${stats.truck.type}</span>
              <span><i class="fas fa-circle" style="color: ${stats.truck.status === "active" ? "var(--success)" : "var(--warning)"}; font-size: 0.5rem;"></i> ${stats.truck.status}</span>
            </div>
          </div>
        </div>
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem; margin-top: 1.5rem; padding-top: 1.5rem; border-top: 1px solid var(--border);">
          <div style="text-align: center;">
            <div style="font-size: 1.5rem; font-weight: 700;">${stats.truck.repairCount || 0}</div>
            <div style="font-size: 0.875rem; color: var(--text-secondary);">Total Repairs</div>
          </div>
          <div style="text-align: center;">
            <div style="font-size: 1.5rem; font-weight: 700; color: var(--danger);">$${Math.round(stats.truck.totalPartsCost || 0).toLocaleString()}</div>
            <div style="font-size: 0.875rem; color: var(--text-secondary);">Parts Cost</div>
          </div>
          <div style="text-align: center;">
            <div style="font-size: 1.5rem; font-weight: 700; color: var(--warning);">$${Math.round(stats.truck.totalLaborCost || 0).toLocaleString()}</div>
            <div style="font-size: 0.875rem; color: var(--text-secondary);">Labor Cost</div>
          </div>
          <div style="text-align: center;">
            <div style="font-size: 2rem; font-weight: 700; color: var(--primary);">$${Math.round(stats.truck.totalRepairCost || 0).toLocaleString()}</div>
            <div style="font-size: 0.875rem; color: var(--text-secondary);">Total Spent</div>
          </div>
        </div>
      </div>

      <h2 style="font-size: 1.25rem; font-weight: 700; margin-bottom: 1rem; display: flex; align-items: center; gap: 0.5rem;">
        <i class="fas fa-history" style="color: var(--primary);"></i> Repair History
      </h2>
      <div class="card">
        <div class="table-container">
          <table>
            <thead>
              <tr>
                <th><i class="fas fa-calendar"></i> Date</th>
                <th><i class="fas fa-clipboard"></i> Issue</th>
                <th><i class="fas fa-boxes"></i> Parts</th>
                <th><i class="fas fa-dollar-sign"></i> Parts Cost</th>
                <th><i class="fas fa-user-clock"></i> Labor</th>
                <th><i class="fas fa-calculator"></i> Total</th>
              </tr>
            </thead>
            <tbody>${repairsHtml}</tbody>
          </table>
        </div>
      </div>
    `;
  } catch (e) {
    console.error("Vehicle detail error:", e);
    showAlert("Failed to load vehicle details", "error");
  }
}

function quickRepair() {
  if (currentVehicleId) openRepairModal(currentVehicleId);
  else openRepairModal();
}

async function loadRepairs() {
  try {
    const repairs = await api("/api/repairs");
    const container = document.getElementById("repairs-list");
    if (!repairs || !repairs.length) {
      container.innerHTML = `
        <div class="empty-state">
          <i class="fas fa-clipboard-check"></i>
          <h3>No Repairs Yet</h3>
          <p>Start by logging your first repair record</p>
          ${
            currentUser.role !== "driver" && currentUser.role !== "viewer"
              ? `<button class="btn btn-primary" id="btn-first-repair" style="margin-top: 1rem;"><i class="fas fa-plus"></i> Log Repair</button>`
              : ""
          }
        </div>`;
      const btn = document.getElementById("btn-first-repair");
      if (btn) btn.addEventListener("click", () => openRepairModal());
      return;
    }

    container.innerHTML = repairs
      .map((r) => {
        const partsHtml =
          r.partsUsed && r.partsUsed.length > 0
            ? `<div class="repair-parts-list">
        ${r.partsUsed.map((p) => `<span class="repair-part-tag"><i class="fas fa-cog"></i> ${p.partNumber} (x${p.quantity})</span>`).join("")}
      </div>`
            : "";

        return `
      <div class="repair-item">
        <div class="repair-header">
          <div class="repair-vehicle">
            <div class="repair-vehicle-icon"><i class="fas fa-truck"></i></div>
            <div>
              <div style="font-weight: 700; font-size: 1.125rem;">${r.truckName || r.truckId}</div>
              <div style="color: var(--text-secondary); font-size: 0.875rem;">
                <i class="fas fa-calendar-day"></i> ${new Date(r.date).toLocaleDateString()}
                ${r.mechanic ? `| <i class="fas fa-user"></i> ${r.mechanic}` : ""}
              </div>
            </div>
          </div>
          <div class="repair-cost"><i class="fas fa-dollar-sign" style="font-size: 1rem;"></i> ${Math.round(r.totalCost || 0)}</div>
        </div>
        <div style="margin-bottom: 0.5rem;"><strong><i class="fas fa-clipboard" style="color: var(--primary);"></i></strong> ${r.issue}</div>
        ${partsHtml}
        ${r.notes ? `<div style="margin-top: 0.75rem; padding-top: 0.75rem; border-top: 1px solid var(--border); color: var(--text-secondary); font-size: 0.875rem;"><i class="fas fa-sticky-note"></i> ${r.notes}</div>` : ""}
      </div>`;
      })
      .join("");
  } catch (e) {
    console.error("Repairs load error:", e);
  }
}

async function openRepairModal(preselectedTruckId = null) {
  try {
    currentRepairParts = [];
    updatePartsList();
    const [trucks, parts] = await Promise.all([
      api("/api/trucks"),
      api("/api/parts"),
    ]);
    availableParts = parts || [];

    const truckSelect = document.getElementById("repair-truck-select");
    const partSelect = document.getElementById("temp-part-select");

    truckSelect.innerHTML =
      '<option value="">Select Vehicle...</option>' +
      (trucks || [])
        .map(
          (t) =>
            `<option value="${t.truckId}" ${preselectedTruckId === t.truckId ? "selected" : ""}>${t.truckId} - ${t.name}</option>`,
        )
        .join("");

    partSelect.innerHTML =
      '<option value="">Select Part...</option>' +
      (parts || [])
        .filter((p) => p.quantity > 0)
        .map(
          (p) =>
            `<option value="${p._id}" data-cost="${p.cost || 0}" data-number="${p.partNumber}">${p.partNumber} - ${p.description} (Stock: ${p.quantity})</option>`,
        )
        .join("");

    document.querySelector('input[name="date"]').valueAsDate = new Date();
    document.querySelector('input[name="mechanic"]').value =
      currentUser.name || currentUser.username;

    openModal("repair-modal");
  } catch (e) {
    console.error("Repair modal error:", e);
    showAlert("Failed to load data", "error");
  }
}

function addPartToRepair() {
  const partSelect = document.getElementById("temp-part-select");
  const qtyInput = document.getElementById("temp-part-qty");
  const partId = partSelect.value;
  const quantity = parseInt(qtyInput.value);

  if (!partId || quantity < 1) {
    showAlert("Please select a part and quantity", "error");
    return;
  }

  const part = availableParts.find((p) => p._id === partId);
  if (!part) return;

  if (part.quantity < quantity) {
    showAlert(`Insufficient stock. Only ${part.quantity} available`, "error");
    return;
  }

  const existingIndex = currentRepairParts.findIndex(
    (p) => p.partId === partId,
  );
  if (existingIndex >= 0) {
    currentRepairParts[existingIndex].quantity += quantity;
    currentRepairParts[existingIndex].totalCost =
      currentRepairParts[existingIndex].unitCost *
      currentRepairParts[existingIndex].quantity;
  } else {
    currentRepairParts.push({
      partId: part._id,
      partNumber: part.partNumber,
      description: part.description,
      quantity: quantity,
      unitCost: part.cost || 0,
      totalCost: (part.cost || 0) * quantity,
    });
  }

  partSelect.value = "";
  qtyInput.value = "1";
  updatePartsList();
  calculateRepairTotal();
}

function removePartFromRepair(index) {
  currentRepairParts.splice(index, 1);
  updatePartsList();
  calculateRepairTotal();
}

function updatePartsList() {
  const container = document.getElementById("repair-parts-list");
  if (currentRepairParts.length === 0) {
    container.innerHTML = `<div class="empty-state" style="padding: 2rem;"><i class="fas fa-box-open" style="font-size: 3rem;"></i><p>No parts added yet</p></div>`;
    return;
  }

  container.innerHTML = currentRepairParts
    .map(
      (p, index) => `
    <div class="part-row">
      <div class="part-info">
        <div class="part-icon"><i class="fas fa-cog"></i></div>
        <div>
          <div style="font-weight: 600;">${p.partNumber}</div>
          <div style="font-size: 0.875rem; color: var(--text-secondary);">${p.description}</div>
          <div style="font-size: 0.875rem; color: var(--primary);">${p.quantity} x $${p.unitCost.toFixed(2)} = $${p.totalCost.toFixed(2)}</div>
        </div>
      </div>
      <button type="button" class="btn btn-sm btn-danger remove-part-btn" data-index="${index}"><i class="fas fa-trash"></i></button>
    </div>
  `,
    )
    .join("");

  container.querySelectorAll(".remove-part-btn").forEach((btn) => {
    btn.addEventListener("click", function () {
      removePartFromRepair(parseInt(this.dataset.index));
    });
  });

  document.getElementById("parts-used-json").value =
    JSON.stringify(currentRepairParts);
}

function calculateRepairTotal() {
  const laborHours =
    parseFloat(document.querySelector('input[name="laborHours"]').value) || 0;
  const laborRate =
    parseFloat(document.querySelector('input[name="laborRate"]').value) || 0;
  const laborCost = laborHours * laborRate;
  const partsCost = currentRepairParts.reduce((sum, p) => sum + p.totalCost, 0);
  const grandTotal = partsCost + laborCost;

  document.getElementById("parts-total-cost").textContent =
    partsCost.toFixed(2);
  document.getElementById("labor-total-cost").textContent =
    laborCost.toFixed(2);
  document.getElementById("grand-total-cost").textContent =
    grandTotal.toFixed(2);
}

async function saveRepair() {
  const form = document.getElementById("repair-form");
  const formData = Object.fromEntries(new FormData(form));
  const data = {
    truckId: formData.truckId,
    date: formData.date,
    issue: formData.issue,
    laborHours: parseFloat(formData.laborHours) || 0,
    laborRate: parseFloat(formData.laborRate) || 75,
    mechanic: formData.mechanic,
    notes: formData.notes,
    partsUsed: currentRepairParts,
  };

  if (!data.truckId || !data.issue) {
    showAlert("Please fill in all required fields", "error");
    return;
  }

  try {
    await api("/api/repairs", { method: "POST", body: JSON.stringify(data) });
    closeModal("repair-modal");
    form.reset();
    currentRepairParts = [];
    loadRepairs();
    loadDashboard();
    if (currentVehicleId) viewVehicle(currentVehicleId);
    showAlert("Repair logged successfully!", "success");
  } catch (e) {
    showAlert(e.message, "error");
  }
}

async function loadUsers() {
  try {
    const users = await api("/api/users");
    const tbody = document.getElementById("users-table");

    if (!users || users.length === 0) {
      tbody.innerHTML =
        '<tr><td colspan="6" style="text-align: center; padding: 2rem;">No users found</td></tr>';
      return;
    }

    tbody.innerHTML = users
      .map((u) => {
        const roleIcon =
          u.role === "admin"
            ? "fa-shield-alt"
            : u.role === "mechanic"
              ? "fa-wrench"
              : u.role === "driver"
                ? "fa-truck"
                : "fa-eye";
        return `
        <tr>
          <td><strong><i class="fas fa-user" style="color: var(--primary); margin-right: 0.5rem;"></i>${u.username}</strong></td>
          <td>${u.name || "-"}</td>
          <td><span class="badge badge-${u.role === "admin" ? "danger" : u.role === "mechanic" ? "success" : "warning"}"><i class="fas ${roleIcon}"></i> ${u.role}</span></td>
          <td>${u.isActive !== false ? '<span class="badge badge-success"><i class="fas fa-check"></i> Active</span>' : '<span class="badge badge-danger"><i class="fas fa-ban"></i> Disabled</span>'}</td>
          <td><i class="fas fa-calendar" style="color: var(--text-secondary);"></i> ${new Date(u.createdAt).toLocaleDateString()}</td>
          <td>
            <button class="btn btn-sm btn-secondary" data-action="toggle-user" data-id="${u._id}" data-active="${u.isActive !== false}">
              <i class="fas ${u.isActive === false ? "fa-check" : "fa-ban"}"></i> ${u.isActive === false ? "Enable" : "Disable"}
            </button>
            ${
              currentUser._id !== u._id
                ? `<button class="btn btn-sm btn-danger" data-action="delete-user" data-id="${u._id}" style="margin-left: 0.5rem;"><i class="fas fa-trash"></i></button>`
                : '<span style="font-size: 0.75rem; color: var(--text-secondary); margin-left: 0.5rem;">(You)</span>'
            }
          </td>
        </tr>
      `;
      })
      .join("");
  } catch (e) {
    console.error("Users load error:", e);
  }
}

async function toggleUser(userId, isActive) {
  const action = isActive ? "enable" : "disable";
  if (!confirm(`Are you sure you want to ${action} this user?`)) return;
  try {
    await api(`/api/users/${userId}`, {
      method: "PATCH",
      body: JSON.stringify({ isActive }),
    });
    loadUsers();
    showAlert(`User ${action}d successfully!`, "success");
  } catch (e) {
    showAlert(`Failed to ${action} user: ${e.message}`, "error");
  }
}

async function deleteUser(userId) {
  if (!confirm("Permanently delete this user?")) return;
  try {
    await api(`/api/users/${userId}`, { method: "DELETE" });
    loadUsers();
    showAlert("User deleted!", "success");
  } catch (e) {
    showAlert("Failed to delete user: " + e.message, "error");
  }
}

async function saveUser() {
  const form = document.getElementById("user-form");
  const data = Object.fromEntries(new FormData(form));
  try {
    await api("/api/users", { method: "POST", body: JSON.stringify(data) });
    closeModal("user-modal");
    form.reset();
    loadUsers();
    showAlert("User created!", "success");
  } catch (e) {
    showAlert(e.message, "error");
  }
}

async function loadLogs() {
  try {
    const logs = await api("/api/activity-logs");
    const tbody = document.getElementById("logs-table");

    if (!logs || logs.length === 0) {
      tbody.innerHTML =
        '<tr><td colspan="4" style="text-align: center; padding: 2rem;">No activity logs</td></tr>';
      return;
    }

    tbody.innerHTML = logs
      .map((l) => {
        const actionIcons = {
          CREATE_USER: "fa-user-plus",
          USER_ENABLED: "fa-check-circle",
          USER_DISABLED: "fa-ban",
          USER_DELETED: "fa-user-times",
          CREATE_PART: "fa-box",
          DELETE_PART: "fa-trash",
          CREATE_TRUCK: "fa-truck",
          DELETE_TRUCK: "fa-trash",
          CREATE_REPAIR: "fa-wrench",
          DELETE_REPAIR: "fa-trash",
        };
        const icon = actionIcons[l.action] || "fa-circle";
        return `
        <tr>
          <td><i class="fas fa-clock" style="color: var(--text-secondary);"></i> ${new Date(l.timestamp).toLocaleString()}</td>
          <td><i class="fas fa-user" style="color: var(--primary);"></i> ${l.username}</td>
          <td><span class="badge badge-info"><i class="fas ${icon}"></i> ${l.action}</span></td>
          <td>${l.entityType}: ${l.entityId}</td>
        </tr>
      `;
      })
      .join("");
  } catch (e) {
    console.error("Logs load error:", e);
  }
}

function openModal(id) {
  document.getElementById(id).classList.add("active");
  document.body.style.overflow = "hidden";
}

function closeModal(id) {
  document.getElementById(id).classList.remove("active");
  document.body.style.overflow = "";
  const form = document.querySelector(`#${id} form`);
  if (form) form.reset();
  if (id === "repair-modal") {
    currentRepairParts = [];
    updatePartsList();
  }
}

function showAlert(msg, type = "error") {
  const div = document.createElement("div");
  div.className = `alert alert-${type}`;
  div.innerHTML = `<i class="fas ${type === "success" ? "fa-check-circle" : "fa-exclamation-circle"}"></i> <span>${msg}</span>`;
  document.getElementById("app-alerts").appendChild(div);
  setTimeout(() => div.remove(), 5000);
}
