const API_URL = 'https://rentadrive-backend-production.up.railway.app/api';
let token = localStorage.getItem('adminToken');
let currentAdmin = JSON.parse(localStorage.getItem('currentAdmin') || '{}');
let currentUserId = null;
let currentUserDaysLeft = 0;
let currentUserExpiry = null;
let allUsers = [];
let currentFilter = 'all';
let allAuditLogs = [];  // ← nuevo

// ============================================
// INIT
// ============================================
if (token && currentAdmin.email) {
    document.getElementById('loginCard').style.display = 'none';
    document.getElementById('dashboard').style.display = 'block';
    initDashboard();
}

// ============================================
// LOGIN
// ============================================
document.getElementById('loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const btn = document.getElementById('loginBtn');
    btn.textContent = '⏳ Iniciando...';
    btn.disabled = true;
    const email = document.getElementById('loginEmail').value;
    const password = document.getElementById('loginPassword').value;
    try {
        const response = await fetch(`${API_URL}/admin/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password })
        });
        const data = await response.json();
        if (data.success) {
            token = data.token;
            currentAdmin = data.admin;
            localStorage.setItem('adminToken', token);
            localStorage.setItem('currentAdmin', JSON.stringify(currentAdmin));
            document.getElementById('loginCard').style.display = 'none';
            document.getElementById('dashboard').style.display = 'block';
            initDashboard();
        } else {
            showMessage('loginMessage', data.message, 'error');
        }
    } catch (error) {
        showMessage('loginMessage', 'Error de conexión con el servidor', 'error');
    } finally {
        btn.textContent = '🚀 Iniciar Sesión';
        btn.disabled = false;
    }
});

// ============================================
// INIT DASHBOARD
// ============================================
async function initDashboard() {
    document.getElementById('adminName').textContent = currentAdmin.name;
    document.getElementById('adminRole').textContent = currentAdmin.role;
    document.getElementById('adminRole').className = `role-badge ${currentAdmin.role}`;
    if (currentAdmin.role === 'super_admin') {
        document.getElementById('adminsTabBtn').classList.remove('hidden');
    }
    await loadStats();
    await loadUsers();
}

// ============================================
// LOGOUT
// ============================================
function logout() {
    if (confirm('¿Seguro que deseas cerrar sesión?')) {
        localStorage.removeItem('adminToken');
        localStorage.removeItem('currentAdmin');
        location.reload();
    }
}

// ============================================
// REFRESH ALL
// ============================================
async function refreshAll() {
    await loadStats();
    await loadUsers();
    showToast('🔄 Datos actualizados', 'success');
}

// ============================================
// STATS CON ANIMACIÓN
// ============================================
async function loadStats() {
    try {
        const response = await fetch(`${API_URL}/admin/stats`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        const data = await response.json();
        if (data.success) {
            animateNumber('statTotalUsers', data.stats.totalUsers);
            animateNumber('statActiveUsers', data.stats.activeSubscriptions);
            animateNumber('statInactiveUsers', data.stats.inactiveSubscriptions);
            animateNumber('statExpiredUsers', data.stats.expiredSubscriptions);
        }
    } catch (error) {
        console.error('Error loading stats:', error);
    }
}

function animateNumber(elementId, target) {
    const el = document.getElementById(elementId);
    let current = 0;
    const step = Math.max(1, Math.ceil(target / 20));
    const timer = setInterval(() => {
        current = Math.min(current + step, target);
        el.textContent = current;
        if (current >= target) clearInterval(timer);
    }, 40);
}

// ============================================
// LOAD USERS
// ============================================
async function loadUsers() {
    document.getElementById('usersLoading').classList.remove('hidden');
    try {
        const response = await fetch(`${API_URL}/admin/users`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        const data = await response.json();
        if (data.success) {
            allUsers = data.users;
            applyFilter(currentFilter);
        } else {
            showMessage('usersMessage', data.message, 'error');
        }
    } catch (error) {
        showMessage('usersMessage', 'Error cargando usuarios', 'error');
    } finally {
        document.getElementById('usersLoading').classList.add('hidden');
    }
}

// ============================================
// FILTROS USUARIOS
// ============================================
function setFilter(filter, btn) {
    currentFilter = filter;
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    applyFilter(filter);
}

function filterUsersByStatus(status) {
    showTab('users', null);
    currentFilter = status;
    document.querySelectorAll('.filter-btn').forEach(b => {
        b.classList.remove('active');
        if (b.getAttribute('onclick') && b.getAttribute('onclick').includes(`'${status}'`)) {
            b.classList.add('active');
        }
    });
    applyFilter(status);
}

function applyFilter(filter) {
    const now = new Date();
    let filtered = allUsers;
    if (filter === 'active') {
        filtered = allUsers.filter(u => {
            const exp = u.subscriptionExpiry ? new Date(u.subscriptionExpiry) : null;
            return u.subscriptionActive && exp && exp > now;
        });
    } else if (filter === 'expiring') {
        filtered = allUsers.filter(u => {
            const exp = u.subscriptionExpiry ? new Date(u.subscriptionExpiry) : null;
            if (!exp || !u.subscriptionActive) return false;
            const days = Math.floor((exp - now) / (1000 * 60 * 60 * 24));
            return days >= 0 && days <= 7;
        });
    } else if (filter === 'expired') {
        filtered = allUsers.filter(u => {
            const exp = u.subscriptionExpiry ? new Date(u.subscriptionExpiry) : null;
            return u.subscriptionActive && exp && exp <= now;
        });
    } else if (filter === 'inactive') {
        filtered = allUsers.filter(u => !u.subscriptionActive);
    }
    displayUsers(filtered);
}

// ============================================
// SEARCH USER
// ============================================
async function searchUser() {
    const email = document.getElementById('searchEmail').value.trim();
    if (!email) {
        showToast('📧 Por favor ingresa un email', 'error');
        return;
    }
    document.getElementById('usersLoading').classList.remove('hidden');
    try {
        const response = await fetch(`${API_URL}/admin/search-user?email=${encodeURIComponent(email)}`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        const data = await response.json();
        if (data.success) {
            displayUsers([data.user]);
            showToast('✅ Usuario encontrado', 'success');
        } else {
            showToast('❌ ' + data.message, 'error');
            displayUsers([]);
        }
    } catch (error) {
        showToast('❌ Error buscando usuario', 'error');
    } finally {
        document.getElementById('usersLoading').classList.add('hidden');
    }
}

// ============================================
// DISPLAY USERS
// ============================================
function displayUsers(users) {
    const tbody = document.getElementById('usersTableBody');
    const countEl = document.getElementById('userCount');
    tbody.innerHTML = '';

    if (users.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; padding:40px; color:#6b7280;">No hay usuarios para mostrar</td></tr>';
        countEl.classList.add('hidden');
        return;
    }

    countEl.classList.remove('hidden');
    countEl.textContent = `${users.length} usuario${users.length !== 1 ? 's' : ''} encontrado${users.length !== 1 ? 's' : ''}`;

    users.forEach(user => {
        const expiry = user.subscriptionExpiry ? new Date(user.subscriptionExpiry) : null;
        const now = new Date();
        const daysLeft = expiry ? Math.floor((expiry - now) / (1000 * 60 * 60 * 24)) : 0;

        let statusBadge = '';
        let rowClass = '';
        if (user.subscriptionActive && daysLeft > 7) {
            statusBadge = '<span class="status-badge active">✅ Activa</span>';
        } else if (user.subscriptionActive && daysLeft >= 0 && daysLeft <= 7) {
            statusBadge = '<span class="status-badge expiring">⚠️ Vence pronto</span>';
            rowClass = 'row-warning';
        } else if (user.subscriptionActive && daysLeft < 0) {
            statusBadge = '<span class="status-badge expired">⏰ Expirada</span>';
            rowClass = 'row-expired';
        } else {
            statusBadge = '<span class="status-badge inactive">❌ Inactiva</span>';
        }

        const daysDisplay = daysLeft > 0
            ? `<strong class="${daysLeft <= 7 ? 'days-warning' : ''}">${daysLeft}d</strong>`
            : '<span style="color:#9ca3af">-</span>';

        const canManage = currentAdmin.role === 'super_admin' || currentAdmin.role === 'vendedor';
        const avatarLetter = user.email.charAt(0).toUpperCase();

        const row = `
            <tr class="${rowClass}">
                <td>
                    <div class="user-email-cell">
                        <span class="user-avatar">${avatarLetter}</span>
                        <span>${user.email}</span>
                    </div>
                </td>
                <td class="hide-mobile"><strong>${user.plan || 'none'}</strong></td>
                <td>${statusBadge}</td>
                <td class="hide-mobile">${expiry ? expiry.toLocaleDateString('es-MX') : 'N/A'}</td>
                <td class="hide-mobile">${daysDisplay}</td>
                <td>
                    <div class="action-buttons">
                        ${canManage
                            ? `<button onclick="openModal('${user.userId}', '${user.email}', ${user.subscriptionActive}, '${user.subscriptionExpiry}')" class="btn-small" title="Gestionar suscripción">⚙️ Gestionar</button>`
                            : ''}
                        ${currentAdmin.role === 'super_admin'
                            ? `<button onclick="openDeleteModalDirect('${user.userId}', '${user.email}')" class="btn-small danger" title="Eliminar cuenta" style="background:linear-gradient(135deg,#ef4444,#dc2626);box-shadow:0 2px 8px rgba(239,68,68,0.3);">🗑️</button>`
                            : ''}
                    </div>
                </td>
            </tr>
        `;
        tbody.innerHTML += row;
    });
}

// ============================================
// MODAL
// ============================================
function openModal(userId, email, isActive, expiry) {
    currentUserId = userId;
    currentUserExpiry = expiry;
    const expiryDate = expiry && expiry !== 'null' ? new Date(expiry) : null;
    const now = new Date();
    currentUserDaysLeft = expiryDate && isActive
        ? Math.max(0, Math.floor((expiryDate - now) / (1000 * 60 * 60 * 24)))
        : 0;

    document.getElementById('modalUserEmail').textContent = email;
    document.getElementById('modalUserStatus').textContent = isActive ? '✅ Activa' : '❌ Inactiva';
    document.getElementById('modalUserExpiry').textContent = expiryDate ? expiryDate.toLocaleDateString('es-MX') : 'N/A';
    document.getElementById('modalDaysLeft').textContent = currentUserDaysLeft > 0 ? `${currentUserDaysLeft} días` : 'Sin días';
    document.getElementById('currentDaysRemove').textContent = `${currentUserDaysLeft} días`;
    document.getElementById('modalDaysAdd').value = '30';
    document.getElementById('modalDaysRemove').value = '7';
    document.getElementById('modalDaysSet').value = '30';
    document.getElementById('modalMessage').innerHTML = '';
    switchModalTab('add', null);
    document.getElementById('subscriptionModal').style.display = 'flex';
}

function closeModal() {
    document.getElementById('subscriptionModal').style.display = 'none';
    document.getElementById('modalMessage').innerHTML = '';
    currentUserId = null;
    currentUserDaysLeft = 0;
    currentUserExpiry = null;
}

function switchModalTab(tab, e) {
    document.querySelectorAll('.modal-tab-btn').forEach(btn => btn.classList.remove('active'));
    document.querySelectorAll('.modal-tab-content').forEach(c => c.classList.remove('active'));
    if (e && e.target) {
        e.target.classList.add('active');
    } else {
        const idx = tab === 'add' ? 0 : tab === 'remove' ? 1 : 2;
        document.querySelectorAll('.modal-tab-btn')[idx]?.classList.add('active');
    }
    document.getElementById(`modalTab${tab.charAt(0).toUpperCase() + tab.slice(1)}`).classList.add('active');
}

function setDaysAdd(days)    { document.getElementById('modalDaysAdd').value = days; }
function setDaysRemove(days) { document.getElementById('modalDaysRemove').value = days; }
function setDaysSet(days)    { document.getElementById('modalDaysSet').value = days; }

// ============================================
// ADD DAYS
// ============================================
async function addDaysToSubscription() {
    const daysToAdd = parseInt(document.getElementById('modalDaysAdd').value);
    if (!daysToAdd || daysToAdd < 1 || daysToAdd > 365) {
        showMessage('modalMessage', '📅 Ingresa días válidos (1-365)', 'error');
        return;
    }
    try {
        const response = await fetch(`${API_URL}/admin/extend-subscription`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
            body: JSON.stringify({ userId: currentUserId, days: daysToAdd })
        });
        const data = await response.json();
        if (data.success) {
            showMessage('modalMessage', `✅ Se agregaron ${daysToAdd} días. Total: ${currentUserDaysLeft + daysToAdd} días`, 'success');
            setTimeout(() => { closeModal(); loadUsers(); loadStats(); }, 1500);
        } else {
            showMessage('modalMessage', '❌ ' + data.message, 'error');
        }
    } catch (error) {
        showMessage('modalMessage', '❌ Error de conexión', 'error');
    }
}

// ============================================
// REMOVE DAYS
// ============================================
async function removeDaysFromSubscription() {
    const daysToRemove = parseInt(document.getElementById('modalDaysRemove').value);
    if (!daysToRemove || daysToRemove < 1) {
        showMessage('modalMessage', '📅 Ingresa días válidos', 'error');
        return;
    }
    if (daysToRemove > currentUserDaysLeft) {
        showMessage('modalMessage', `⚠️ No puedes quitar más de ${currentUserDaysLeft} días`, 'error');
        return;
    }
    if (!confirm(`⚠️ ¿Quitar ${daysToRemove} días?\nQuedarán: ${currentUserDaysLeft - daysToRemove} días`)) return;
    const newDays = currentUserDaysLeft - daysToRemove;
    try {
        const response = await fetch(`${API_URL}/admin/activate-subscription`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
            body: JSON.stringify({ userId: currentUserId, days: newDays })
        });
        const data = await response.json();
        if (data.success) {
            showMessage('modalMessage', `✅ Quitados ${daysToRemove} días. Quedan: ${newDays} días`, 'success');
            setTimeout(() => { closeModal(); loadUsers(); loadStats(); }, 1500);
        } else {
            showMessage('modalMessage', '❌ ' + data.message, 'error');
        }
    } catch (error) {
        showMessage('modalMessage', '❌ Error de conexión', 'error');
    }
}

// ============================================
// SET EXACT DAYS
// ============================================
async function setExactDays() {
    const exactDays = parseInt(document.getElementById('modalDaysSet').value);
    if (!exactDays || exactDays < 1 || exactDays > 730) {
        showMessage('modalMessage', '📅 Ingresa días válidos (1-730)', 'error');
        return;
    }
    if (!confirm(`📅 ¿Establecer ${exactDays} días desde hoy?\nReemplaza los actuales (${currentUserDaysLeft})`)) return;
    try {
        const response = await fetch(`${API_URL}/admin/activate-subscription`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
            body: JSON.stringify({ userId: currentUserId, days: exactDays })
        });
        const data = await response.json();
        if (data.success) {
            showMessage('modalMessage', `✅ Establecidos ${exactDays} días desde hoy`, 'success');
            setTimeout(() => { closeModal(); loadUsers(); loadStats(); }, 1500);
        } else {
            showMessage('modalMessage', '❌ ' + data.message, 'error');
        }
    } catch (error) {
        showMessage('modalMessage', '❌ Error de conexión', 'error');
    }
}

// ============================================
// DEACTIVATE
// ============================================
async function deactivateSubscription() {
    const reason = prompt('🚫 Razón para desactivar:\n\nEjemplos:\n• No pagó\n• Solicitó cancelación\n• Infracción', '');
    if (reason === null) return;
    const finalReason = reason.trim() || 'Sin razón especificada';
    if (!confirm(`⚠️ ¿Confirmas desactivar?\n\nRazón: ${finalReason}`)) return;
    try {
        const response = await fetch(`${API_URL}/admin/deactivate-subscription`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
            body: JSON.stringify({ userId: currentUserId, reason: finalReason })
        });
        const data = await response.json();
        if (data.success) {
            showMessage('modalMessage', `✅ Suscripción desactivada.${data.daysLost ? ` Días perdidos: ${data.daysLost}` : ''}`, 'success');
            setTimeout(() => { closeModal(); loadUsers(); loadStats(); }, 1500);
        } else {
            showMessage('modalMessage', '❌ ' + data.message, 'error');
        }
    } catch (error) {
        showMessage('modalMessage', '❌ Error de conexión', 'error');
    }
}

// ============================================
// AUDIT LOGS
// ============================================
async function loadAuditLogs() {
    document.getElementById('auditLoading').classList.remove('hidden');
    const limit = document.getElementById('auditLimit')?.value || 50;
    try {
        const response = await fetch(`${API_URL}/admin/audit-logs?limit=${limit}`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        const data = await response.json();
        if (data.success) {
            allAuditLogs = data.logs;
            const searchTerm = document.getElementById('auditSearch')?.value || '';
            renderAuditLogs(allAuditLogs, searchTerm);
        } else {
            showMessage('auditMessage', data.message, 'error');
        }
    } catch (error) {
        showMessage('auditMessage', 'Error cargando auditoría', 'error');
    } finally {
        document.getElementById('auditLoading').classList.add('hidden');
    }
}

// ============================================
// RENDER AUDIT + BÚSQUEDA CON HIGHLIGHT
// ============================================
function renderAuditLogs(logs, searchTerm = '') {
    const tbody = document.getElementById('auditTableBody');
    const countEl = document.getElementById('auditCount');
    const term = searchTerm.toLowerCase().trim();

    const filtered = term
        ? logs.filter(log => {
            const userEmail  = (log.userEmail || log.targetEmail || log.targetAdminEmail || '').toLowerCase();
            const adminEmail = (log.adminEmail || '').toLowerCase();
            const adminName  = (log.adminName || '').toLowerCase();
            const action     = (log.action || '').toLowerCase();
            const desc       = (log.details?.description || '').toLowerCase();
            return userEmail.includes(term)
                || adminEmail.includes(term)
                || adminName.includes(term)
                || action.includes(term)
                || desc.includes(term);
        })
        : logs;

    if (countEl) {
        if (term && filtered.length !== logs.length) {
            countEl.classList.remove('hidden');
            countEl.textContent = `${filtered.length} resultado${filtered.length !== 1 ? 's' : ''} de ${logs.length} registros`;
        } else {
            countEl.classList.add('hidden');
        }
    }

    if (filtered.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; padding:40px; color:#6b7280;">
            ${term ? `❌ Sin resultados para "<strong>${term}</strong>"` : 'No hay registros'}
        </td></tr>`;
        return;
    }

    const highlight = (text) => {
        if (!term || !text || text === '-') return text;
        const safe = term.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        return text.replace(new RegExp(`(${safe})`, 'gi'),
            '<mark style="background:#fef08a; border-radius:3px; padding:0 2px;">$1</mark>');
    };

    tbody.innerHTML = '';
    filtered.forEach(log => {
        const date = log.timestamp
            ? new Date(log.timestamp).toLocaleString('es-MX', {
                day: '2-digit', month: '2-digit',
                hour: '2-digit', minute: '2-digit'
            }) : '-';

        const adminLabel = log.adminName
            ? `<strong>${log.adminName}</strong><br><small style="color:#6b7280;">${log.adminEmail || ''}</small>`
            : (log.adminEmail || '-');

        const userEmail = log.userEmail || log.targetEmail || log.targetAdminEmail || '-';

        let actionBg = '#f3f4f6', actionColor = '#374151';
        const action = log.action || '';
        if (action.includes('DESACTIVAR') || action.includes('deactivate'))         { actionBg = '#fee2e2'; actionColor = '#dc2626'; }
        else if (action.includes('AGREGAR') || action.includes('extend') || action.includes('add_days')) { actionBg = '#d1fae5'; actionColor = '#059669'; }
        else if (action.includes('ESTABLECER') || action.includes('activate'))      { actionBg = '#dbeafe'; actionColor = '#2563eb'; }
        else if (action.includes('QUITAR') || action.includes('remove_days'))       { actionBg = '#fef3c7'; actionColor = '#d97706'; }
        else if (action.includes('delete'))                                          { actionBg = '#fce7f3'; actionColor = '#db2777'; }
        else if (action.includes('create') || action.includes('change_admin_role')) { actionBg = '#ede9fe'; actionColor = '#7c3aed'; }

        let detailsHtml = '-';
        if (log.details) {
            const d = log.details;
            const lines = [];
            if (d.daysAdded)                 lines.push(`➕ +${d.daysAdded} días`);
            if (d.daysRemoved)               lines.push(`➖ -${d.daysRemoved} días`);
            if (d.newDaysTotal !== undefined) lines.push(`📅 Total: ${d.newDaysTotal} días`);
            if (d.description)               lines.push(`📝 ${d.description}`);
            if (d.reason)                    lines.push(`💬 ${d.reason}`);
            if (d.newExpiry)                 lines.push(`🗓️ Expira: ${new Date(d.newExpiry).toLocaleDateString('es-MX')}`);
            if (d.oldRole && d.newRole)      lines.push(`🎭 ${d.oldRole} → ${d.newRole}`);
            detailsHtml = lines.length > 0
                ? `<div class="audit-details">${lines.join('<br>')}</div>`
                : `<pre style="font-size:10px; max-width:220px; overflow:auto; background:#f9fafb; padding:6px; border-radius:6px; margin:0; max-height:80px;">${JSON.stringify(log.details, null, 2)}</pre>`;
        }

        const row = `
            <tr>
                <td class="hide-mobile" style="font-size:12px; white-space:nowrap; color:#6b7280;">${date}</td>
                <td style="font-size:13px;">${adminLabel}</td>
                <td>
                    <span style="background:${actionBg}; color:${actionColor}; padding:4px 8px; border-radius:6px; font-size:11px; font-weight:600; white-space:nowrap; display:inline-block;">
                        ${action}
                    </span>
                </td>
                <td style="font-size:13px;">${highlight(userEmail)}</td>
                <td class="hide-mobile">${detailsHtml}</td>
            </tr>
        `;
        tbody.innerHTML += row;
    });
}

function filterAuditLogs(term) {
    if (allAuditLogs.length === 0) return;
    renderAuditLogs(allAuditLogs, term);
}

function clearAuditSearch() {
    const input = document.getElementById('auditSearch');
    if (input) input.value = '';
    renderAuditLogs(allAuditLogs, '');
}

// ============================================
// ADMINS
// ============================================
async function loadAdmins() {
    if (currentAdmin.role !== 'super_admin') return;
    document.getElementById('adminsLoading').classList.remove('hidden');
    try {
        const response = await fetch(`${API_URL}/admin/list-admins`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        const data = await response.json();
        if (data.success) {
            const tbody = document.getElementById('adminsTableBody');
            tbody.innerHTML = '';
            data.admins.forEach(admin => {
                const lastLogin = admin.lastLogin
                    ? new Date(admin.lastLogin).toLocaleString('es-MX', {
                        day: '2-digit', month: '2-digit',
                        hour: '2-digit', minute: '2-digit'
                    }) : 'Nunca';
                const statusBadge = admin.active
                    ? '<span class="status-badge active">✅ Activo</span>'
                    : '<span class="status-badge inactive">❌ Inactivo</span>';
                const isCurrentUser = admin.id === currentAdmin.id;
                const row = `
                    <tr>
                        <td>${admin.email}</td>
                        <td class="hide-mobile"><strong>${admin.name}</strong></td>
                        <td><span class="role-badge ${admin.role}">${admin.role}</span></td>
                        <td class="hide-mobile">${statusBadge}</td>
                        <td class="hide-mobile" style="font-size:12px; color:#6b7280;">${lastLogin}</td>
                        <td>
                            ${!isCurrentUser ? `
                                <div class="action-buttons">
                                    ${admin.active
                                        ? `<button onclick="toggleAdminStatus('${admin.id}', false, '${admin.email}')" class="btn-small danger" title="Desactivar">🚫</button>`
                                        : `<button onclick="toggleAdminStatus('${admin.id}', true, '${admin.email}')" class="btn-small" title="Activar">✅</button>`
                                    }
                                    <button onclick="openChangeRoleModal('${admin.id}', '${admin.email}', '${admin.role}')" class="btn-small secondary" title="Cambiar rol">🎭</button>
                                    <button onclick="deleteAdmin('${admin.id}', '${admin.email}')" class="btn-small danger" title="Eliminar">🗑️</button>
                                </div>
                            ` : '<span style="color:#9ca3af; font-style:italic; font-size:11px;">Tú</span>'}
                        </td>
                    </tr>
                `;
                tbody.innerHTML += row;
            });
        } else {
            showMessage('adminsMessage', data.message, 'error');
        }
    } catch (error) {
        showMessage('adminsMessage', 'Error cargando admins', 'error');
    } finally {
        document.getElementById('adminsLoading').classList.add('hidden');
    }
}

async function toggleAdminStatus(adminId, activate, email) {
    if (!confirm(`¿${activate ? 'Activar' : 'Desactivar'} a ${email}?`)) return;
    try {
        const response = await fetch(`${API_URL}/admin/toggle-admin-status`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
            body: JSON.stringify({ adminId, active: activate })
        });
        const data = await response.json();
        if (data.success) { showToast(`✅ ${data.message}`, 'success'); loadAdmins(); }
        else { showToast(`❌ ${data.message}`, 'error'); }
    } catch (error) { showToast('❌ Error de conexión', 'error'); }
}

async function deleteAdmin(adminId, email) {
    if (!confirm(`⚠️ ¿ELIMINAR a ${email}?\nEsta acción NO se puede deshacer.`)) return;
    if (!confirm(`🚨 ÚLTIMA CONFIRMACIÓN: Se eliminará a ${email}`)) return;
    try {
        const response = await fetch(`${API_URL}/admin/delete-admin/${adminId}`, {
            method: 'DELETE',
            headers: { 'Authorization': `Bearer ${token}` }
        });
        const data = await response.json();
        if (data.success) { showToast(`✅ ${data.message}`, 'success'); loadAdmins(); }
        else { showToast(`❌ ${data.message}`, 'error'); }
    } catch (error) { showToast('❌ Error de conexión', 'error'); }
}

function openChangeRoleModal(adminId, email, currentRole) {
    const newRole = prompt(`Cambiar rol de ${email}\nActual: ${currentRole}\n\nNuevo rol (super_admin, vendedor, soporte):`, currentRole);
    if (!newRole || newRole === currentRole) return;
    if (!['super_admin', 'vendedor', 'soporte'].includes(newRole)) {
        alert('❌ Rol inválido. Debe ser: super_admin, vendedor o soporte');
        return;
    }
    changeAdminRole(adminId, newRole);
}

async function changeAdminRole(adminId, newRole) {
    try {
        const response = await fetch(`${API_URL}/admin/change-role`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
            body: JSON.stringify({ adminId, newRole })
        });
        const data = await response.json();
        if (data.success) { showToast(`✅ ${data.message}`, 'success'); loadAdmins(); }
        else { showToast(`❌ ${data.message}`, 'error'); }
    } catch (error) { showToast('❌ Error de conexión', 'error'); }
}

document.getElementById('createAdminForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const newAdmin = {
        email: document.getElementById('newAdminEmail').value,
        name: document.getElementById('newAdminName').value,
        password: document.getElementById('newAdminPassword').value,
        role: document.getElementById('newAdminRole').value
    };
    try {
        const response = await fetch(`${API_URL}/admin/create-admin`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
            body: JSON.stringify(newAdmin)
        });
        const data = await response.json();
        if (data.success) {
            showToast('✅ Admin creado exitosamente', 'success');
            document.getElementById('createAdminForm').reset();
            loadAdmins();
        } else {
            showMessage('adminsMessage', '❌ ' + data.message, 'error');
        }
    } catch (error) {
        showMessage('adminsMessage', '❌ Error de conexión', 'error');
    }
});

// ============================================
// SHOW TAB
// ============================================
function showTab(tabName, e) {
    document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
    if (e && e.target) {
        e.target.closest('.tab-btn').classList.add('active');
    } else {
        document.querySelectorAll('.tab-btn').forEach(btn => {
            if (btn.getAttribute('onclick')?.includes(`'${tabName}'`)) btn.classList.add('active');
        });
    }
    document.getElementById(`tab${tabName.charAt(0).toUpperCase() + tabName.slice(1)}`).classList.add('active');
    if (tabName === 'audit') loadAuditLogs();
    else if (tabName === 'admins') loadAdmins();
}

// ============================================
// MESSAGES & TOAST
// ============================================
function showMessage(elementId, message, type) {
    const element = document.getElementById(elementId);
    if (!element) return;
    element.className = `message ${type}`;
    element.innerHTML = message;
    element.style.display = 'block';
    setTimeout(() => { element.style.display = 'none'; }, 5000);
}

function showToast(message, type = 'success') {
    const container = document.getElementById('toastContainer');
    if (!container) return;
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    container.appendChild(toast);
    setTimeout(() => toast.classList.add('toast-show'), 10);
    setTimeout(() => {
        toast.classList.remove('toast-show');
        setTimeout(() => toast.remove(), 400);
    }, 3000);
}

// ============================================
// TOGGLE PASSWORD
// ============================================
function togglePasswordVisibility(inputId, button) {
    const input = document.getElementById(inputId);
    if (input.type === 'password') {
        input.type = 'text';
        button.textContent = '🙈';
    } else {
        input.type = 'password';
        button.textContent = '👁️';
    }
}

// ============================================
// CERRAR MODAL AL CLICK AFUERA
// ============================================
document.getElementById('subscriptionModal').addEventListener('click', function(e) {
    if (e.target === this) closeModal();
});


// ============================================
// ELIMINAR CUENTA DE USUARIO
// ============================================
function openDeleteModal() {
    const email = document.getElementById('modalUserEmail').textContent;
    document.getElementById('deleteModalEmail').textContent = email;
    document.getElementById('deleteConfirmInput').value = '';
    document.getElementById('btnConfirmDelete').disabled = true;
    document.getElementById('btnConfirmDelete').style.opacity = '0.5';
    document.getElementById('deleteModalMessage').innerHTML = '';
    document.getElementById('deleteModal').style.display = 'flex';
}

function openDeleteModalDirect(userId, email) {
    currentUserId = userId;
    document.getElementById('deleteModalEmail').textContent = email;
    document.getElementById('deleteConfirmInput').value = '';
    document.getElementById('btnConfirmDelete').disabled = true;
    document.getElementById('btnConfirmDelete').style.opacity = '0.5';
    document.getElementById('deleteModalMessage').innerHTML = '';
    document.getElementById('deleteModal').style.display = 'flex';
}

function closeDeleteModal() {
    document.getElementById('deleteModal').style.display = 'none';
    document.getElementById('deleteConfirmInput').value = '';
}

function checkDeleteConfirm() {
    const val = document.getElementById('deleteConfirmInput').value.trim();
    const btn = document.getElementById('btnConfirmDelete');
    const ok = val === 'ELIMINAR';
    btn.disabled = !ok;
    btn.style.opacity = ok ? '1' : '0.5';
}

async function confirmDeleteUser() {
    if (!currentUserId) return;
    const btn = document.getElementById('btnConfirmDelete');
    btn.textContent = '⏳ Eliminando...';
    btn.disabled = true;

    try {
        const response = await fetch(`${API_URL}/admin/delete-user`, {
            method: 'DELETE',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({ userId: currentUserId })
        });
        const data = await response.json();

        if (data.success) {
            closeDeleteModal();
            closeModal();
            showToast('🗑️ Cuenta eliminada permanentemente', 'success');
            await loadStats();
            await loadUsers();
        } else {
            document.getElementById('deleteModalMessage').innerHTML =
                `<div class="message error">❌ ${data.message}</div>`;
            btn.textContent = '🗑️ Eliminar definitivamente';
            btn.disabled = false;
            btn.style.opacity = '1';
        }
    } catch (error) {
        document.getElementById('deleteModalMessage').innerHTML =
            `<div class="message error">❌ Error de conexión al eliminar</div>`;
        btn.textContent = '🗑️ Eliminar definitivamente';
        btn.disabled = false;
        btn.style.opacity = '1';
    }
}
