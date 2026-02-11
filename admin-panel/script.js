const API_URL = 'https://rentadrive-backend-production.up.railway.app/api';
let token = localStorage.getItem('adminToken');
let currentAdmin = JSON.parse(localStorage.getItem('currentAdmin') || '{}');
let currentUserId = null;
let currentUserDaysLeft = 0;
let currentUserExpiry = null;

// Check if already logged in
if (token && currentAdmin.email) {
    document.getElementById('loginCard').style.display = 'none';
    document.getElementById('dashboard').style.display = 'block';
    initDashboard();
}

// Login
document.getElementById('loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
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
    }
});

// Initialize Dashboard
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

// Logout
function logout() {
    if (confirm('¿Seguro que deseas cerrar sesión?')) {
        localStorage.removeItem('adminToken');
        localStorage.removeItem('currentAdmin');
        location.reload();
    }
}

// Load Stats
async function loadStats() {
    try {
        const response = await fetch(`${API_URL}/admin/stats`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        
        const data = await response.json();
        
        if (data.success) {
            document.getElementById('statTotalUsers').textContent = data.stats.totalUsers;
            document.getElementById('statActiveUsers').textContent = data.stats.activeSubscriptions;
            document.getElementById('statInactiveUsers').textContent = data.stats.inactiveSubscriptions;
            document.getElementById('statExpiredUsers').textContent = data.stats.expiredSubscriptions;
        }
    } catch (error) {
        console.error('Error loading stats:', error);
    }
}

// Load Users
async function loadUsers() {
    document.getElementById('usersLoading').classList.remove('hidden');
    
    try {
        const response = await fetch(`${API_URL}/admin/users`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        
        const data = await response.json();
        
        if (data.success) {
            displayUsers(data.users);
        } else {
            showMessage('usersMessage', data.message, 'error');
        }
    } catch (error) {
        showMessage('usersMessage', 'Error cargando usuarios', 'error');
    } finally {
        document.getElementById('usersLoading').classList.add('hidden');
    }
}

// Search User
async function searchUser() {
    const email = document.getElementById('searchEmail').value.trim();
    
    if (!email) {
        showMessage('usersMessage', '📧 Por favor ingresa un email', 'error');
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
            showMessage('usersMessage', '✅ Usuario encontrado', 'success');
        } else {
            showMessage('usersMessage', '❌ ' + data.message, 'error');
        }
    } catch (error) {
        showMessage('usersMessage', '❌ Error buscando usuario', 'error');
    } finally {
        document.getElementById('usersLoading').classList.add('hidden');
    }
}

// Display Users
function displayUsers(users) {
    const tbody = document.getElementById('usersTableBody');
    tbody.innerHTML = '';
    
    if (users.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; padding:30px; color:#6b7280;">No hay usuarios para mostrar</td></tr>';
        return;
    }
    
    users.forEach(user => {
        const expiry = user.subscriptionExpiry ? new Date(user.subscriptionExpiry) : null;
        const now = new Date();
        const daysLeft = expiry ? Math.floor((expiry - now) / (1000 * 60 * 60 * 24)) : 0;
        
        let statusBadge = '';
        if (user.subscriptionActive && daysLeft > 0) {
            statusBadge = '<span class="status-badge active">✅ Activa</span>';
        } else if (user.subscriptionActive && daysLeft <= 0) {
            statusBadge = '<span class="status-badge expired">⏰ Expirada</span>';
        } else {
            statusBadge = '<span class="status-badge inactive">❌ Inactiva</span>';
        }
        
        const canManage = currentAdmin.role === 'super_admin' || currentAdmin.role === 'vendedor';
        
        const row = `
            <tr>
                <td>${user.email}</td>
                <td class="hide-mobile"><strong>${user.plan || 'none'}</strong></td>
                <td>${statusBadge}</td>
                <td class="hide-mobile">${expiry ? expiry.toLocaleDateString('es-MX') : 'N/A'}</td>
                <td class="hide-mobile"><strong>${daysLeft > 0 ? daysLeft + 'd' : '-'}</strong></td>
                <td>
                    ${canManage ? `<button onclick="openModal('${user.userId}', '${user.email}', ${user.subscriptionActive}, '${user.subscriptionExpiry}')" class="btn-small">⚙️</button>` : '-'}
                </td>
            </tr>
        `;
        tbody.innerHTML += row;
    });
}

// Open Modal
function openModal(userId, email, isActive, expiry) {
    currentUserId = userId;
    currentUserExpiry = expiry;
    
    // Calcular días restantes
    const expiryDate = expiry && expiry !== 'null' ? new Date(expiry) : null;
    const now = new Date();
    currentUserDaysLeft = expiryDate && isActive ? Math.max(0, Math.floor((expiryDate - now) / (1000 * 60 * 60 * 24))) : 0;
    
    document.getElementById('modalUserEmail').textContent = email;
    document.getElementById('modalUserStatus').textContent = isActive ? '✅ Activa' : '❌ Inactiva';
    document.getElementById('modalUserExpiry').textContent = expiryDate ? expiryDate.toLocaleDateString('es-MX') : 'N/A';
    document.getElementById('modalDaysLeft').textContent = currentUserDaysLeft > 0 ? `${currentUserDaysLeft} días` : 'Sin días';
    document.getElementById('currentDaysRemove').textContent = `${currentUserDaysLeft} días`;
    
    // Reset inputs
    document.getElementById('modalDaysAdd').value = '30';
    document.getElementById('modalDaysRemove').value = '7';
    document.getElementById('modalDaysSet').value = '30';
    
    // Switch to add tab by default
    switchModalTab('add');
    
    document.getElementById('subscriptionModal').style.display = 'flex';
}

// Close Modal
function closeModal() {
    document.getElementById('subscriptionModal').style.display = 'none';
    document.getElementById('modalMessage').innerHTML = '';
    currentUserId = null;
    currentUserDaysLeft = 0;
    currentUserExpiry = null;
}

// Switch Modal Tab
function switchModalTab(tab) {
    // Remove active class from all tabs
    document.querySelectorAll('.modal-tab-btn').forEach(btn => btn.classList.remove('active'));
    document.querySelectorAll('.modal-tab-content').forEach(content => content.classList.remove('active'));
    
    // Add active class to selected tab
    const tabButton = event ? event.target : document.querySelector(`.modal-tab-btn:nth-child(${tab === 'add' ? 1 : tab === 'remove' ? 2 : 3})`);
    if (tabButton) tabButton.classList.add('active');
    
    document.getElementById(`modalTab${tab.charAt(0).toUpperCase() + tab.slice(1)}`).classList.add('active');
}

// Set Days Functions (botones rápidos)
function setDaysAdd(days) {
    document.getElementById('modalDaysAdd').value = days;
}

function setDaysRemove(days) {
    document.getElementById('modalDaysRemove').value = days;
}

function setDaysSet(days) {
    document.getElementById('modalDaysSet').value = days;
}

// Add Days to Subscription
async function addDaysToSubscription() {
    const daysToAdd = parseInt(document.getElementById('modalDaysAdd').value);
    
    if (!daysToAdd || daysToAdd < 1 || daysToAdd > 365) {
        showMessage('modalMessage', '📅 Ingresa días válidos (1-365)', 'error');
        return;
    }
    
    try {
        const response = await fetch(`${API_URL}/admin/extend-subscription`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({ userId: currentUserId, days: daysToAdd })
        });
        
        const data = await response.json();
        
        if (data.success) {
            const totalDays = currentUserDaysLeft + daysToAdd;
            showMessage('modalMessage', `✅ Se agregaron ${daysToAdd} días. Total: ${totalDays} días`, 'success');
            setTimeout(() => {
                closeModal();
                loadUsers();
                loadStats();
            }, 2000);
        } else {
            showMessage('modalMessage', '❌ ' + data.message, 'error');
        }
    } catch (error) {
        showMessage('modalMessage', '❌ Error de conexión', 'error');
    }
}

// Remove Days from Subscription
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
    
    if (!confirm(`⚠️ ¿Seguro que deseas quitar ${daysToRemove} días?\n\nQuedarán: ${currentUserDaysLeft - daysToRemove} días`)) {
        return;
    }
    
    // Calcular nueva fecha restando días
    const newDays = currentUserDaysLeft - daysToRemove;
    
    try {
        const response = await fetch(`${API_URL}/admin/activate-subscription`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({ userId: currentUserId, days: newDays })
        });
        
        const data = await response.json();
        
        if (data.success) {
            showMessage('modalMessage', `✅ Se quitaron ${daysToRemove} días. Quedan: ${newDays} días`, 'success');
            setTimeout(() => {
                closeModal();
                loadUsers();
                loadStats();
            }, 2000);
        } else {
            showMessage('modalMessage', '❌ ' + data.message, 'error');
        }
    } catch (error) {
        showMessage('modalMessage', '❌ Error de conexión', 'error');
    }
}

// Set Exact Days
async function setExactDays() {
    const exactDays = parseInt(document.getElementById('modalDaysSet').value);
    
    if (!exactDays || exactDays < 1 || exactDays > 730) {
        showMessage('modalMessage', '📅 Ingresa días válidos (1-730)', 'error');
        return;
    }
    
    if (!confirm(`📅 ¿Establecer exactamente ${exactDays} días desde hoy?\n\nReemplazará los días actuales (${currentUserDaysLeft})`)) {
        return;
    }
    
    try {
        const response = await fetch(`${API_URL}/admin/activate-subscription`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({ userId: currentUserId, days: exactDays })
        });
        
        const data = await response.json();
        
        if (data.success) {
            showMessage('modalMessage', `✅ Establecidos ${exactDays} días desde hoy`, 'success');
            setTimeout(() => {
                closeModal();
                loadUsers();
                loadStats();
            }, 2000);
        } else {
            showMessage('modalMessage', '❌ ' + data.message, 'error');
        }
    } catch (error) {
        showMessage('modalMessage', '❌ Error de conexión', 'error');
    }
}

// Deactivate Subscription
// Deactivate Subscription
async function deactivateSubscription() {
    const reason = prompt('🚫 ¿Por qué deseas desactivar esta suscripción?\n\nEjemplos:\n• No pagó\n• Solicitó cancelación\n• Infracción de términos\n• Cambio de plan\n\nRazón:', '');
    
    if (reason === null) {
        // Usuario canceló
        return;
    }
    
    const finalReason = reason.trim() || 'Sin razón especificada';
    
    if (!confirm(`⚠️ ¿Confirmas desactivar esta suscripción?\n\nRazón: ${finalReason}\n\nEsta acción desactivará completamente el acceso del usuario.`)) {
        return;
    }
    
    try {
        const response = await fetch(`${API_URL}/admin/deactivate-subscription`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({ 
                userId: currentUserId, 
                reason: finalReason 
            })
        });
        
        const data = await response.json();
        
        if (data.success) {
            showMessage('modalMessage', `✅ Suscripción desactivada. ${data.daysLost ? `Días perdidos: ${data.daysLost}` : ''}`, 'success');
            setTimeout(() => {
                closeModal();
                loadUsers();
                loadStats();
            }, 1500);
        } else {
            showMessage('modalMessage', '❌ ' + data.message, 'error');
        }
    } catch (error) {
        showMessage('modalMessage', '❌ Error de conexión', 'error');
    }
}

// Load Audit Logs
async function loadAuditLogs() {
    document.getElementById('auditLoading').classList.remove('hidden');
    
    try {
        const response = await fetch(`${API_URL}/admin/audit-logs?limit=50`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        
        const data = await response.json();
        
        if (data.success) {
            const tbody = document.getElementById('auditTableBody');
            tbody.innerHTML = '';
            
            if (data.logs.length === 0) {
                tbody.innerHTML = '<tr><td colspan="4" style="text-align:center; padding:30px; color:#6b7280;">No hay registros</td></tr>';
                return;
            }
            
            data.logs.forEach(log => {
                const date = new Date(log.timestamp).toLocaleString('es-MX', {
                    day: '2-digit',
                    month: '2-digit',
                    hour: '2-digit',
                    minute: '2-digit'
                });
                const details = JSON.stringify(log.details, null, 2);
                
                const row = `
                    <tr>
                        <td class="hide-mobile">${date}</td>
                        <td><strong>${log.adminName || log.adminEmail}</strong></td>
                        <td><span style="background:#f3f4f6; padding:4px 8px; border-radius:6px; font-size:11px; font-weight:600;">${log.action}</span></td>
                        <td class="hide-mobile"><pre style="font-size:10px; max-width:250px; overflow:auto; background:#f9fafb; padding:8px; border-radius:6px;">${details}</pre></td>
                    </tr>
                `;
                tbody.innerHTML += row;
            });
        } else {
            showMessage('auditMessage', data.message, 'error');
        }
    } catch (error) {
        showMessage('auditMessage', 'Error cargando auditoría', 'error');
    } finally {
        document.getElementById('auditLoading').classList.add('hidden');
    }
}

// Load Admins
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
                const lastLogin = admin.lastLogin ? new Date(admin.lastLogin).toLocaleString('es-MX', {
                    day: '2-digit',
                    month: '2-digit',
                    hour: '2-digit',
                    minute: '2-digit'
                }) : 'Nunca';
                const statusBadge = admin.active ? 
                    '<span class="status-badge active">✅</span>' : 
                    '<span class="status-badge inactive">❌</span>';
                
                const isCurrentUser = admin.id === currentAdmin.id;
                
                const row = `
                    <tr>
                        <td>${admin.email}</td>
                        <td class="hide-mobile"><strong>${admin.name}</strong></td>
                        <td><span class="role-badge ${admin.role}">${admin.role}</span></td>
                        <td class="hide-mobile">${statusBadge}</td>
                        <td class="hide-mobile">${lastLogin}</td>
                        <td>
                            ${!isCurrentUser ? `
                                <div class="action-buttons">
                                    ${admin.active ? 
                                        `<button onclick="toggleAdminStatus('${admin.id}', false, '${admin.email}')" class="btn-small danger">🚫</button>` : 
                                        `<button onclick="toggleAdminStatus('${admin.id}', true, '${admin.email}')" class="btn-small">✅</button>`
                                    }
                                    <button onclick="openChangeRoleModal('${admin.id}', '${admin.email}', '${admin.role}')" class="btn-small secondary">🎭</button>
                                    <button onclick="deleteAdmin('${admin.id}', '${admin.email}')" class="btn-small danger">🗑️</button>
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

// Toggle Admin Status
async function toggleAdminStatus(adminId, activate, email) {
    const action = activate ? 'activar' : 'desactivar';
    if (!confirm(`¿Seguro que deseas ${action} a ${email}?`)) {
        return;
    }
    
    try {
        const response = await fetch(`${API_URL}/admin/toggle-admin-status`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({ adminId, active: activate })
        });
        
        const data = await response.json();
        
        if (data.success) {
            showMessage('adminsMessage', `✅ ${data.message}`, 'success');
            loadAdmins();
        } else {
            showMessage('adminsMessage', `❌ ${data.message}`, 'error');
        }
    } catch (error) {
        showMessage('adminsMessage', '❌ Error de conexión', 'error');
    }
}

// Delete Admin
async function deleteAdmin(adminId, email) {
    if (!confirm(`⚠️ ¿ESTÁS SEGURO que deseas ELIMINAR PERMANENTEMENTE a ${email}?\n\nEsta acción NO se puede deshacer.`)) {
        return;
    }
    
    if (!confirm(`🚨 ÚLTIMA CONFIRMACIÓN: Se eliminará completamente a ${email}`)) {
        return;
    }
    
    try {
        const response = await fetch(`${API_URL}/admin/delete-admin/${adminId}`, {
            method: 'DELETE',
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });
        
        const data = await response.json();
        
        if (data.success) {
            showMessage('adminsMessage', `✅ ${data.message}`, 'success');
            loadAdmins();
        } else {
            showMessage('adminsMessage', `❌ ${data.message}`, 'error');
        }
    } catch (error) {
        showMessage('adminsMessage', '❌ Error de conexión', 'error');
    }
}

// Open Change Role Modal
function openChangeRoleModal(adminId, email, currentRole) {
    const newRole = prompt(`Cambiar rol de ${email}\n\nRol actual: ${currentRole}\n\nNuevo rol (super_admin, vendedor, soporte):`, currentRole);
    
    if (!newRole || newRole === currentRole) {
        return;
    }
    
    const validRoles = ['super_admin', 'vendedor', 'soporte'];
    if (!validRoles.includes(newRole)) {
        alert('❌ Rol inválido. Debe ser: super_admin, vendedor o soporte');
        return;
    }
    
    changeAdminRole(adminId, newRole);
}

// Change Admin Role
async function changeAdminRole(adminId, newRole) {
    try {
        const response = await fetch(`${API_URL}/admin/change-role`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({ adminId, newRole })
        });
        
        const data = await response.json();
        
        if (data.success) {
            showMessage('adminsMessage', `✅ ${data.message}`, 'success');
            loadAdmins();
        } else {
            showMessage('adminsMessage', `❌ ${data.message}`, 'error');
        }
    } catch (error) {
        showMessage('adminsMessage', '❌ Error de conexión', 'error');
    }
}

// Create Admin
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
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify(newAdmin)
        });
        
        const data = await response.json();
        
        if (data.success) {
            showMessage('adminsMessage', '✅ Admin creado exitosamente', 'success');
            document.getElementById('createAdminForm').reset();
            loadAdmins();
        } else {
            showMessage('adminsMessage', '❌ ' + data.message, 'error');
        }
    } catch (error) {
        showMessage('adminsMessage', '❌ Error de conexión', 'error');
    }
});

// Show Tab
function showTab(tabName) {
    document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
    
    event.target.classList.add('active');
    document.getElementById(`tab${tabName.charAt(0).toUpperCase() + tabName.slice(1)}`).classList.add('active');
    
    if (tabName === 'audit') {
        loadAuditLogs();
    } else if (tabName === 'admins') {
        loadAdmins();
    }
}

// Show Message
function showMessage(elementId, message, type) {
    const element = document.getElementById(elementId);
    element.className = `message ${type}`;
    element.textContent = message;
    element.style.display = 'block';
    
    setTimeout(() => {
        element.style.display = 'none';
    }, 5000);
}

// Close modal on outside click
document.getElementById('subscriptionModal').addEventListener('click', function(e) {
    if (e.target === this) {
        closeModal();
    }
});



// Toggle password visibility
function togglePasswordVisibility(inputId, button) {
    const input = document.getElementById(inputId);
    
    if (input.type === 'password') {
        input.type = 'text';
        button.textContent = '🙈'; // Ojo cerrado
    } else {
        input.type = 'password';
        button.textContent = '👁️'; // Ojo abierto
    }
}


// Close modal on outside click
document.getElementById('subscriptionModal').addEventListener('click', function(e) {
    if (e.target === this) {
        closeModal();
    }
});