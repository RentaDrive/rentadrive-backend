// server.js
const express = require('express');
const admin = require('firebase-admin');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
require('dotenv').config();

// Inicializar Firebase Admin
let privateKey = process.env.FIREBASE_PRIVATE_KEY;

// Eliminar comillas si existen
if (privateKey && privateKey.startsWith('"') && privateKey.endsWith('"')) {
  privateKey = privateKey.slice(1, -1);
}

// Reemplazar \\n por \n
if (privateKey) {
  privateKey = privateKey.replace(/\\n/g, '\n');
}

admin.initializeApp({
  credential: admin.credential.cert({
    projectId: process.env.FIREBASE_PROJECT_ID,
    clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
    privateKey: privateKey
  })
});

const db = admin.firestore();
const app = express();

// Middlewares
app.use(cors());
app.use(express.json());

// Rate limiting general
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 50,
  message: { success: false, message: 'Demasiadas solicitudes' }
});

// Rate limiting estricto para admins
const adminLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { success: false, message: 'Demasiados intentos de admin' }
});

app.use('/api/', limiter);

// ============================================
// MIDDLEWARE: Autenticación de Admin
// ============================================
function authenticateAdmin(req, res, next) {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  
  if (!token) {
    return res.status(401).json({ 
      success: false, 
      message: 'Token no proporcionado' 
    });
  }
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.admin = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ 
      success: false, 
      message: 'Token inválido o expirado' 
    });
  }
}

// ============================================
// MIDDLEWARE: Verificar permisos
// ============================================
function requireRole(...allowedRoles) {
  return (req, res, next) => {
    if (!allowedRoles.includes(req.admin.role)) {
      return res.status(403).json({
        success: false,
        message: 'No tienes permisos para esta acción'
      });
    }
    next();
  };
}

// ============================================
// ENDPOINT: REGISTRO DE USUARIO
// ============================================
app.post('/api/register', async (req, res) => {
  try {
    const { email, password, deviceId } = req.body;
    
    console.log('📝 Registro nuevo:', email);
    
    if (!email || !password || !deviceId) {
      return res.status(400).json({ 
        success: false, 
        message: 'Datos incompletos' 
      });
    }
    
    if (password.length < 6) {
      return res.status(400).json({ 
        success: false, 
        message: 'Contraseña muy corta (mínimo 6 caracteres)' 
      });
    }
    
    const userRecord = await admin.auth().createUser({
      email,
      password,
      disabled: false
    });
    
    console.log('✅ Usuario creado:', userRecord.uid);
    
    await db.collection('users').doc(userRecord.uid).set({
      email,
      deviceId,
      subscriptionActive: false,
      subscriptionExpiry: null,
      plan: 'none',
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      registeredFrom: 'app'
    });
    
    res.json({
      success: true,
      userId: userRecord.uid,
      message: 'Usuario registrado exitosamente'
    });
    
  } catch (error) {
    console.error('❌ Error:', error);
    const message = error.code === 'auth/email-already-exists' 
      ? 'Este email ya está registrado' 
      : 'Error al registrar usuario';
    res.status(400).json({ success: false, message });
  }
});

// ============================================
// ENDPOINT: LOGIN DE USUARIO
// ============================================
app.post('/api/login', async (req, res) => {
  try {
    const { email, password, deviceId } = req.body;
    
    console.log('🔑 Login:', email);
    
    if (!email || !password || !deviceId) {
      return res.status(400).json({ 
        success: false, 
        message: 'Datos incompletos' 
      });
    }
    
    let userRecord;
    try {
      userRecord = await admin.auth().getUserByEmail(email);
    } catch (error) {
      return res.status(401).json({ 
        success: false, 
        message: 'Credenciales incorrectas' 
      });
    }
    
    const userDoc = await db.collection('users').doc(userRecord.uid).get();
    
    if (!userDoc.exists) {
      return res.status(401).json({ 
        success: false, 
        message: 'Usuario sin suscripción activa' 
      });
    }
    
    const userData = userDoc.data();
    
    if (userData.deviceId && userData.deviceId !== deviceId) {
      console.log('⚠️ Dispositivo no autorizado');
      
      await db.collection('security_logs').add({
        userId: userRecord.uid,
        email,
        attemptedDevice: deviceId,
        authorizedDevice: userData.deviceId,
        timestamp: admin.firestore.FieldValue.serverTimestamp(),
        type: 'unauthorized_device'
      });
      
      return res.status(403).json({ 
        success: false, 
        message: 'Dispositivo no autorizado. Contacta al vendedor.' 
      });
    }
    
    if (!userData.deviceId) {
      await db.collection('users').doc(userRecord.uid).update({ 
        deviceId,
        firstLogin: admin.firestore.FieldValue.serverTimestamp()
      });
      console.log('✅ Dispositivo registrado');
    }
    
    const isActive = userData.subscriptionActive === true;
    const expiry = userData.subscriptionExpiry?.toMillis() || 0;
    const now = Date.now();
    const isValid = isActive && now < expiry;
    
    if (!isValid) {
      return res.status(403).json({ 
        success: false, 
        message: 'Suscripción expirada o inactiva',
        expiry 
      });
    }
    
    const daysLeft = Math.floor((expiry - now) / (1000 * 60 * 60 * 24));
    console.log(`✅ Login exitoso - ${daysLeft} días`);
    
    const customToken = await admin.auth().createCustomToken(userRecord.uid);
    
    // Actualizar último login
    await db.collection('users').doc(userRecord.uid).update({
      lastLogin: admin.firestore.FieldValue.serverTimestamp()
    });
    
    res.json({
      success: true,
      userId: userRecord.uid,
      token: customToken,
      expiry,
      daysLeft,
      message: 'Login exitoso'
    });
    
  } catch (error) {
    console.error('❌ Error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Error del servidor' 
    });
  }
});

// ============================================
// ENDPOINT: VALIDAR LICENCIA
// ============================================
app.post('/api/validate', async (req, res) => {
  try {
    const { userId, deviceId, timestamp } = req.body;
    
    console.log('🔍 Validando:', userId);
    
    if (!userId || !deviceId || !timestamp) {
      return res.status(400).json({ 
        valid: false, 
        message: 'Datos incompletos' 
      });
    }
    
    const timeDiff = Date.now() - timestamp;
    if (Math.abs(timeDiff) > 300000) {
      console.log('⚠️ Timestamp inválido');
      return res.status(400).json({ 
        valid: false, 
        message: 'Timestamp inválido' 
      });
    }
    
    const userDoc = await db.collection('users').doc(userId).get();
    
    if (!userDoc.exists) {
      return res.json({ valid: false, message: 'Usuario no encontrado' });
    }
    
    const userData = userDoc.data();
    
    if (userData.deviceId !== deviceId) {
      console.log('⚠️ Device mismatch');
      await db.collection('security_logs').add({
        userId,
        attemptedDevice: deviceId,
        authorizedDevice: userData.deviceId,
        timestamp: admin.firestore.FieldValue.serverTimestamp(),
        type: 'device_mismatch'
      });
      
      return res.json({ 
        valid: false, 
        message: 'Dispositivo no autorizado' 
      });
    }
    
    const isActive = userData.subscriptionActive === true;
    const expiry = userData.subscriptionExpiry?.toMillis() || 0;
    const now = Date.now();
    const isValid = isActive && now < expiry;
    const daysLeft = Math.floor((expiry - now) / (1000 * 60 * 60 * 24));
    
    await db.collection('users').doc(userId).update({
      lastValidation: admin.firestore.FieldValue.serverTimestamp(),
      validationCount: admin.firestore.FieldValue.increment(1)
    });
    
    console.log(`${isValid ? '✅' : '⚠️'} ${isValid ? 'Válida' : 'Expirada'}`);
    
    res.json({
      valid: isValid,
      expiry,
      daysLeft: Math.max(0, daysLeft),
      message: isValid ? 'Licencia válida' : 'Licencia expirada'
    });
    
  } catch (error) {
    console.error('❌ Error:', error);
    res.status(500).json({ 
      valid: false, 
      message: 'Error del servidor' 
    });
  }
});

// ============================================
// ENDPOINT: LOGIN DE ADMIN
// ============================================
app.post('/api/admin/login', adminLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    
    console.log('🔐 Intento de login admin:', email);
    
    if (!email || !password) {
      return res.status(400).json({ 
        success: false, 
        message: 'Email y contraseña requeridos' 
      });
    }
    
    // Buscar admin en Firestore
    const adminSnapshot = await db.collection('admins')
      .where('email', '==', email)
      .where('active', '==', true)
      .get();
    
    if (adminSnapshot.empty) {
      console.log('⚠️ Admin no encontrado o inactivo');
      return res.status(401).json({ 
        success: false, 
        message: 'Credenciales incorrectas' 
      });
    }
    
    const adminDoc = adminSnapshot.docs[0];
    const adminData = adminDoc.data();
    
    // Verificar contraseña
    const passwordMatch = await bcrypt.compare(password, adminData.passwordHash);
    
    if (!passwordMatch) {
      console.log('⚠️ Contraseña incorrecta');
      return res.status(401).json({ 
        success: false, 
        message: 'Credenciales incorrectas' 
      });
    }
    
    // Generar JWT token
    const token = jwt.sign(
      { 
        adminId: adminDoc.id,
        email: adminData.email,
        name: adminData.name,
        role: adminData.role,
        timestamp: Date.now()
      },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );
    
    // Actualizar último login
    await db.collection('admins').doc(adminDoc.id).update({
      lastLogin: admin.firestore.FieldValue.serverTimestamp()
    });
    
    console.log(`✅ Login admin exitoso: ${email} (${adminData.role})`);
    
    res.json({
      success: true,
      token: token,
      admin: {
        id: adminDoc.id,
        email: adminData.email,
        name: adminData.name,
        role: adminData.role
      },
      expiresIn: 86400,
      message: 'Login exitoso'
    });
    
  } catch (error) {
    console.error('❌ Error en login admin:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Error del servidor' 
    });
  }
});

// ============================================
// ENDPOINT: CREAR NUEVO ADMIN (solo super_admin)
// ============================================
app.post('/api/admin/create-admin', authenticateAdmin, requireRole('super_admin'), async (req, res) => {
  try {
    const { email, password, name, role } = req.body;
    
    console.log(`📝 Creando nuevo admin: ${email}`);
    
    if (!email || !password || !name || !role) {
      return res.status(400).json({ 
        success: false, 
        message: 'Todos los campos son requeridos' 
      });
    }
    
    // Validar roles permitidos
    const validRoles = ['super_admin', 'vendedor', 'soporte'];
    if (!validRoles.includes(role)) {
      return res.status(400).json({ 
        success: false, 
        message: `Rol inválido. Roles permitidos: ${validRoles.join(', ')}` 
      });
    }
    
    // Verificar si el email ya existe
    const existingAdmin = await db.collection('admins')
      .where('email', '==', email)
      .get();
    
    if (!existingAdmin.empty) {
      return res.status(400).json({ 
        success: false, 
        message: 'El email ya está registrado' 
      });
    }
    
    // Hash de la contraseña
    const passwordHash = await bcrypt.hash(password, 10);
    
    // Crear admin en Firestore
    const adminDoc = await db.collection('admins').add({
      email,
      passwordHash,
      name,
      role,
      active: true,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      createdBy: req.admin.email
    });
    
    // Registrar en audit log
    await db.collection('audit_logs').add({
      adminId: req.admin.adminId,
      adminEmail: req.admin.email,
      adminName: req.admin.name,
      action: 'create_admin',
      targetEmail: email,
      details: { name, role },
      timestamp: admin.firestore.FieldValue.serverTimestamp()
    });
    
    console.log(`✅ Nuevo admin creado: ${email} (${role}) por ${req.admin.email}`);
    
    res.json({
      success: true,
      message: 'Admin creado exitosamente',
      admin: {
        id: adminDoc.id,
        email,
        name,
        role
      }
    });
    
  } catch (error) {
    console.error('❌ Error creando admin:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Error del servidor' 
    });
  }
});

// ============================================
// ENDPOINT: LISTAR USUARIOS
// ============================================
app.get('/api/admin/users', authenticateAdmin, async (req, res) => {
  try {
    const usersSnapshot = await db.collection('users').get();
    const users = [];
    
    usersSnapshot.forEach(doc => {
      const data = doc.data();
      users.push({
        userId: doc.id,
        email: data.email,
        deviceId: data.deviceId,
        subscriptionActive: data.subscriptionActive || false,
        subscriptionExpiry: data.subscriptionExpiry?.toDate().toISOString() || null,
        plan: data.plan || 'none',
        createdAt: data.createdAt?.toDate().toISOString() || null,
        lastLogin: data.lastLogin?.toDate().toISOString() || null
      });
    });
    
    res.json({
      success: true,
      count: users.length,
      users: users
    });
    
  } catch (error) {
    console.error('❌ Error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Error del servidor' 
    });
  }
});

// ============================================
// ENDPOINT: ACTIVAR SUSCRIPCIÓN
// ============================================
app.post('/api/admin/activate-subscription', authenticateAdmin, requireRole('super_admin', 'vendedor'), async (req, res) => {
  try {
    const { userId, days } = req.body;
    
    console.log(`🔧 Activando suscripción: ${userId} - ${days} días`);
    
    if (!userId || !days) {
      return res.status(400).json({ 
        success: false, 
        message: 'userId y days son requeridos' 
      });
    }
    
    // Calcular fecha de expiración
    const expiryDate = new Date();
    expiryDate.setDate(expiryDate.getDate() + parseInt(days));
    
    // Actualizar usuario
    await db.collection('users').doc(userId).update({
      subscriptionActive: true,
      subscriptionExpiry: admin.firestore.Timestamp.fromDate(expiryDate),
      plan: 'premium',
      lastModifiedBy: req.admin.email,
      lastModifiedAt: admin.firestore.FieldValue.serverTimestamp()
    });
    
    // Registrar en audit log
    await db.collection('audit_logs').add({
      adminId: req.admin.adminId,
      adminEmail: req.admin.email,
      adminName: req.admin.name,
      action: 'activate_subscription',
      userId: userId,
      details: { 
        days: parseInt(days),
        expiryDate: expiryDate.toISOString(),
        plan: 'premium'
      },
      timestamp: admin.firestore.FieldValue.serverTimestamp()
    });
    
    console.log(`✅ Suscripción activada por ${req.admin.email}: ${userId} - ${days} días`);
    
    res.json({
      success: true,
      message: `Suscripción activada por ${days} días`,
      userId: userId,
      expiryDate: expiryDate.toISOString(),
      daysActivated: parseInt(days),
      activatedBy: req.admin.email
    });
    
  } catch (error) {
    console.error('❌ Error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Error del servidor' 
    });
  }
});

// ============================================
// ENDPOINT: LISTAR ADMINS (solo super_admin)
// ============================================
app.get('/api/admin/list-admins', authenticateAdmin, requireRole('super_admin'), async (req, res) => {
  try {
    const adminsSnapshot = await db.collection('admins').get();
    const admins = [];
    
    adminsSnapshot.forEach(doc => {
      const data = doc.data();
      admins.push({
        id: doc.id,
        email: data.email,
        name: data.name,
        role: data.role,
        active: data.active,
        createdAt: data.createdAt?.toDate().toISOString(),
        createdBy: data.createdBy,
        lastLogin: data.lastLogin?.toDate().toISOString()
      });
    });
    
    res.json({
      success: true,
      count: admins.length,
      admins: admins
    });
    
  } catch (error) {
    console.error('❌ Error:', error);
    res.status(500).json({ success: false, message: 'Error del servidor' });
  }
});

// ============================================
// ENDPOINT: VER AUDIT LOGS
// ============================================
app.get('/api/admin/audit-logs', authenticateAdmin, async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 50;
    
    const logsSnapshot = await db.collection('audit_logs')
      .orderBy('timestamp', 'desc')
      .limit(limit)
      .get();
    
    const logs = [];
    logsSnapshot.forEach(doc => {
      const data = doc.data();
      logs.push({
        id: doc.id,
        adminEmail: data.adminEmail,
        adminName: data.adminName,
        action: data.action,
        userId: data.userId,
        targetEmail: data.targetEmail,
        details: data.details,
        timestamp: data.timestamp?.toDate().toISOString()
      });
    });
    
    res.json({
      success: true,
      count: logs.length,
      logs: logs
    });
    
  } catch (error) {
    console.error('❌ Error:', error);
    res.status(500).json({ success: false, message: 'Error del servidor' });
  }
});

// ============================================
// ENDPOINT: DESACTIVAR/ACTIVAR ADMIN (solo super_admin)
// ============================================
app.post('/api/admin/toggle-admin-status', authenticateAdmin, requireRole('super_admin'), async (req, res) => {
  try {
    const { adminId, active } = req.body;
    
    if (!adminId || typeof active !== 'boolean') {
      return res.status(400).json({ 
        success: false, 
        message: 'adminId y active (boolean) son requeridos' 
      });
    }
    
    // No permitir desactivarse a sí mismo
    if (adminId === req.admin.adminId) {
      return res.status(400).json({ 
        success: false, 
        message: 'No puedes desactivarte a ti mismo' 
      });
    }
    
    await db.collection('admins').doc(adminId).update({
      active: active,
      modifiedBy: req.admin.email,
      modifiedAt: admin.firestore.FieldValue.serverTimestamp()
    });
    
    // Registrar en audit log
    await db.collection('audit_logs').add({
      adminId: req.admin.adminId,
      adminEmail: req.admin.email,
      adminName: req.admin.name,
      action: active ? 'activate_admin' : 'deactivate_admin',
      targetAdminId: adminId,
      timestamp: admin.firestore.FieldValue.serverTimestamp()
    });
    
    console.log(`✅ Admin ${active ? 'activado' : 'desactivado'}: ${adminId} por ${req.admin.email}`);
    
    res.json({
      success: true,
      message: `Admin ${active ? 'activado' : 'desactivado'} exitosamente`
    });
    
  } catch (error) {
    console.error('❌ Error:', error);
    res.status(500).json({ success: false, message: 'Error del servidor' });
  }
});

// ============================================
// ENDPOINT: HEALTH CHECK
// ============================================
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    message: 'Servidor RentaDrive OK' 
  });
});

// ============================================
// ENDPOINT: EXTENDER SUSCRIPCIÓN
// ============================================
app.post('/api/admin/extend-subscription', authenticateAdmin, requireRole('super_admin', 'vendedor'), async (req, res) => {
  try {
    const { userId, days } = req.body;
    
    console.log(`➕ Extendiendo suscripción: ${userId} + ${days} días`);
    
    if (!userId || !days) {
      return res.status(400).json({ 
        success: false, 
        message: 'userId y days son requeridos' 
      });
    }
    
    const userDoc = await db.collection('users').doc(userId).get();
    
    if (!userDoc.exists) {
      return res.status(404).json({ 
        success: false, 
        message: 'Usuario no encontrado' 
      });
    }
    
    const userData = userDoc.data();
    let newExpiryDate;
    
    // Si ya tiene suscripción activa, extender desde la fecha actual de expiración
    if (userData.subscriptionExpiry && userData.subscriptionActive) {
      newExpiryDate = userData.subscriptionExpiry.toDate();
      newExpiryDate.setDate(newExpiryDate.getDate() + parseInt(days));
    } else {
      // Si no tiene suscripción o está inactiva, empezar desde hoy
      newExpiryDate = new Date();
      newExpiryDate.setDate(newExpiryDate.getDate() + parseInt(days));
    }
    
    await db.collection('users').doc(userId).update({
      subscriptionActive: true,
      subscriptionExpiry: admin.firestore.Timestamp.fromDate(newExpiryDate),
      plan: 'premium',
      lastModifiedBy: req.admin.email,
      lastModifiedAt: admin.firestore.FieldValue.serverTimestamp()
    });
    
    // Registrar en audit log
    await db.collection('audit_logs').add({
      adminId: req.admin.adminId,
      adminEmail: req.admin.email,
      adminName: req.admin.name,
      action: 'extend_subscription',
      userId: userId,
      details: { 
        daysAdded: parseInt(days),
        newExpiryDate: newExpiryDate.toISOString(),
        previousExpiry: userData.subscriptionExpiry?.toDate().toISOString() || null
      },
      timestamp: admin.firestore.FieldValue.serverTimestamp()
    });
    
    console.log(`✅ Suscripción extendida por ${req.admin.email}: ${userId} + ${days} días`);
    
    res.json({
      success: true,
      message: `Suscripción extendida por ${days} días`,
      userId: userId,
      newExpiryDate: newExpiryDate.toISOString(),
      daysAdded: parseInt(days),
      modifiedBy: req.admin.email
    });
    
  } catch (error) {
    console.error('❌ Error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Error del servidor' 
    });
  }
});

// ============================================
// ENDPOINT: DESACTIVAR SUSCRIPCIÓN
// ============================================
app.post('/api/admin/deactivate-subscription', authenticateAdmin, requireRole('super_admin', 'vendedor'), async (req, res) => {
  try {
    const { userId, reason } = req.body;
    
    console.log(`🚫 Desactivando suscripción: ${userId}`);
    
    if (!userId) {
      return res.status(400).json({ 
        success: false, 
        message: 'userId es requerido' 
      });
    }
    
    const userDoc = await db.collection('users').doc(userId).get();
    
    if (!userDoc.exists) {
      return res.status(404).json({ 
        success: false, 
        message: 'Usuario no encontrado' 
      });
    }
    
    await db.collection('users').doc(userId).update({
      subscriptionActive: false,
      deactivatedAt: admin.firestore.FieldValue.serverTimestamp(),
      deactivatedBy: req.admin.email,
      deactivationReason: reason || 'No especificado',
      lastModifiedBy: req.admin.email,
      lastModifiedAt: admin.firestore.FieldValue.serverTimestamp()
    });
    
    // Registrar en audit log
    await db.collection('audit_logs').add({
      adminId: req.admin.adminId,
      adminEmail: req.admin.email,
      adminName: req.admin.name,
      action: 'deactivate_subscription',
      userId: userId,
      details: { 
        reason: reason || 'No especificado'
      },
      timestamp: admin.firestore.FieldValue.serverTimestamp()
    });
    
    console.log(`✅ Suscripción desactivada por ${req.admin.email}: ${userId}`);
    
    res.json({
      success: true,
      message: 'Suscripción desactivada',
      userId: userId,
      deactivatedBy: req.admin.email
    });
    
  } catch (error) {
    console.error('❌ Error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Error del servidor' 
    });
  }
});

// ============================================
// ENDPOINT: OBTENER ESTADÍSTICAS
// ============================================
app.get('/api/admin/stats', authenticateAdmin, async (req, res) => {
  try {
    const usersSnapshot = await db.collection('users').get();
    
    let totalUsers = 0;
    let activeSubscriptions = 0;
    let inactiveSubscriptions = 0;
    let expiredSubscriptions = 0;
    const now = Date.now();
    
    usersSnapshot.forEach(doc => {
      const data = doc.data();
      totalUsers++;
      
      const isActive = data.subscriptionActive === true;
      const expiry = data.subscriptionExpiry?.toMillis() || 0;
      const isValid = isActive && now < expiry;
      
      if (isValid) {
        activeSubscriptions++;
      } else if (isActive && now >= expiry) {
        expiredSubscriptions++;
      } else {
        inactiveSubscriptions++;
      }
    });
    
    // Contar admins
    const adminsSnapshot = await db.collection('admins').get();
    const totalAdmins = adminsSnapshot.size;
    
    res.json({
      success: true,
      stats: {
        totalUsers,
        activeSubscriptions,
        inactiveSubscriptions,
        expiredSubscriptions,
        totalAdmins
      }
    });
    
  } catch (error) {
    console.error('❌ Error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Error del servidor' 
    });
  }
});

// ============================================
// ENDPOINT: BUSCAR USUARIO POR EMAIL
// ============================================
app.get('/api/admin/search-user', authenticateAdmin, async (req, res) => {
  try {
    const { email } = req.query;
    
    if (!email) {
      return res.status(400).json({ 
        success: false, 
        message: 'Email es requerido' 
      });
    }
    
    const usersSnapshot = await db.collection('users')
      .where('email', '==', email)
      .get();
    
    if (usersSnapshot.empty) {
      return res.json({ 
        success: false, 
        message: 'Usuario no encontrado' 
      });
    }
    
    const userDoc = usersSnapshot.docs[0];
    const data = userDoc.data();
    
    res.json({
      success: true,
      user: {
        userId: userDoc.id,
        email: data.email,
        deviceId: data.deviceId,
        subscriptionActive: data.subscriptionActive || false,
        subscriptionExpiry: data.subscriptionExpiry?.toDate().toISOString() || null,
        plan: data.plan || 'none',
        createdAt: data.createdAt?.toDate().toISOString() || null,
        lastLogin: data.lastLogin?.toDate().toISOString() || null
      }
    });
    
  } catch (error) {
    console.error('❌ Error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Error del servidor' 
    });
  }
});



// Iniciar servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Servidor en puerto ${PORT}`);
  console.log(`📡 Endpoints públicos:`);
  console.log(`   POST /api/register`);
  console.log(`   POST /api/login`);
  console.log(`   POST /api/validate`);
  console.log(`   GET  /api/health`);
  console.log(`📡 Endpoints de Admin:`);
  console.log(`   POST /api/admin/login`);
  console.log(`   POST /api/admin/create-admin (super_admin)`);
  console.log(`   GET  /api/admin/users`);
  console.log(`   GET  /api/admin/list-admins (super_admin)`);
  console.log(`   POST /api/admin/activate-subscription`);
  console.log(`   GET  /api/admin/audit-logs`);
  console.log(`   POST /api/admin/toggle-admin-status (super_admin)`);
});
