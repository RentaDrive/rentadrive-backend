// server.js
const express = require('express');
const admin = require('firebase-admin');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const helmet = require('helmet');
const { body, validationResult } = require('express-validator');

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

// Confiar en proxies (Railway, Heroku, etc.)
app.set('trust proxy', 1);


// Middlewares de seguridad
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      scriptSrcAttr: ["'unsafe-inline'", "'unsafe-hashes'"],  // NUEVO: permite onclick
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
  crossOriginEmbedderPolicy: false
}));

app.use(cors());

// Limitar tamaño del body para prevenir ataques DoS
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// Servir el panel de administración
app.use('/admin', express.static('admin-panel'));

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
// FUNCIÓN: SANITIZAR STRINGS
// ============================================
function sanitizeString(str, maxLength = 200) {
  if (!str) return '';
  
  return String(str)
    .trim()
    .slice(0, maxLength)
    .replace(/[<>]/g, '')
    .replace(/javascript:/gi, '')
    .replace(/on\w+\s*=/gi, '');
}

// ============================================
// MIDDLEWARE: Logging de seguridad
// ============================================
app.use((req, res, next) => {
  const suspiciousPatterns = [
    /(\bunion\b.*\bselect\b)/i,
    /(\bor\b.*=.*)/i,
    /(javascript:|<script|onerror=)/i,
    /(\.\.\/)|(\.\.\\)/,
  ];
  
  const fullUrl = req.originalUrl + JSON.stringify(req.body);
  
  for (const pattern of suspiciousPatterns) {
    if (pattern.test(fullUrl)) {
      console.log('⚠️ SOSPECHOSO:', {
        ip: req.ip,
        url: req.originalUrl,
        method: req.method,
        timestamp: new Date().toISOString()
      });
      
      db.collection('security_alerts').add({
        type: 'suspicious_request',
        ip: req.ip,
        url: req.originalUrl,
        method: req.method,
        pattern: pattern.toString(),
        timestamp: admin.firestore.FieldValue.serverTimestamp()
      }).catch(err => console.error('Error logging security alert:', err));
      
      break;
    }
  }
  
  next();
});

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
// ENDPOINT: LOGIN DE USUARIO (CORREGIDO)
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
    
    // ✅ VALIDAR CONTRASEÑA CON FIREBASE AUTH
    let userRecord;
    try {
      // Intentar autenticar con Firebase Admin
      // Nota: Firebase Admin SDK no tiene método directo para validar contraseña
      // Tenemos que usar signInWithEmailAndPassword del cliente o verificar con custom token
      
      // Verificar que el usuario existe
      userRecord = await admin.auth().getUserByEmail(email);
      
      // IMPORTANTE: Firebase Admin NO puede validar contraseñas directamente
      // Necesitamos usar el REST API de Firebase Authentication
      const firebaseAuthUrl = `https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${process.env.FIREBASE_API_KEY}`;
      
      const authResponse = await fetch(firebaseAuthUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          email: email,
          password: password,
          returnSecureToken: true
        })
      });
      
      const authData = await authResponse.json();
      
      if (!authResponse.ok || authData.error) {
        console.log('⚠️ Contraseña incorrecta:', authData.error?.message);
        return res.status(401).json({ 
          success: false, 
          message: 'Credenciales incorrectas' 
        });
      }
      
      console.log('✅ Contraseña verificada correctamente');
      
    } catch (error) {
      console.log('⚠️ Error en autenticación:', error.message);
      return res.status(401).json({ 
        success: false, 
        message: 'Credenciales incorrectas' 
      });
    }
    
    const userDoc = await db.collection('users').doc(userRecord.uid).get();
    
    if (!userDoc.exists) {
      return res.status(401).json({ 
        success: false, 
        message: 'Usuario sin suscripción activa',
        userId: userRecord.uid
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
app.post('/api/admin/login', 
  adminLimiter,
  [
    body('email')
      .trim()
      .isEmail().withMessage('Email inválido')
      .normalizeEmail()
      .isLength({ max: 100 }).withMessage('Email muy largo'),
    body('password')
      .isLength({ min: 6, max: 100 }).withMessage('Contraseña debe tener entre 6-100 caracteres')
  ],
  async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      console.log('⚠️ Validación fallida:', errors.array());
      return res.status(400).json({ 
        success: false, 
        message: 'Datos inválidos',
        errors: errors.array()
      });
    }
    
    const { email, password } = req.body;
    
    console.log('🔐 Intento de login admin:', email);
    
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
    
    const passwordMatch = await bcrypt.compare(password, adminData.passwordHash);
    
    if (!passwordMatch) {
      console.log('⚠️ Contraseña incorrecta');
      return res.status(401).json({ 
        success: false, 
        message: 'Credenciales incorrectas' 
      });
    }
    
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
    
    const validRoles = ['super_admin', 'vendedor', 'soporte'];
    if (!validRoles.includes(role)) {
      return res.status(400).json({ 
        success: false, 
        message: `Rol inválido. Roles permitidos: ${validRoles.join(', ')}` 
      });
    }
    
    const existingAdmin = await db.collection('admins')
      .where('email', '==', email)
      .get();
    
    if (!existingAdmin.empty) {
      return res.status(400).json({ 
        success: false, 
        message: 'El email ya está registrado' 
      });
    }
    
    const passwordHash = await bcrypt.hash(password, 10);
    
    const adminDoc = await db.collection('admins').add({
      email,
      passwordHash,
      name,
      role,
      active: true,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      createdBy: req.admin.email
    });
    
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
// ENDPOINT: ACTIVAR/ESTABLECER DÍAS EXACTOS
// ============================================
app.post('/api/admin/activate-subscription', authenticateAdmin, requireRole('super_admin', 'vendedor'), async (req, res) => {
  try {
    const { userId, days } = req.body;
    
    console.log(`🔧 Estableciendo días exactos: ${userId} - ${days} días`);
    
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
    
    const now = new Date();
    const oldExpiry = userData.subscriptionExpiry?.toDate();
    const oldDaysLeft = oldExpiry && userData.subscriptionActive ? 
      Math.max(0, Math.floor((oldExpiry - now) / (1000 * 60 * 60 * 24))) : 0;
    
    const expiryDate = new Date();
    expiryDate.setDate(expiryDate.getDate() + parseInt(days));
    
    await db.collection('users').doc(userId).update({
      subscriptionActive: true,
      subscriptionExpiry: admin.firestore.Timestamp.fromDate(expiryDate),
      plan: 'premium',
      lastModifiedBy: req.admin.email,
      lastModifiedAt: admin.firestore.FieldValue.serverTimestamp()
    });
    
    await db.collection('audit_logs').add({
      adminId: req.admin.adminId,
      adminEmail: req.admin.email,
      adminName: req.admin.name,
      action: 'ESTABLECER_DIAS_EXACTOS',
      userId: userId,
      userEmail: userData.email,
      details: { 
        action: 'set_exact_days',
        previousDays: oldDaysLeft,
        newDays: parseInt(days),
        previousExpiry: oldExpiry?.toISOString() || null,
        newExpiry: expiryDate.toISOString(),
        wasActive: userData.subscriptionActive || false,
        description: `Estableció ${days} días exactos (antes tenía: ${oldDaysLeft} días)`
      },
      timestamp: admin.firestore.FieldValue.serverTimestamp()
    });
    
    console.log(`✅ Días establecidos por ${req.admin.email}: ${userId} - ${days} días (antes: ${oldDaysLeft})`);
    
    res.json({
      success: true,
      message: `Suscripción establecida con ${days} días`,
      userId: userId,
      expiryDate: expiryDate.toISOString(),
      daysSet: parseInt(days),
      previousDays: oldDaysLeft,
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
// ENDPOINT: EXTENDER/AGREGAR DÍAS
// ============================================
app.post('/api/admin/extend-subscription', authenticateAdmin, requireRole('super_admin', 'vendedor'), async (req, res) => {
  try {
    const { userId, days } = req.body;
    
    console.log(`➕ Agregando días: ${userId} + ${days} días`);
    
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
    
    const now = new Date();
    const currentExpiry = userData.subscriptionExpiry?.toDate() || now;
    const currentDaysLeft = userData.subscriptionActive ? 
      Math.max(0, Math.floor((currentExpiry - now) / (1000 * 60 * 60 * 24))) : 0;
    
    let newExpiryDate;
    
    if (userData.subscriptionActive && currentExpiry > now) {
      newExpiryDate = new Date(currentExpiry);
      newExpiryDate.setDate(newExpiryDate.getDate() + parseInt(days));
    } else {
      newExpiryDate = new Date();
      newExpiryDate.setDate(newExpiryDate.getDate() + parseInt(days));
    }
    
    const newDaysTotal = Math.floor((newExpiryDate - now) / (1000 * 60 * 60 * 24));
    
    await db.collection('users').doc(userId).update({
      subscriptionActive: true,
      subscriptionExpiry: admin.firestore.Timestamp.fromDate(newExpiryDate),
      plan: 'premium',
      lastModifiedBy: req.admin.email,
      lastModifiedAt: admin.firestore.FieldValue.serverTimestamp()
    });
    
    await db.collection('audit_logs').add({
      adminId: req.admin.adminId,
      adminEmail: req.admin.email,
      adminName: req.admin.name,
      action: 'AGREGAR_DIAS',
      userId: userId,
      userEmail: userData.email,
      details: { 
        action: 'add_days',
        daysAdded: parseInt(days),
        previousDays: currentDaysLeft,
        newDaysTotal: newDaysTotal,
        previousExpiry: userData.subscriptionExpiry?.toDate().toISOString() || null,
        newExpiry: newExpiryDate.toISOString(),
        description: `Agregó ${days} días (de ${currentDaysLeft} a ${newDaysTotal} días)`
      },
      timestamp: admin.firestore.FieldValue.serverTimestamp()
    });
    
    console.log(`✅ Días agregados por ${req.admin.email}: ${userId} + ${days} días (${currentDaysLeft} → ${newDaysTotal})`);
    
    res.json({
      success: true,
      message: `Se agregaron ${days} días. Total: ${newDaysTotal} días`,
      userId: userId,
      newExpiryDate: newExpiryDate.toISOString(),
      daysAdded: parseInt(days),
      previousDays: currentDaysLeft,
      newTotalDays: newDaysTotal,
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
    
    const userData = userDoc.data();
    
    const now = new Date();
    const oldExpiry = userData.subscriptionExpiry?.toDate();
    const daysLost = oldExpiry && userData.subscriptionActive ? 
      Math.max(0, Math.floor((oldExpiry - now) / (1000 * 60 * 60 * 24))) : 0;
    
    await db.collection('users').doc(userId).update({
      subscriptionActive: false,
      deactivatedAt: admin.firestore.FieldValue.serverTimestamp(),
      deactivatedBy: req.admin.email,
      deactivationReason: reason || 'No especificado',
      lastModifiedBy: req.admin.email,
      lastModifiedAt: admin.firestore.FieldValue.serverTimestamp()
    });
    
    await db.collection('audit_logs').add({
      adminId: req.admin.adminId,
      adminEmail: req.admin.email,
      adminName: req.admin.name,
      action: 'DESACTIVAR_SUSCRIPCION',
      userId: userId,
      userEmail: userData.email,
      details: { 
        action: 'deactivate',
        reason: reason || 'Sin razón especificada',
        daysLost: daysLost,
        previousExpiry: oldExpiry?.toISOString() || null,
        wasActive: userData.subscriptionActive || false,
        description: `Desactivó suscripción (perdió ${daysLost} días). Razón: ${reason || 'N/A'}`
      },
      timestamp: admin.firestore.FieldValue.serverTimestamp()
    });
    
    console.log(`✅ Suscripción desactivada por ${req.admin.email}: ${userId} (perdió ${daysLost} días)`);
    
    res.json({
      success: true,
      message: 'Suscripción desactivada',
      userId: userId,
      daysLost: daysLost,
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
    let { email } = req.query;
    
    if (!email) {
      return res.status(400).json({ 
        success: false, 
        message: 'Email es requerido' 
      });
    }
    
    email = email.trim().toLowerCase();
    
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email) || email.length > 100) {
      return res.status(400).json({ 
        success: false, 
        message: 'Formato de email inválido' 
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
    
    if (adminId === req.admin.adminId) {
      return res.status(400).json({ 
        success: false, 
        message: 'No puedes desactivarte a ti mismo' 
      });
    }
    
    const adminDoc = await db.collection('admins').doc(adminId).get();
    
    if (!adminDoc.exists) {
      return res.status(404).json({ 
        success: false, 
        message: 'Admin no encontrado' 
      });
    }
    
    await db.collection('admins').doc(adminId).update({
      active: active,
      modifiedBy: req.admin.email,
      modifiedAt: admin.firestore.FieldValue.serverTimestamp()
    });
    
    await db.collection('audit_logs').add({
      adminId: req.admin.adminId,
      adminEmail: req.admin.email,
      adminName: req.admin.name,
      action: active ? 'activate_admin' : 'deactivate_admin',
      targetAdminId: adminId,
      targetAdminEmail: adminDoc.data().email,
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
// ENDPOINT: ELIMINAR ADMIN PERMANENTEMENTE (solo super_admin)
// ============================================
app.delete('/api/admin/delete-admin/:adminId', authenticateAdmin, requireRole('super_admin'), async (req, res) => {
  try {
    const { adminId } = req.params;
    
    if (!adminId) {
      return res.status(400).json({ 
        success: false, 
        message: 'adminId es requerido' 
      });
    }
    
    if (adminId === req.admin.adminId) {
      return res.status(400).json({ 
        success: false, 
        message: 'No puedes eliminarte a ti mismo' 
      });
    }
    
    const adminDoc = await db.collection('admins').doc(adminId).get();
    
    if (!adminDoc.exists) {
      return res.status(404).json({ 
        success: false, 
        message: 'Admin no encontrado' 
      });
    }
    
    const adminData = adminDoc.data();
    
    await db.collection('admins').doc(adminId).delete();
    
    await db.collection('audit_logs').add({
      adminId: req.admin.adminId,
      adminEmail: req.admin.email,
      adminName: req.admin.name,
      action: 'delete_admin',
      targetAdminId: adminId,
      targetAdminEmail: adminData.email,
      targetAdminName: adminData.name,
      timestamp: admin.firestore.FieldValue.serverTimestamp()
    });
    
    console.log(`🗑️ Admin eliminado: ${adminData.email} por ${req.admin.email}`);
    
    res.json({
      success: true,
      message: `Admin ${adminData.email} eliminado permanentemente`
    });
    
  } catch (error) {
    console.error('❌ Error:', error);
    res.status(500).json({ success: false, message: 'Error del servidor' });
  }
});

// ============================================
// ENDPOINT: CAMBIAR ROL DE ADMIN (solo super_admin)
// ============================================
app.post('/api/admin/change-role', authenticateAdmin, requireRole('super_admin'), async (req, res) => {
  try {
    const { adminId, newRole } = req.body;
    
    if (!adminId || !newRole) {
      return res.status(400).json({ 
        success: false, 
        message: 'adminId y newRole son requeridos' 
      });
    }
    
    const validRoles = ['super_admin', 'vendedor', 'soporte'];
    if (!validRoles.includes(newRole)) {
      return res.status(400).json({ 
        success: false, 
        message: `Rol inválido. Roles permitidos: ${validRoles.join(', ')}` 
      });
    }
    
    if (adminId === req.admin.adminId) {
      return res.status(400).json({ 
        success: false, 
        message: 'No puedes cambiar tu propio rol' 
      });
    }
    
    const adminDoc = await db.collection('admins').doc(adminId).get();
    
    if (!adminDoc.exists) {
      return res.status(404).json({ 
        success: false, 
        message: 'Admin no encontrado' 
      });
    }
    
    const oldRole = adminDoc.data().role;
    
    await db.collection('admins').doc(adminId).update({
      role: newRole,
      modifiedBy: req.admin.email,
      modifiedAt: admin.firestore.FieldValue.serverTimestamp()
    });
    
    await db.collection('audit_logs').add({
      adminId: req.admin.adminId,
      adminEmail: req.admin.email,
      adminName: req.admin.name,
      action: 'change_admin_role',
      targetAdminId: adminId,
      targetAdminEmail: adminDoc.data().email,
      details: {
        oldRole: oldRole,
        newRole: newRole
      },
      timestamp: admin.firestore.FieldValue.serverTimestamp()
    });
    
    console.log(`✅ Rol cambiado: ${adminDoc.data().email} de ${oldRole} a ${newRole}`);
    
    res.json({
      success: true,
      message: `Rol cambiado de ${oldRole} a ${newRole}`
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
  console.log(`   POST /api/admin/extend-subscription`);
  console.log(`   POST /api/admin/deactivate-subscription`);
  console.log(`   GET  /api/admin/audit-logs`);
  console.log(`   POST /api/admin/toggle-admin-status (super_admin)`);
});
