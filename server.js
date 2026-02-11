// server.js
const express = require('express');
const admin = require('firebase-admin');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
require('dotenv').config();

// Inicializar Firebase Admin
admin.initializeApp({
  credential: admin.credential.cert({
    projectId: process.env.FIREBASE_PROJECT_ID,
    clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
    privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n')
  })
});

const db = admin.firestore();
const app = express();

// Middlewares
app.use(cors());
app.use(express.json());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 50,
  message: { success: false, message: 'Demasiadas solicitudes' }
});

app.use('/api/', limiter);

// ============================================
// ENDPOINT: REGISTRO
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
// ENDPOINT: LOGIN
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
  console.log(`📡 Endpoints:`);
  console.log(`   POST /api/register`);
  console.log(`   POST /api/login`);
  console.log(`   POST /api/validate`);
  console.log(`   GET  /api/health`);
});
