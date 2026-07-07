// src/server.ts
import express from 'express';
import cors from 'cors';
import * as admin from 'firebase-admin';
import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import cookieSession from 'cookie-session';
import dotenv from 'dotenv';

dotenv.config();

// 1. Initialize Firebase Admin securely
const serviceAccountRaw = process.env.FIREBASE_SERVICE_ACCOUNT_KEY || '{}';
let serviceAccount;
try {
  serviceAccount = JSON.parse(serviceAccountRaw);
} catch (e) {
  console.error("Failed to parse FIREBASE_SERVICE_ACCOUNT_KEY. Make sure it's valid JSON.");
}

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});
const db = admin.firestore();

const app = express();

// Set up CORS so your frontend can communicate with this backend securely
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:5173';
app.use(cors({ 
  origin: FRONTEND_URL, 
  credentials: true // Crucial: allows secure cookies to be sent back and forth
}));
app.use(express.json({ limit: '10mb' })); // Increased limit just in case payload is large

// 2. Set up Secure Cookies
app.use(cookieSession({
  maxAge: 24 * 60 * 60 * 1000, // Session lasts for 1 day
  keys: [process.env.SESSION_SECRET || 'default_secret_key_change_in_production']
}));

app.use(passport.initialize());
app.use(passport.session());

// 3. Configure Google OAuth Strategy
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID || '',
    clientSecret: process.env.GOOGLE_CLIENT_SECRET || '',
    callbackURL: '/auth/google/callback',
    proxy: true // Trust the Render reverse proxy so redirect URLs are HTTPS
  },
  (accessToken, refreshToken, profile, done) => {
    // Save Google profile to our session cookie
    done(null, profile);
  }
));

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user: Express.User, done) => done(null, user));

// ==========================================
// AUTHENTICATION ROUTES
// ==========================================

// Frontend redirects here to start the login process
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

// Google redirects here after successful login
app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: FRONTEND_URL }), (req, res) => {
  res.redirect(FRONTEND_URL);
});

// Frontend calls this to check if user is logged in
app.get('/api/current-user', (req, res) => {
  res.json(req.user || null);
});

// Frontend redirects here to log out
app.get('/auth/logout', (req, res) => {
  req.logout(() => {
    res.redirect(FRONTEND_URL);
  });
});

// ==========================================
// SECURE DATABASE ROUTES
// ==========================================

// Middleware to protect routes
const requireAuth = (req: express.Request, res: express.Response, next: express.NextFunction) => {
  if (!req.user) return res.status(401).json({ error: 'Unauthorized' });
  next();
};

// --- Custom Properties ---
app.get('/api/custom-properties', requireAuth, async (req, res) => {
  try {
    const snapshot = await db.collection('custom_properties').get();
    const properties: any[] = [];
    snapshot.forEach(doc => properties.push({ id: doc.id, data: doc.data() }));
    res.json(properties);
  } catch (e: any) { res.status(500).json({ error: e.message }); }
});

app.post('/api/custom-properties', requireAuth, async (req, res) => {
  try {
    const { code, data } = req.body;
    await db.collection('custom_properties').doc(code).set(data);
    res.json({ success: true });
  } catch (e: any) { res.status(500).json({ error: e.message }); }
});

// --- Remote Profiles (Settings) ---
app.get('/api/remote-profiles', requireAuth, async (req, res) => {
  try {
    const doc = await db.collection('app_settings').doc('profile_rules').get();
    res.json(doc.exists ? doc.data() : null);
  } catch (e: any) { res.status(500).json({ error: e.message }); }
});

app.post('/api/remote-profiles', requireAuth, async (req, res) => {
  try {
    const { currentProfile, newRules } = req.body;
    await db.collection('app_settings').doc('profile_rules').set({ [currentProfile]: newRules }, { merge: true });
    res.json({ success: true });
  } catch (e: any) { res.status(500).json({ error: e.message }); }
});

// --- OOO Records ---
app.get('/api/ooo-logs/:profile', requireAuth, async (req, res) => {
  try {
    const profile = req.params.profile;
    const snapshot = await db.collection('ooo_logs').where('profile', '==', profile).get();
    const records: any[] = [];
    const today = new Date();
    today.setHours(0, 0, 0, 0);

    snapshot.forEach((doc: any) => {
      const data = doc.data();
      const endDate = data.endDate.toDate();
      if (endDate >= today) {
        records.push({
          id: doc.id,
          roomType: data.roomType,
          count: data.count || 1,
          startDate: data.startDate.toDate().toISOString(),
          endDate: endDate.toISOString(),
          profile: data.profile
        });
      }
    });
    res.json(records);
  } catch (e: any) { res.status(500).json({ error: e.message }); }
});

app.post('/api/ooo-logs', requireAuth, async (req, res) => {
  try {
    const record = req.body;
    record.startDate = new Date(record.startDate);
    record.endDate = new Date(record.endDate);
    const docRef = await db.collection('ooo_logs').add(record);
    res.json({ id: docRef.id });
  } catch (e: any) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/ooo-logs/:id', requireAuth, async (req, res) => {
  try {
    await db.collection('ooo_logs').doc(req.params.id).delete();
    res.json({ success: true });
  } catch (e: any) { res.status(500).json({ error: e.message }); }
});

// --- Completed Upgrades ---
app.get('/api/completed-upgrades/:userId', requireAuth, async (req, res) => {
  try {
    // Only allow users to fetch their own upgrades
    if ((req.user as any).id !== req.params.userId) return res.status(403).json({ error: 'Forbidden' });
    
    const snapshot = await db.collection('users').doc(req.params.userId).collection('completedUpgrades').get();
    const upgrades: any[] = [];
    snapshot.forEach((doc: any) => {
      const data = doc.data();
      data.firestoreId = doc.id;
      if (data.completedTimestamp) {
        data.completedTimestamp = data.completedTimestamp.toDate().toISOString();
      }
      upgrades.push(data);
    });
    res.json(upgrades);
  } catch (e: any) { res.status(500).json({ error: e.message }); }
});

app.post('/api/completed-upgrades/:userId', requireAuth, async (req, res) => {
  try {
    if ((req.user as any).id !== req.params.userId) return res.status(403).json({ error: 'Forbidden' });
    
    const upgrade = req.body;
    if (upgrade.completedTimestamp) upgrade.completedTimestamp = new Date(upgrade.completedTimestamp);
    
    const docRef = await db.collection('users').doc(req.params.userId).collection('completedUpgrades').add(upgrade);
    res.json({ firestoreId: docRef.id });
  } catch (e: any) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/completed-upgrades/:userId/:firestoreId', requireAuth, async (req, res) => {
  try {
    if ((req.user as any).id !== req.params.userId) return res.status(403).json({ error: 'Forbidden' });
    await db.collection('users').doc(req.params.userId).collection('completedUpgrades').doc(req.params.firestoreId).delete();
    res.json({ success: true });
  } catch (e: any) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/completed-upgrades/:userId/clear/:profile', requireAuth, async (req, res) => {
  try {
    if ((req.user as any).id !== req.params.userId) return res.status(403).json({ error: 'Forbidden' });
    
    const snapshot = await db.collection('users').doc(req.params.userId).collection('completedUpgrades').where('profile', '==', req.params.profile).get();
    if (snapshot.empty) return res.json({ count: 0 });
    
    const batch = db.batch();
    snapshot.docs.forEach((doc: any) => batch.delete(doc.ref));
    await batch.commit();
    res.json({ count: snapshot.size });
  } catch (e: any) { res.status(500).json({ error: e.message }); }
});

// --- Accepted Upgrades ---
app.get('/api/accepted-upgrades/:userId/:profile', requireAuth, async (req, res) => {
  try {
    if ((req.user as any).id !== req.params.userId) return res.status(403).json({ error: 'Forbidden' });
    
    const snapshot = await db.collection('users').doc(req.params.userId).collection('acceptedUpgrades').where('profile', '==', req.params.profile).get();
    const upgrades: any[] = [];
    snapshot.forEach(doc => upgrades.push(doc.data()));
    res.json(upgrades);
  } catch (e: any) { res.status(500).json({ error: e.message }); }
});

app.post('/api/accepted-upgrades/:userId/:profile', requireAuth, async (req, res) => {
  try {
    if ((req.user as any).id !== req.params.userId) return res.status(403).json({ error: 'Forbidden' });
    
    const { upgrades } = req.body;
    const profile = req.params.profile;
    const ref = db.collection('users').doc(req.params.userId).collection('acceptedUpgrades');
    
    const sanitize = (obj: any) => {
      const clean: any = {};
      Object.keys(obj).forEach(k => { if (obj[k] !== undefined) clean[k] = obj[k]; });
      clean.profile = profile;
      return clean;
    };

    const batch = db.batch();
    const existing = await ref.where('profile', '==', profile).get();
    existing.docs.forEach((doc: any) => batch.delete(doc.ref));

    upgrades.forEach((upg: any) => {
      const newDocRef = ref.doc();
      batch.set(newDocRef, sanitize(upg));
    });

    await batch.commit();
    res.json({ success: true });
  } catch (e: any) { res.status(500).json({ error: e.message }); }
});

// --- Lead Times & Cloud Data ---
app.get('/api/lead-times/:profile', requireAuth, async (req, res) => {
  try {
    const doc = await db.collection('property_analytics').doc(req.params.profile).get();
    res.json(doc.exists && doc.data()?.leadTimeStats ? doc.data()!.leadTimeStats : {});
  } catch (e: any) { res.status(500).json({ error: e.message }); }
});

app.post('/api/lead-times/:profile', requireAuth, async (req, res) => {
  try {
    const { roomData } = req.body;
    await db.collection('property_analytics').doc(req.params.profile).set({ 
      leadTimeStats: roomData, 
      updatedAt: admin.firestore.FieldValue.serverTimestamp() 
    }, { merge: true });
    res.json({ success: true });
  } catch (e: any) { res.status(500).json({ error: e.message }); }
});

app.get('/api/snt-data/:prefix', requireAuth, async (req, res) => {
  try {
    const doc = await db.collection('SNTData').doc(`${req.params.prefix}_latest`).get();
    res.json(doc.exists ? doc.data() : null);
  } catch (e: any) { res.status(500).json({ error: e.message }); }
});

app.get('/api/synxis-data/:prefix', requireAuth, async (req, res) => {
  try {
    const doc = await db.collection('SynxisData').doc(`${req.params.prefix}_latest`).get();
    res.json(doc.exists ? doc.data() : null);
  } catch (e: any) { res.status(500).json({ error: e.message }); }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Backend Server running on port ${PORT}`);
});
