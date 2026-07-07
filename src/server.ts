// src/server.ts
import express from 'express';
import cors from 'cors';
import * as admin from 'firebase-admin';
import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import cookieSession from 'cookie-session';
import dotenv from 'dotenv';

dotenv.config();

// 1. Initialize Firebase Admin
const serviceAccountRaw = process.env.FIREBASE_SERVICE_ACCOUNT_KEY || '{}';
let serviceAccount;
try {
  serviceAccount = JSON.parse(serviceAccountRaw);
} catch (e) {
  console.error("Failed to parse FIREBASE_SERVICE_ACCOUNT_KEY.");
}

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});
const db = admin.firestore();
const app = express();

const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:5173';
app.use(cors({ origin: FRONTEND_URL, credentials: true }));
app.use(express.json({ limit: '10mb' })); 

app.set('trust proxy', 1);
const isProduction = process.env.NODE_ENV === 'production' || FRONTEND_URL.includes('onrender.com');

app.use(cookieSession({
  name: 'session',
  maxAge: 24 * 60 * 60 * 1000, 
  keys: [process.env.SESSION_SECRET || 'default_secret_key'],
  secure: isProduction, 
  sameSite: isProduction ? 'none' : 'lax', 
  httpOnly: true
}));

app.use((req: express.Request, res: express.Response, next: express.NextFunction) => {
  if (req.session && !req.session.regenerate) req.session.regenerate = (cb: any) => cb();
  if (req.session && !req.session.save) req.session.save = (cb: any) => cb();
  next();
});

app.use(passport.initialize());
app.use(passport.session());

// ==========================================
// NEW SECURITY GATEKEEPER (WHITELIST)
// ==========================================
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID || '',
    clientSecret: process.env.GOOGLE_CLIENT_SECRET || '',
    callbackURL: '/auth/google/callback',
    proxy: true 
  },
  async (accessToken, refreshToken, profile, done) => {
    try {
      const email = profile.emails?.[0]?.value?.toLowerCase();
      if (!email) return done(new Error("No email found"), false);

      // CHANGE THIS TO YOUR ACTUAL EMAIL TO BOOTSTRAP YOUR FIRST ACCOUNT
      const SUPER_ADMIN_EMAIL = 'jryan@charlestownehotels.com'; 

      const userRef = db.collection('user_access').doc(email);
      const userDoc = await userRef.get();

      // If user isn't in DB and isn't the Super Admin, reject them
      if (!userDoc.exists && email !== SUPER_ADMIN_EMAIL) {
        return done(null, false, { message: 'unauthorized' }); 
      }

      // If Super Admin logs in for the very first time, create their Admin profile
      if (!userDoc.exists && email === SUPER_ADMIN_EMAIL) {
        await userRef.set({
          name: profile.displayName,
          email: email,
          role: 'Admin',
          assignedProperties: [],
          lastSignIn: new Date()
        });
      } else {
        // Update last sign in for existing users
        await userRef.update({ lastSignIn: new Date() });
      }

      // Fetch fresh data
      const freshUserDoc = await userRef.get();
      const userData = freshUserDoc.data();

      // Build the secure session object
      const sessionUser = {
        id: profile.id,
        email: email,
        name: profile.displayName || userData?.name,
        role: userData?.role || 'Property User',
        assignedProperties: userData?.assignedProperties || []
      };

      done(null, sessionUser);
    } catch (error) {
      done(error, false);
    }
  }
));

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user: Express.User, done) => done(null, user));

// ==========================================
// AUTHENTICATION ROUTES
// ==========================================
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

// Custom callback to handle rejected logins gracefully
app.get('/auth/google/callback', (req, res, next) => {
  passport.authenticate('google', (err: any, user: any, info: any) => {
    if (err || !user) {
      // User is not whitelisted, send them back to frontend with an error flag
      return res.redirect(`${FRONTEND_URL}?error=unauthorized`);
    }
    req.logIn(user, (loginErr) => {
      if (loginErr) return next(loginErr);
      return res.redirect(FRONTEND_URL);
    });
  })(req, res, next);
});

app.get('/api/current-user', (req, res) => res.json(req.user || null));
app.get('/auth/logout', (req, res) => {
  req.logout(() => res.redirect(FRONTEND_URL));
});

// ==========================================
// MIDDLEWARE
// ==========================================
const requireAuth = (req: express.Request, res: express.Response, next: express.NextFunction) => {
  if (!req.user) return res.status(401).json({ error: 'Unauthorized' });
  next();
};

const requireAdmin = (req: express.Request, res: express.Response, next: express.NextFunction) => {
  if (!req.user || (req.user as any).role !== 'Admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

// ==========================================
// ADMIN PORTAL ROUTES (NEW)
// ==========================================
// Get all users
app.get('/api/admin/users', requireAdmin, async (req, res) => {
  try {
    const snapshot = await db.collection('user_access').get();
    const users: any[] = [];
    snapshot.forEach(doc => {
      const data = doc.data();
      if (data.lastSignIn) data.lastSignIn = data.lastSignIn.toDate().toISOString();
      users.push(data);
    });
    res.json(users);
  } catch (e: any) { res.status(500).json({ error: e.message }); }
});

// Add or Update User
app.post('/api/admin/users', requireAdmin, async (req, res) => {
  try {
    const { email, name, role, assignedProperties } = req.body;
    const cleanEmail = email.toLowerCase();
    
    await db.collection('user_access').doc(cleanEmail).set({
      email: cleanEmail,
      name,
      role,
      assignedProperties: assignedProperties || [],
      updatedAt: new Date()
    }, { merge: true }); // Merge true keeps lastSignIn if it exists
    
    res.json({ success: true });
  } catch (e: any) { res.status(500).json({ error: e.message }); }
});

// Delete User
app.delete('/api/admin/users/:email', requireAdmin, async (req, res) => {
  try {
    await db.collection('user_access').doc(req.params.email).delete();
    res.json({ success: true });
  } catch (e: any) { res.status(500).json({ error: e.message }); }
});


// ==========================================
// STANDARD DATABASE ROUTES (Existing)
// ==========================================
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

app.get('/api/completed-upgrades/:userId', requireAuth, async (req, res) => {
  try {
    if ((req.user as any).id !== req.params.userId) return res.status(403).json({ error: 'Forbidden' });
    const snapshot = await db.collection('users').doc(req.params.userId).collection('completedUpgrades').get();
    const upgrades: any[] = [];
    snapshot.forEach((doc: any) => {
      const data = doc.data();
      data.firestoreId = doc.id;
      if (data.completedTimestamp) data.completedTimestamp = data.completedTimestamp.toDate().toISOString();
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
    upgrades.forEach((upg: any) => batch.set(ref.doc(), sanitize(upg)));
    await batch.commit();
    res.json({ success: true });
  } catch (e: any) { res.status(500).json({ error: e.message }); }
});

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
