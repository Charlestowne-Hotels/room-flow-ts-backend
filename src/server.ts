// src/server.ts
import express from 'express';
import cors from 'cors';
import * as admin from 'firebase-admin';
import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import cookieSession from 'cookie-session';
import dotenv from 'dotenv';
import { log, fail } from './logger';

dotenv.config();

// 1. Initialize Firebase Admin
const serviceAccountRaw = process.env.FIREBASE_SERVICE_ACCOUNT_KEY || '{}';
let serviceAccount;
try {
  serviceAccount = JSON.parse(serviceAccountRaw);
} catch (e) {
  log.error('Failed to parse FIREBASE_SERVICE_ACCOUNT_KEY.', e);
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
// Cookie security is an explicit deployment decision, not inferred from the
// frontend hostname. Set SECURE_COOKIES=true on any deployed environment.
const isProduction =
  process.env.SECURE_COOKIES === 'true' ||
  process.env.NODE_ENV === 'production' ||
  FRONTEND_URL.includes('onrender.com');
// ==========================================
// SESSION SECRET GUARD
// cookie-session signs (does not encrypt) session contents, so a known or weak
// secret lets anyone forge a cookie claiming role: 'Admin'. Refuse to start
// rather than degrade silently to a hardcoded default.
// ==========================================
const SESSION_SECRET = process.env.SESSION_SECRET;
if (!SESSION_SECRET || SESSION_SECRET.length < 32) {
  console.error(
    'FATAL: SESSION_SECRET is missing or too short (need 32+ chars). ' +
    'Set it in the environment before starting the server.'
  );
  process.exit(1);
}

app.use(cookieSession({
  name: 'session',
  maxAge: 24 * 60 * 60 * 1000, 
  keys: [SESSION_SECRET],
  secure: isProduction, 
  sameSite: isProduction ? 'none' : 'lax', 
  httpOnly: true
}));

// ==========================================
// FIX A: SLIDING SESSION EXPIRY
// cookie-session only re-issues the cookie when the session object changes.
// Touching a value on every request resets the 24h maxAge window, so active
// users don't get logged out mid-session (and stop hitting spurious 401s).
// ==========================================
app.use((req: express.Request, res: express.Response, next: express.NextFunction) => {
  if (req.session) {
    (req.session as any).nowInMinutes = Math.floor(Date.now() / 60000);
  }
  next();
});

app.use((req: express.Request, res: express.Response, next: express.NextFunction) => {
  if (req.session && !req.session.regenerate) req.session.regenerate = (cb: any) => cb();
  if (req.session && !req.session.save) req.session.save = (cb: any) => cb();
  next();
});

app.use(passport.initialize());
app.use(passport.session());

// ==========================================
// NEW SECURITY GATEKEEPER (WHITELIST)
// Google SSO is the only authentication method. Access is controlled solely by
// membership in the user_access collection.
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

// Blocks access to a property the user isn't assigned to (admins bypass). Expects a :profile route param.
const requirePropertyAccess = (req: express.Request, res: express.Response, next: express.NextFunction) => {
  const user = req.user as any;
  if (!user) return res.status(401).json({ error: 'Unauthorized' });
  if (user.role === 'Admin') return next();
  const profile = req.params.profile;
  const assigned = (user.assignedProperties || []).map((p: string) => p.toLowerCase());
  if (profile && assigned.includes(profile.toLowerCase())) return next();
  return res.status(403).json({ error: 'Not assigned to this property' });
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
      // Defensive: never send a credential hash to the client, even a leftover
      // one from a document written before password auth was removed.
      const { passwordHash, ...safe } = data;
      users.push(safe);
    });
    res.json(users);
  } catch (e: any) { fail(req, res, e); }
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
  } catch (e: any) { fail(req, res, e); }
});

// ==========================================
// ONE-TIME MIGRATION: per-user upgrade history -> shared per-property history.
// Idempotent: target doc IDs are derived from the source, so re-running
// overwrites rather than duplicating. Only completed upgrades are migrated —
// accepted upgrades are a transient working list and regenerate naturally.
// ==========================================
app.post('/api/admin/migrate-upgrades', requireAdmin, async (req, res) => {
  try {
    const userRefs = await db.collection('users').listDocuments();
    let migrated = 0, skipped = 0;
    const byProfile: Record<string, number> = {};

    for (const userRef of userRefs) {
      const snap = await userRef.collection('completedUpgrades').get();
      for (const doc of snap.docs) {
        const data = doc.data();
        if (!data.profile) { skipped++; continue; }
        await db.collection('properties').doc(data.profile)
          .collection('completedUpgrades').doc(`${userRef.id}_${doc.id}`)
          .set({ ...data, completedBy: data.completedBy || userRef.id }, { merge: true });
        byProfile[data.profile] = (byProfile[data.profile] || 0) + 1;
        migrated++;
      }
    }
    log.info('migrate-upgrades', { migrated, skipped, byProfile });
    res.json({ success: true, migrated, skipped, byProfile });
  } catch (e: any) { fail(req, res, e); }
});

// Delete User
app.delete('/api/admin/users/:email', requireAdmin, async (req, res) => {
  try {
    await db.collection('user_access').doc(req.params.email).delete();
    res.json({ success: true });
  } catch (e: any) { fail(req, res, e); }
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
  } catch (e: any) { fail(req, res, e); }
});

app.post('/api/custom-properties', requireAdmin, async (req, res) => {
  try {
    const { code, data } = req.body;
    await db.collection('custom_properties').doc(code).set(data);
    res.json({ success: true });
  } catch (e: any) { fail(req, res, e); }
});

app.get('/api/remote-profiles', requireAuth, async (req, res) => {
  try {
    const doc = await db.collection('app_settings').doc('profile_rules').get();
    res.json(doc.exists ? doc.data() : null);
  } catch (e: any) { fail(req, res, e); }
});

app.post('/api/remote-profiles', requireAuth, async (req, res) => {
  try {
    const { currentProfile, newRules } = req.body;
    await db.collection('app_settings').doc('profile_rules').set({ [currentProfile]: newRules }, { merge: true });
    res.json({ success: true });
  } catch (e: any) { fail(req, res, e); }
});

app.get('/api/ooo-logs/:profile', requireAuth, requirePropertyAccess, async (req, res) => {
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
  } catch (e: any) { fail(req, res, e); }
});

app.post('/api/ooo-logs', requireAuth, async (req, res) => {
  try {
    const record = req.body;
    record.startDate = new Date(record.startDate);
    record.endDate = new Date(record.endDate);
    const docRef = await db.collection('ooo_logs').add(record);
    res.json({ id: docRef.id });
  } catch (e: any) { fail(req, res, e); }
});

app.delete('/api/ooo-logs/:id', requireAuth, async (req, res) => {
  try {
    await db.collection('ooo_logs').doc(req.params.id).delete();
    res.json({ success: true });
  } catch (e: any) { fail(req, res, e); }
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
  } catch (e: any) { fail(req, res, e); }
});

app.post('/api/completed-upgrades/:userId', requireAuth, async (req, res) => {
  try {
    if ((req.user as any).id !== req.params.userId) return res.status(403).json({ error: 'Forbidden' });
    const upgrade = req.body;
    if (upgrade.completedTimestamp) upgrade.completedTimestamp = new Date(upgrade.completedTimestamp);
    const docRef = await db.collection('users').doc(req.params.userId).collection('completedUpgrades').add(upgrade);
    res.json({ firestoreId: docRef.id });
  } catch (e: any) { fail(req, res, e); }
});

app.delete('/api/completed-upgrades/:userId/:firestoreId', requireAuth, async (req, res) => {
  try {
    if ((req.user as any).id !== req.params.userId) return res.status(403).json({ error: 'Forbidden' });
    await db.collection('users').doc(req.params.userId).collection('completedUpgrades').doc(req.params.firestoreId).delete();
    res.json({ success: true });
  } catch (e: any) { fail(req, res, e); }
});

app.delete('/api/completed-upgrades/:userId/clear/:profile', requireAdmin, async (req, res) => {
  try {
    if ((req.user as any).id !== req.params.userId) return res.status(403).json({ error: 'Forbidden' });
    const snapshot = await db.collection('users').doc(req.params.userId).collection('completedUpgrades').where('profile', '==', req.params.profile).get();
    if (snapshot.empty) return res.json({ count: 0 });
    const batch = db.batch();
    snapshot.docs.forEach((doc: any) => batch.delete(doc.ref));
    await batch.commit();
    res.json({ count: snapshot.size });
  } catch (e: any) { fail(req, res, e); }
});

app.get('/api/accepted-upgrades/:userId/:profile', requireAuth, async (req, res) => {
  try {
    if ((req.user as any).id !== req.params.userId) return res.status(403).json({ error: 'Forbidden' });
    const snapshot = await db.collection('users').doc(req.params.userId).collection('acceptedUpgrades').where('profile', '==', req.params.profile).get();
    const upgrades: any[] = [];
    snapshot.forEach(doc => upgrades.push(doc.data()));
    res.json(upgrades);
  } catch (e: any) { fail(req, res, e); }
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
  } catch (e: any) { fail(req, res, e); }
});

app.get('/api/lead-times/:profile', requireAuth, async (req, res) => {
  try {
    const doc = await db.collection('property_analytics').doc(req.params.profile).get();
    res.json(doc.exists && doc.data()?.leadTimeStats ? doc.data()!.leadTimeStats : {});
  } catch (e: any) { fail(req, res, e); }
});

app.post('/api/lead-times/:profile', requireAuth, async (req, res) => {
  try {
    const { roomData } = req.body;
    await db.collection('property_analytics').doc(req.params.profile).set({ 
      leadTimeStats: roomData, 
      updatedAt: admin.firestore.FieldValue.serverTimestamp() 
    }, { merge: true });
    res.json({ success: true });
  } catch (e: any) { fail(req, res, e); }
});

app.get('/api/snt-data/:prefix', requireAuth, async (req, res) => {
  try {
    const doc = await db.collection('SNTData').doc(`${req.params.prefix}_latest`).get();
    res.json(doc.exists ? doc.data() : null);
  } catch (e: any) { fail(req, res, e); }
});

app.get('/api/synxis-data/:prefix', requireAuth, async (req, res) => {
  try {
    const doc = await db.collection('SynxisData').doc(`${req.params.prefix}_latest`).get();
    res.json(doc.exists ? doc.data() : null);
  } catch (e: any) { fail(req, res, e); }
});

// Lightweight endpoint for cron-job.org to ping
app.get('/api/health', (req, res) => {
  res.status(200).send('Server is awake');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  log.info(`Backend server listening on port ${PORT}`);
});
