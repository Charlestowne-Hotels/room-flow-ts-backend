import express from 'express';
import cors from 'cors';
import * as admin from 'firebase-admin';
import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import cookieSession from 'cookie-session';
import dotenv from 'dotenv';

dotenv.config();

// 1. Initialize Firebase Admin securely
const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_KEY || '{}');
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
app.use(express.json());

// 2. Set up Secure Cookies
app.use(cookieSession({
  maxAge: 24 * 60 * 60 * 1000, // Session lasts for 1 day
  keys: [process.env.SESSION_SECRET || 'default_secret_key'] // Used to encrypt the cookie
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
    // When Google authenticates the user, we just save their Google profile to our session cookie
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
  // Successful authentication, redirect back to frontend
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

// Example: Get Custom Properties from Firestore
app.get('/api/custom-properties', requireAuth, async (req, res) => {
  try {
    const snapshot = await db.collection('custom_properties').get();
    const properties: any[] = [];
    snapshot.forEach(doc => properties.push({ id: doc.id, data: doc.data() }));
    res.json(properties);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Backend Server running on port ${PORT}`);
});
