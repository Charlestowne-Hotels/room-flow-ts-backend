import express from 'express';
import cors from 'cors';
import * as admin from 'firebase-admin';

// Initialize Firebase Admin using the Environment Variable from Render
const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_KEY as string);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore();
const app = express();

// Allow your frontend to talk to this backend
app.use(cors({ origin: '*' })); // You can lock this down later to just your frontend URL
app.use(express.json());

// Middleware to verify the user is logged in via Google
const verifyToken = async (req: express.Request, res: express.Response, next: express.NextFunction) => {
  const token = req.headers.authorization?.split('Bearer ')[1];
  if (!token) return res.status(401).send('Unauthorized');
  
  try {
    const decodedToken = await admin.auth().verifyIdToken(token);
    (req as any).user = decodedToken;
    next();
  } catch (error) {
    res.status(401).send('Invalid token');
  }
};

// Example Route: Get Custom Properties
app.get('/api/custom-properties', verifyToken, async (req, res) => {
  try {
    const snapshot = await db.collection('custom_properties').get();
    const properties: any[] = [];
    snapshot.forEach(doc => {
      properties.push({ id: doc.id, data: doc.data() });
    });
    res.json(properties);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
