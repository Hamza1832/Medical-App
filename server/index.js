const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(bodyParser.json());

// Mock DB
const users = [
  {
    id: 1,
    username: 'admin',
    passwordHash: bcrypt.hashSync('admin123', 8),
    role: 'ADMIN',
    mfaEnabled: true,
    mfaSecret: '123456', // mock TOTP
  },
  {
    id: 2,
    username: 'doctor1',
    passwordHash: bcrypt.hashSync('doctor123', 8),
    role: 'DOCTOR',
    mfaEnabled: true,
    mfaSecret: '654321',
  },
];

// Helper : generate JWT
const generateToken = (user) => {
  return jwt.sign(
    { id: user.id, username: user.username, role: user.role },
    process.env.JWT_SECRET || 'supersecret',
    { expiresIn: '1h' }
  );
};

// --- Routes ---

// Login initial (username + password)
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  const user = users.find((u) => u.username === username);

  if (!user) return res.status(401).json({ message: 'Utilisateur non trouvé' });

  const passwordIsValid = bcrypt.compareSync(password, user.passwordHash);
  if (!passwordIsValid)
    return res.status(401).json({ message: 'Mot de passe incorrect' });

  if (user.mfaEnabled) {
    // Si MFA activé, retourne token temporaire
    return res.json({ mfa_required: true, temp_user_id: user.id });
  } else {
    const token = generateToken(user);
    return res.json({ access_token: token });
  }
});

// MFA verification (mock)
app.post('/api/auth/mfa', (req, res) => {
  const { temp_user_id, otp } = req.body;
  const user = users.find((u) => u.id === temp_user_id);

  if (!user) return res.status(401).json({ message: 'Utilisateur non trouvé' });

  // Vérification MFA simple (mock)
  if (otp === user.mfaSecret) {
    const token = generateToken(user);
    return res.json({ access_token: token });
  } else {
    return res.status(401).json({ message: 'OTP incorrect' });
  }
});

// Middleware pour vérifier JWT
const verifyToken = (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token) return res.status(403).json({ message: 'Token manquant' });

  jwt.verify(token.replace('Bearer ', ''), process.env.JWT_SECRET || 'supersecret', (err, decoded) => {
    if (err) return res.status(401).json({ message: 'Token invalide' });
    req.user = decoded;
    next();
  });
};

// Exemple route sécurisée
app.get('/api/patients', verifyToken, (req, res) => {
  // Stub de données patients
  const patients = [
    { id: 1, name: 'Patient A' },
    { id: 2, name: 'Patient B' },
  ];
  res.json({ user: req.user, patients });
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
