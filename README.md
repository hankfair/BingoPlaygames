import shutil
import os

# Define project structure
project_root = "/mnt/data/bingoplay-backend"
os.makedirs(project_root + "/routes", exist_ok=True)
os.makedirs(project_root + "/models", exist_ok=True)
os.makedirs(project_root + "/middleware", exist_ok=True)

# Create server.js
server_js = """\
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
require('dotenv').config();

const authRoutes = require('./routes/auth');
const adminRoutes = require('./routes/admin');
const betRoutes = require('./routes/bets');

const app = express();
app.use(cors());
app.use(express.json());

mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.log(err));

app.use('/api/auth', authRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/bets', betRoutes);

app.get('/', (req, res) => res.send('🎰 BingoPlay Backend is Running'));

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
"""
with open(f"{project_root}/server.js", "w") as f:
    f.write(server_js)

# Create package.json
package_json = """\
{
  "name": "bingoplay-backend",
  "version": "1.0.0",
  "main": "server.js",
  "scripts": {
    "start": "node server.js"
  },
  "dependencies": {
    "bcrypt": "^5.1.0",
    "cors": "^2.8.5",
    "dotenv": "^16.3.1",
    "express": "^4.18.2",
    "jsonwebtoken": "^9.0.1",
    "mongoose": "^7.3.1"
  }
}
"""
with open(f"{project_root}/package.json", "w") as f:
    f.write(package_json)

# Create .env.example
env_example = """\
PORT=5000
JWT_SECRET=your_jwt_secret
MONGO_URI=your_mongodb_uri
"""
with open(f"{project_root}/.env.example", "w") as f:
    f.write(env_example)

# Create User model
user_model = """\
const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: String,
  isAdmin: { type: Boolean, default: false },
  balance: {
    USD: { type: Number, default: 0 },
    PEN: { type: Number, default: 0 }
  },
  bets: [{
    match: String,
    betType: String,
    amount: Number,
    odds: Number,
    result: String
  }]
});

module.exports = mongoose.model('User', UserSchema);
"""
with open(f"{project_root}/models/User.js", "w") as f:
    f.write(user_model)

# Create middleware auth
middleware_auth = """\
const jwt = require('jsonwebtoken');

exports.verifyToken = (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token) return res.status(403).send("Token missing");
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).send("Invalid token");
  }
};
"""
with open(f"{project_root}/middleware/auth.js", "w") as f:
    f.write(middleware_auth)

# Create routes
auth_route = """\
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const router = express.Router();

router.post('/register', async (req, res) => {
  try {
    const { email, password } = req.body;
    const exists = await User.findOne({ email });
    if (exists) return res.status(400).send("Email already in use.");
    const hashed = await bcrypt.hash(password, 10);
    const user = new User({ email, password: hashed });
    await user.save();
    res.status(201).send("Registered successfully");
  } catch (err) {
    res.status(500).send("Server error");
  }
});

router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password)))
      return res.status(401).send("Invalid credentials");
    const token = jwt.sign({ id: user._id, isAdmin: user.isAdmin }, process.env.JWT_SECRET);
    res.json({ token });
  } catch (err) {
    res.status(500).send("Server error");
  }
});

module.exports = router;
"""
with open(f"{project_root}/routes/auth.js", "w") as f:
    f.write(auth_route)

admin_route = """\
const express = require('express');
const router = express.Router();
const auth = require('../middleware/auth');

router.get('/dashboard', auth.verifyToken, (req, res) => {
  if (!req.user.isAdmin) return res.status(403).send("Access denied");
  res.send("Welcome Admin");
});

module.exports = router;
"""
with open(f"{project_root}/routes/admin.js", "w") as f:
    f.write(admin_route)

bets_route = """\
const express = require('express');
const router = express.Router();
const User = require('../models/User');
const auth = require('../middleware/auth');

router.post('/place', auth.verifyToken, async (req, res) => {
  const { match, betType, amount, odds, currency } = req.body;
  const user = await User.findById(req.user.id);
  if (user.balance[currency] < amount) return res.status(400).send("Insufficient funds");
  user.balance[currency] -= amount;
  user.bets.push({ match, betType, amount, odds, result: "pending" });
  await user.save();
  res.send("Bet placed successfully");
});

module.exports = router;
"""
with open(f"{project_root}/routes/bets.js", "w") as f:
    f.write(bets_route)

# Create zip file
zip_path = "/mnt/data/bingoplay-backend.zip"
shutil.make_archive(zip_path.replace(".zip", ""), 'zip', project_root)

zip_path
