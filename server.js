require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cors = require('cors');

const app = express();

// Allow CORS for all domains
app.use(cors({
  origin: '*', // Allow all domains
  methods: ['GET', 'POST', 'PATCH', 'DELETE'], // Allowed HTTP methods
  allowedHeaders: ['Content-Type', 'Authorization'], // Allowed headers
}));

app.use(express.json());
app.use(helmet());

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});
app.use(limiter);

mongoose.connect("mongodb+srv://maanda744:PhROOm1f3QzK2w42@cluster0.koox3.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0")
  .then(() => console.log('Connected to MongoDB'))
  .catch((err) => {
    console.error('Failed to connect to MongoDB:', err.message);
    console.error('Connection URI:', process.env.MONGODB_URI); // Log the URI for debugging
  });

// Database Models
const User = mongoose.model('User', new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  type: String,
  cars: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Car' }]
}));

const Car = mongoose.model('Car', new mongoose.Schema({
  owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  carWash: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, // Reference to the car wash
  licensePlate: String,
  status: { type: String, enum: ['received', 'in-progress', 'washing', 'completed'], default: 'received' },
  createdAt: { type: Date, default: Date.now }
}));

// Auth Middleware
const authenticate = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).send('Access denied');

  try {
    const verified = jwt.verify(token, process.env.JWT_SECRET);
    req.user = await User.findById(verified.id);
    next();
  } catch (err) {
    res.status(400).send('Invalid token');
  }
};

// Routes
app.post('/api/register', async (req, res) => {
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    const user = new User({
      ...req.body,
      password: hashedPassword
    });
    await user.save();
    res.status(201).json(user);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.post('/api/login', async (req, res) => {
  const user = await User.findOne({ email: req.body.email });
  if (!user || !await bcrypt.compare(req.body.password, user.password)) {
    return res.status(400).json({ error: 'Invalid credentials' });
  }

  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);
  res.json({ token, user });
});

app.post('/api/cars', async (req, res) => {
  try {
    const { licensePlate, carWashId } = req.body;

    // Ensure the selected car wash exists and is of type 'carwash'
    const carWash = await User.findById(carWashId);
    if (!carWash || carWash.type !== 'carwash') {
      return res.status(400).json({ error: 'Invalid car wash selected' });
    }

    const car = new Car({
      owner: req.user._id, // The user adding the car
      carWash: carWashId, // The selected car wash
      licensePlate,
    });

    await car.save();
    res.status(201).json(car);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.get('/api/my-cars', async (req, res) => {
  try {
    // Ensure the user is an individual
    if (req.user.type !== 'individual') {
      return res.status(403).json({ error: 'Only individual users can access this route' });
    }

    const cars = await Car.find({ owner: req.user._id }).populate('carWash');
    res.json(cars);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.get('/api/carwashes', async (req, res) => {
  try {
    const carWashes = await User.find({ type: 'carwash' });
    res.json(carWashes);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.get('/api/carwash/cars', authenticate, async (req, res) => {
  try {
    // Ensure the user is a car wash
    if (req.user.type !== 'carwash') {
      return res.status(403).json({ error: 'Only car wash users can access this route' });
    }

    const cars = await Car.find({ carWash: req.user._id }).populate('owner');
    res.json(cars);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.patch('/api/carwash/cars/:id',  async (req, res) => {
  try {
    // Ensure the user is a car wash
    if (req.user.type !== 'carwash') {
      return res.status(403).json({ error: 'Only car wash users can access this route' });
    }

    const car = await Car.findOneAndUpdate(
      { _id: req.params.id, carWash: req.user._id }, // Ensure the car belongs to this car wash
      { status: req.body.status },
      { new: true }
    );

    if (!car) {
      return res.status(404).json({ error: 'Car not found or does not belong to this car wash' });
    }

    res.json(car);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.get('/api/carwash/all-cars',  async (req, res) => {
  try {
    // Ensure the user is a car wash
    if (req.user.type !== 'carwash') {
      return res.status(403).json({ error: 'Only car wash users can access this route' });
    }

    const cars = await Car.find({ carWash: req.user._id }).populate('owner');
    res.json(cars);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));