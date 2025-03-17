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
  origin: '*',
  methods: ['GET', 'POST', 'PATCH', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
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
  });

// Database Models
const User = mongoose.model('User', new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  type: String,
  location: String,
  cars: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Car' }]
}));

const Car = mongoose.model('Car', new mongoose.Schema({
  owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  carWash: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
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
    const { name, email, password, type, location } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const user = new User({
      name,
      email,
      password: hashedPassword,
      type,
      location: type === 'carwash' ? location : undefined,
    });

    await user.save();
    res.status(201).json(user);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const user = await User.findOne({ email: req.body.email });
    if (!user || !await bcrypt.compare(req.body.password, user.password)) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);
    res.json({ token, user });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});


// Car wash adding car for existing/new individual
app.post('/api/carwash/cars', async (req, res) => {
  try {
    if (req.user.type !== 'carwash') {
      return res.status(403).json({ error: 'Only car washes can add cars' });
    }

    const { licensePlate, ownerId, newUser } = req.body;
    let owner;

    if (ownerId) {
      owner = await User.findById(ownerId);
      if (!owner || owner.type !== 'individual') {
        return res.status(400).json({ error: 'Invalid individual user' });
      }
    } else if (newUser) {
      const hashedPassword = await bcrypt.hash(newUser.password, 10);
      owner = new User({
        name: newUser.name,
        email: newUser.email,
        password: hashedPassword,
        type: 'individual'
      });
      await owner.save();
    } else {
      return res.status(400).json({ error: 'Must provide either existing user or new user details' });
    }

    const car = new Car({
      owner: owner._id,
      carWash: req.user._id,
      licensePlate,
    });

    await car.save();
    res.status(201).json(car);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

//get
app.get('/api/my-cars', async (req, res) => {
  try {
    // Ensure the user is an individual
    // if (req.user.type !== 'individual') {
    //   return res.status(403).json({ error: 'Only individual users can access this route' });
    // }

    const cars = await Car.find({ owner: req.user._id }).populate('carWash');
    res.json(cars);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Get individuals for car wash to select
app.get('/api/individuals', async (req, res) => {
  try {
    const individuals = await User.find({ type: 'individual' }).select('name email');
    res.json(individuals);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.post('/api/cars',  async (req, res) => {
  try {
    const { licensePlate, carWashId , user_id} = req.body;

    // Ensure the selected car wash exists and is of type 'carwash'
    const carWash = await User.findById(carWashId);
    if (!carWash || carWash.type !== 'carwash') {
      return res.status(400).json({ error: 'Invalid car wash selected' });
    }

    // Create the car
    const car = new Car({
      owner: user_id, // The logged-in individual
      carWash: carWashId, // The selected car wash
      licensePlate,
    });

    await car.save();
    res.status(201).json(car);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});



// Get cars for the logged-in user (optional car ID)
app.get('/api/my-cars/:userId?', async (req, res) => {
  try {

    const { userId  } = req.params

    // Find all cars where the logged-in user is the owner
    const cars = await Car.find({ owner: userId }).populate('carWash', 'name'); // Populate car wash name if needed

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

// Get cars for car wash
app.get('/api/carwash/cars',  async (req, res) => {
  try {
    if (req.user.type !== 'carwash') {
      return res.status(403).json({ error: 'Only car wash users can access this route' });
    }

    const cars = await Car.find({ carWash: req.user._id }).populate('owner');
    res.json(cars);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});



// Other existing routes remain the same...

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));