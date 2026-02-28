require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const compression = require("compression");
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const mongoSanitize = require("express-mongo-sanitize");
const xss = require("xss-clean");
const hpp = require("hpp");
const validator = require("validator");

const app = express();

// 🛡️ SECURITY MIDDLEWARE

// 1. Security Headers (Helmet)
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
    },
  },
  crossOriginEmbedderPolicy: false,
}));

// 2. CORS - Railway Optimized
const corsOptions = {
  origin: function (origin, callback) {
    const allowedOrigins = process.env.ALLOWED_ORIGINS?.split(",") || [];

    if (process.env.NODE_ENV === "production") {
      // Allow Railway domains and configured origins
      if (!origin || allowedOrigins.includes(origin) || origin.includes("railway.app")) {
        callback(null, true);
      } else {
        callback(new Error("Not allowed by CORS"));
      }
    } else {
      callback(null, true);
    }
  },
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE", "PATCH"],
  allowedHeaders: ["Content-Type", "Authorization"],
};
app.use(cors(corsOptions));

// 3. RATE LIMITING FOR LOGIN - STRICT
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts per window
  skipSuccessfulRequests: true, // Don't count successful logins
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    res.status(429).json({ 
      error: "Too many login attempts. Please try again after 15 minutes.",
      retryAfter: Math.ceil(req.rateLimit.resetTime / 1000)
    });
  },
  keyGenerator: (req) => {
    // Use IP address + username combination to prevent username enumeration
    return req.ip + (req.body.username || '');
  }
});

// Apply strict rate limiting to login endpoint
app.use("/api/auth/login", loginLimiter);

// General API rate limiting
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // 100 requests per 15 minutes
  message: { error: "Too many requests. Please try again later." }
});
app.use("/api/", apiLimiter);

// 4. Data Sanitization
app.use(mongoSanitize());
app.use(xss());
app.use(hpp());

// 5. Body Parser
app.use(express.json({ limit: "10kb" }));
app.use(compression());
app.use(express.static(path.join(__dirname, "public")));

// JWT Authentication Middleware
const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token)
    return res.status(401).json({ error: "Access denied. No token provided." });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ error: "Invalid token" });
  }
};

// Role-based access control
const requireRole = (roles) => (req, res, next) => {
  if (!roles.includes(req.user.role)) {
    return res.status(403).json({ error: "Access denied. Insufficient permissions." });
  }
  next();
};

// Connect to MongoDB
mongoose
  .connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("MongoDB Connected"))
  .catch((err) => console.error("MongoDB Error:", err));

// USER SCHEMA
const UserSchema = new mongoose.Schema({
  username: { 
    type: String, 
    required: true, 
    unique: true,
    trim: true,
    minlength: [3, "Username must be at least 3 characters"],
    maxlength: [30, "Username cannot exceed 30 characters"],
    match: [/^[a-zA-Z0-9_]+$/, "Username can only contain letters, numbers and underscores"]
  },
  password: { 
    type: String, 
    required: true,
    minlength: [8, "Password must be at least 8 characters"],
    select: false
  },
  role: {
    type: String,
    enum: ["admin", "mechanic", "driver", "viewer"],
    default: "mechanic",
  },
  name: {
    type: String,
    trim: true,
    maxlength: [100, "Name cannot exceed 100 characters"]
  },
  email: {
    type: String,
    trim: true,
    lowercase: true,
    validate: {
      validator: function(v) {
        return !v || validator.isEmail(v);
      },
      message: "Invalid email format"
    }
  },
  phone: {
    type: String,
    trim: true,
    maxlength: [20, "Phone number too long"]
  },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  createdAt: { type: Date, default: Date.now },
  lastLogin: Date,
  isActive: { type: Boolean, default: true },
  loginAttempts: { type: Number, default: 0 },
  lockUntil: Date,
});

// PART SCHEMA
const PartSchema = new mongoose.Schema({
  partNumber: { 
    type: String, 
    required: true, 
    unique: true,
    trim: true,
    maxlength: [50, "Part number too long"]
  },
  description: { 
    type: String, 
    required: true,
    trim: true,
    maxlength: [500, "Description too long"]
  },
  category: { 
    type: String, 
    required: true,
    enum: ["Engine", "Transmission", "Brakes", "Electrical", "Body", "Tires", "Other"]
  },
  quantity: { 
    type: Number, 
    default: 0,
    min: [0, "Quantity cannot be negative"],
    max: [999999, "Quantity too high"]
  },
  minStock: { 
    type: Number, 
    default: 1,
    min: [0, "Min stock cannot be negative"]
  },
  location: {
    type: String,
    trim: true,
    maxlength: [100, "Location too long"]
  },
  cost: { 
    type: Number, 
    default: 0,
    min: [0, "Cost cannot be negative"]
  },
  supplier: {
    type: String,
    trim: true,
    maxlength: [100, "Supplier name too long"]
  },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  updatedAt: { type: Date, default: Date.now },
});

// TRUCK SCHEMA
const TruckSchema = new mongoose.Schema({
  truckId: { 
    type: String, 
    required: true, 
    unique: true,
    trim: true,
    uppercase: true,
    maxlength: [20, "Truck ID too long"]
  },
  name: { 
    type: String, 
    required: true,
    trim: true,
    maxlength: [100, "Name too long"]
  },
  type: { 
    type: String, 
    enum: ["truck", "trailer"], 
    required: true 
  },
  vin: {
    type: String,
    trim: true,
    uppercase: true,
    maxlength: [17, "VIN must be 17 characters"]
  },
  year: {
    type: Number,
    min: [1980, "Year too old"],
    max: [2030, "Year too far in future"]
  },
  make: {
    type: String,
    trim: true,
    maxlength: [50, "Make name too long"]
  },
  model: {
    type: String,
    trim: true,
    maxlength: [50, "Model name too long"]
  },
  notes: {
    type: String,
    trim: true,
    maxlength: [2000, "Notes too long"]
  },
  status: {
    type: String,
    enum: ["active", "maintenance", "retired"],
    default: "active",
  },
  totalRepairCost: { type: Number, default: 0 },
  totalPartsCost: { type: Number, default: 0 },
  totalLaborCost: { type: Number, default: 0 },
  repairCount: { type: Number, default: 0 },
  lastServiceDate: Date,
  nextServiceDue: Date,
  createdAt: { type: Date, default: Date.now },
});

// REPAIR SCHEMA
const RepairSchema = new mongoose.Schema({
  date: { 
    type: Date, 
    required: true
  },
  truckId: { 
    type: String, 
    required: true,
    trim: true,
    maxlength: [20, "Truck ID too long"]
  },
  truckName: {
    type: String,
    trim: true,
    maxlength: [100, "Truck name too long"]
  },
  issue: { 
    type: String, 
    required: true,
    trim: true,
    maxlength: [2000, "Issue description too long"]
  },
  partsUsed: [
    {
      partId: { type: String, required: true },
      partNumber: { type: String, required: true, trim: true },
      description: { type: String, trim: true },
      quantity: { type: Number, required: true, min: 1 },
      unitCost: { type: Number, required: true, min: 0 },
      totalCost: { type: Number, required: true, min: 0 },
    },
  ],
  partsTotalCost: { type: Number, default: 0, min: 0 },
  laborHours: { type: Number, default: 0, min: 0, max: 999 },
  laborRate: { type: Number, default: 75, min: 0 },
  laborCost: { type: Number, default: 0, min: 0 },
  totalCost: { type: Number, default: 0, min: 0 },
  mechanic: {
    type: String,
    trim: true,
    maxlength: [100, "Mechanic name too long"]
  },
  mechanicId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  notes: {
    type: String,
    trim: true,
    maxlength: [2000, "Notes too long"]
  },
  status: {
    type: String,
    enum: ["completed", "in-progress", "scheduled"],
    default: "completed",
  },
  createdAt: { type: Date, default: Date.now },
});

// ACTIVITY LOG SCHEMA
const ActivityLogSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  username: String,
  action: String,
  entityType: String,
  entityId: String,
  details: Object,
  ipAddress: String,
  userAgent: String,
  timestamp: { type: Date, default: Date.now },
});

const User = mongoose.model("User", UserSchema);
const Part = mongoose.model("Part", PartSchema);
const Truck = mongoose.model("Truck", TruckSchema);
const Repair = mongoose.model("Repair", RepairSchema);
const ActivityLog = mongoose.model("ActivityLog", ActivityLogSchema);

// Helper: Log activity with IP
const logActivity = async (userId, username, action, entityType, entityId, details, req) => {
  await ActivityLog.create({
    userId,
    username,
    action,
    entityType,
    entityId,
    details,
    ipAddress: req.ip,
    userAgent: req.headers["user-agent"],
  });
};

// Helper: Update truck costs
const updateTruckCosts = async (truckId) => {
  const repairs = await Repair.find({ truckId });
  const totalPartsCost = repairs.reduce((sum, r) => sum + (r.partsTotalCost || 0), 0);
  const totalLaborCost = repairs.reduce((sum, r) => sum + (r.laborCost || 0), 0);
  const totalRepairCost = repairs.reduce((sum, r) => sum + (r.totalCost || 0), 0);

  await Truck.findOneAndUpdate(
    { truckId },
    { totalPartsCost, totalLaborCost, totalRepairCost, repairCount: repairs.length }
  );
};

// Password validation helper
const validatePassword = (password) => {
  const minLength = 8;
  const hasUpperCase = /[A-Z]/.test(password);
  const hasLowerCase = /[a-z]/.test(password);
  const hasNumbers = /\d/.test(password);
  const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);

  if (password.length < minLength) return "Password must be at least 8 characters";
  if (!hasUpperCase) return "Password must contain at least one uppercase letter";
  if (!hasLowerCase) return "Password must contain at least one lowercase letter";
  if (!hasNumbers) return "Password must contain at least one number";
  if (!hasSpecialChar) return "Password must contain at least one special character";

  return null;
};

// AUTH ROUTES

// Login with account lockout
app.post("/api/auth/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    // Input validation
    if (!username || !password) {
      return res.status(400).json({ error: "Username and password required" });
    }

    if (typeof username !== "string" || typeof password !== "string") {
      return res.status(400).json({ error: "Invalid input format" });
    }

    // Sanitize username
    const sanitizedUsername = validator.escape(username.trim());

    const user = await User.findOne({ username: sanitizedUsername, isActive: true }).select("+password");

    if (!user) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Check if account is locked
    if (user.lockUntil && user.lockUntil > Date.now()) {
      const remainingTime = Math.ceil((user.lockUntil - Date.now()) / 60000);
      return res.status(423).json({ 
        error: `Account temporarily locked due to too many failed attempts. Try again in ${remainingTime} minutes.`,
        locked: true,
        retryAfter: remainingTime * 60
      });
    }

    if (!(await bcrypt.compare(password, user.password))) {
      // Increment login attempts
      user.loginAttempts += 1;

      // Lock account after 5 failed attempts for 15 minutes
      if (user.loginAttempts >= 5) {
        user.lockUntil = new Date(Date.now() + 15 * 60 * 1000);
        await logActivity(user._id, user.username, "ACCOUNT_LOCKED", "User", user.username, { attempts: user.loginAttempts }, req);
      }

      await user.save();

      // Return remaining attempts
      const remainingAttempts = 5 - user.loginAttempts;
      return res.status(401).json({ 
        error: "Invalid credentials",
        remainingAttempts: remainingAttempts > 0 ? remainingAttempts : 0,
        locked: user.loginAttempts >= 5
      });
    }

    // Reset login attempts on success
    if (user.loginAttempts > 0) {
      user.loginAttempts = 0;
      user.lockUntil = undefined;
      await user.save();
    }

    user.lastLogin = new Date();
    await user.save();

    const token = jwt.sign(
      { userId: user._id, username: user.username, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "24h" }
    );

    await logActivity(user._id, user.username, "LOGIN_SUCCESS", "User", user.username, {}, req);

    res.json({
      token,
      user: {
        _id: user._id,
        username: user.username,
        role: user.role,
        name: user.name,
        isActive: user.isActive,
      },
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Get current user
app.get("/api/auth/me", authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select("-password -loginAttempts -lockUntil");
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// USER MANAGEMENT (Admin Only)

// Create user with password validation
app.post("/api/users", authenticate, requireRole(["admin"]), async (req, res) => {
  try {
    let { username, password, role, name, email, phone } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: "Username and password required" });
    }

    username = username.trim();
    if (!/^[a-zA-Z0-9_]+$/.test(username)) {
      return res.status(400).json({ error: "Username can only contain letters, numbers and underscores" });
    }

    const passwordError = validatePassword(password);
    if (passwordError) {
      return res.status(400).json({ error: passwordError });
    }

    if (email && !validator.isEmail(email)) {
      return res.status(400).json({ error: "Invalid email format" });
    }

    const existingUser = await User.findOne({ username: username.toLowerCase() });
    if (existingUser)
      return res.status(400).json({ error: "Username already exists" });

    const hashedPassword = await bcrypt.hash(password, 12);
    const user = new User({
      username: username.toLowerCase(),
      password: hashedPassword,
      role,
      name: name ? validator.escape(name.trim()) : undefined,
      email: email ? email.toLowerCase().trim() : undefined,
      phone: phone ? validator.escape(phone.trim()) : undefined,
      createdBy: req.user.userId,
      isActive: true,
    });

    await user.save();
    await logActivity(req.user.userId, req.user.username, "CREATE_USER", "User", user.username, { username, role }, req);

    res.status(201).json({
      message: "User created",
      userId: user._id,
      user: {
        _id: user._id,
        username: user.username,
        role: user.role,
        name: user.name,
        isActive: user.isActive,
        createdAt: user.createdAt,
      },
    });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Get all users
app.get("/api/users", authenticate, requireRole(["admin"]), async (req, res) => {
  try {
    const users = await User.find().select("-password").sort({ createdAt: -1 });
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Update user status
app.patch("/api/users/:id", authenticate, requireRole(["admin"]), async (req, res) => {
  try {
    const { isActive } = req.body;
    if (req.params.id === req.user.userId && isActive === false) {
      return res.status(400).json({ error: "Cannot disable your own account" });
    }

    const user = await User.findByIdAndUpdate(req.params.id, { isActive }, { new: true }).select("-password");
    if (!user) return res.status(404).json({ error: "User not found" });

    await logActivity(req.user.userId, req.user.username, isActive ? "USER_ENABLED" : "USER_DISABLED", "User", user.username, { isActive }, req);

    res.json({ message: `User ${isActive ? "enabled" : "disabled"} successfully`, user });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Delete user
app.delete("/api/users/:id", authenticate, requireRole(["admin"]), async (req, res) => {
  try {
    if (req.params.id === req.user.userId) {
      return res.status(400).json({ error: "Cannot delete your own account" });
    }

    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ error: "User not found" });

    await User.findByIdAndDelete(req.params.id);
    await logActivity(req.user.userId, req.user.username, "USER_DELETED", "User", user.username, { deletedUser: user.username, role: user.role }, req);

    res.json({ message: "User deleted permanently" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// STATS & DASHBOARD
app.get("/api/stats", authenticate, async (req, res) => {
  try {
    const [totalParts, lowStock, fleetSize] = await Promise.all([
      Part.countDocuments(),
      Part.countDocuments({ $expr: { $lte: ["$quantity", "$minStock"] } }),
      Truck.countDocuments({ status: "active" }),
    ]);

    const startOfMonth = new Date();
    startOfMonth.setDate(1);
    const thisMonthRepairs = await Repair.find({ date: { $gte: startOfMonth } });
    const monthCost = thisMonthRepairs.reduce((sum, r) => sum + (r.totalCost || 0), 0);

    const topVehicles = await Truck.find().sort({ totalRepairCost: -1 }).limit(5).select("truckId name totalRepairCost repairCount");

    res.json({ totalParts, lowStock, fleetSize, monthCost, topVehicles, userRole: req.user.role });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Vehicle-specific stats
app.get("/api/vehicles/:truckId/stats", authenticate, async (req, res) => {
  try {
    const { truckId } = req.params;
    if (!truckId || !/^[A-Z0-9-]+$/.test(truckId)) {
      return res.status(400).json({ error: "Invalid truck ID format" });
    }

    const truck = await Truck.findOne({ truckId });
    if (!truck) return res.status(404).json({ error: "Vehicle not found" });

    const repairs = await Repair.find({ truckId }).sort({ date: -1 });
    res.json({ truck, repairs });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// PARTS API
app.get("/api/parts", authenticate, async (req, res) => {
  try {
    const parts = await Part.find().sort({ updatedAt: -1 });
    res.json(parts);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post("/api/parts", authenticate, requireRole(["admin", "mechanic"]), async (req, res) => {
  try {
    req.body.partNumber = req.body.partNumber?.toUpperCase().trim();
    req.body.description = validator.escape(req.body.description?.trim() || "");
    req.body.location = req.body.location ? validator.escape(req.body.location.trim()) : undefined;
    req.body.supplier = req.body.supplier ? validator.escape(req.body.supplier.trim()) : undefined;

    const part = new Part({ ...req.body, createdBy: req.user.userId });
    await part.save();
    await logActivity(req.user.userId, req.user.username, "CREATE_PART", "part", part._id, req.body, req);
    res.status(201).json(part);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.put("/api/parts/:id", authenticate, requireRole(["admin", "mechanic"]), async (req, res) => {
  try {
    req.body.updatedAt = Date.now();
    if (req.body.description) req.body.description = validator.escape(req.body.description.trim());
    if (req.body.location) req.body.location = validator.escape(req.body.location.trim());
    if (req.body.supplier) req.body.supplier = validator.escape(req.body.supplier.trim());

    const part = await Part.findByIdAndUpdate(req.params.id, req.body, { new: true });
    await logActivity(req.user.userId, req.user.username, "UPDATE_PART", "part", part._id, req.body, req);
    res.json(part);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.delete("/api/parts/:id", authenticate, requireRole(["admin"]), async (req, res) => {
  try {
    const part = await Part.findById(req.params.id);
    if (!part) return res.status(404).json({ error: "Part not found" });

    await Part.findByIdAndDelete(req.params.id);
    await logActivity(req.user.userId, req.user.username, "DELETE_PART", "Part", part.partNumber, {}, req);
    res.json({ message: "Part deleted" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// TRUCKS API
app.get("/api/trucks", authenticate, async (req, res) => {
  try {
    const trucks = await Truck.find().sort({ createdAt: -1 });
    res.json(trucks);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post("/api/trucks", authenticate, requireRole(["admin"]), async (req, res) => {
  try {
    req.body.truckId = req.body.truckId?.toUpperCase().trim();
    req.body.name = validator.escape(req.body.name?.trim() || "");
    if (req.body.make) req.body.make = validator.escape(req.body.make.trim());
    if (req.body.model) req.body.model = validator.escape(req.body.model.trim());
    if (req.body.vin) req.body.vin = req.body.vin.toUpperCase().trim();
    if (req.body.notes) req.body.notes = validator.escape(req.body.notes.trim());

    const truck = new Truck(req.body);
    await truck.save();
    await logActivity(req.user.userId, req.user.username, "CREATE_TRUCK", "truck", truck._id, req.body, req);
    res.status(201).json(truck);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.delete("/api/trucks/:id", authenticate, requireRole(["admin"]), async (req, res) => {
  try {
    const truck = await Truck.findById(req.params.id);
    if (!truck) return res.status(404).json({ error: "Vehicle not found" });

    const hasRepairs = await Repair.findOne({ truckId: truck.truckId });
    if (hasRepairs && !req.query.force) {
      return res.status(400).json({ error: "Vehicle has repair history. Use ?force=true to delete anyway." });
    }

    if (hasRepairs && req.query.force) {
      await Repair.deleteMany({ truckId: truck.truckId });
    }

    await Truck.findByIdAndDelete(req.params.id);
    await logActivity(req.user.userId, req.user.username, "DELETE_TRUCK", "Truck", truck.truckId, { force: !!req.query.force }, req);
    res.json({ message: "Vehicle deleted" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// REPAIRS API
app.get("/api/repairs", authenticate, async (req, res) => {
  try {
    let query = {};
    if (req.user.role === "mechanic") {
      query.mechanicId = req.user.userId;
    }
    const repairs = await Repair.find(query).sort({ date: -1 }).limit(100);

    const repairsWithTruckInfo = await Promise.all(
      repairs.map(async (r) => {
        const truck = await Truck.findOne({ truckId: r.truckId });
        return { ...r.toObject(), truckName: truck ? truck.name : r.truckId };
      })
    );

    res.json(repairsWithTruckInfo);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get("/api/repairs/:id", authenticate, async (req, res) => {
  try {
    const repair = await Repair.findById(req.params.id);
    if (!repair) return res.status(404).json({ error: "Repair not found" });

    if (req.user.role === "mechanic" && repair.mechanicId?.toString() !== req.user.userId) {
      return res.status(403).json({ error: "Access denied" });
    }

    const truck = await Truck.findOne({ truckId: repair.truckId });
    res.json({ ...repair.toObject(), truckName: truck ? truck.name : repair.truckId });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post("/api/repairs", authenticate, requireRole(["admin", "mechanic"]), async (req, res) => {
  try {
    let { truckId, date, issue, laborHours, laborRate, mechanic, notes, partsUsed } = req.body;

    issue = validator.escape(issue.trim());
    if (mechanic) mechanic = validator.escape(mechanic.trim());
    if (notes) notes = validator.escape(notes.trim());
    truckId = truckId.toUpperCase().trim();

    const truck = await Truck.findOne({ truckId });
    if (!truck) return res.status(404).json({ error: "Vehicle not found" });

    let partsTotalCost = 0;
    const processedParts = [];

    if (partsUsed && Array.isArray(partsUsed) && partsUsed.length > 0) {
      for (const item of partsUsed) {
        const part = await Part.findById(item.partId);
        if (part) {
          if (part.quantity < item.quantity) {
            return res.status(400).json({ error: `Insufficient stock for ${part.partNumber}. Only ${part.quantity} available` });
          }

          part.quantity -= item.quantity;
          await part.save();

          processedParts.push({
            partId: part._id,
            partNumber: validator.escape(part.partNumber),
            description: validator.escape(part.description),
            quantity: item.quantity,
            unitCost: item.unitCost || part.cost || 0,
            totalCost: (item.unitCost || part.cost || 0) * item.quantity,
          });

          partsTotalCost += (item.unitCost || part.cost || 0) * item.quantity;
        }
      }
    }

    const laborHrs = parseFloat(laborHours) || 0;
    const rate = parseFloat(laborRate) || 75;
    const laborCost = laborHrs * rate;
    const totalCost = partsTotalCost + laborCost;

    const repair = new Repair({
      truckId,
      date: date || new Date(),
      issue,
      partsUsed: processedParts,
      partsTotalCost,
      laborHours: laborHrs,
      laborRate: rate,
      laborCost,
      totalCost,
      mechanic: mechanic || req.user.username,
      mechanicId: req.user.userId,
      notes,
      truckName: validator.escape(truck.name),
      status: "completed",
    });

    await repair.save();
    await updateTruckCosts(truckId);
    await logActivity(req.user.userId, req.user.username, "CREATE_REPAIR", "Repair", repair._id, { truckId, truckName: truck.name, totalCost, partsCount: processedParts.length }, req);

    res.status(201).json(repair);
  } catch (error) {
    console.error("Repair creation error:", error);
    res.status(400).json({ error: error.message });
  }
});

app.put("/api/repairs/:id", authenticate, requireRole(["admin", "mechanic"]), async (req, res) => {
  try {
    const repair = await Repair.findById(req.params.id);
    if (!repair) return res.status(404).json({ error: "Repair not found" });

    if (req.user.role === "mechanic" && repair.mechanicId?.toString() !== req.user.userId) {
      return res.status(403).json({ error: "You can only edit your own repairs" });
    }

    let { truckId, date, issue, laborHours, laborRate, mechanic, notes, partsUsed } = req.body;

    issue = validator.escape(issue.trim());
    if (mechanic) mechanic = validator.escape(mechanic.trim());
    if (notes) notes = validator.escape(notes.trim());
    truckId = truckId.toUpperCase().trim();

    for (const used of repair.partsUsed || []) {
      if (used.partId) {
        await Part.findByIdAndUpdate(used.partId, { $inc: { quantity: used.quantity } });
      }
    }

    let partsTotalCost = 0;
    const processedParts = [];

    if (partsUsed && Array.isArray(partsUsed) && partsUsed.length > 0) {
      for (const item of partsUsed) {
        const part = await Part.findById(item.partId);
        if (part) {
          if (part.quantity < item.quantity) {
            return res.status(400).json({ error: `Insufficient stock for ${part.partNumber}. Only ${part.quantity} available` });
          }

          part.quantity -= item.quantity;
          await part.save();

          processedParts.push({
            partId: part._id,
            partNumber: validator.escape(part.partNumber),
            description: validator.escape(part.description),
            quantity: item.quantity,
            unitCost: item.unitCost || part.cost || 0,
            totalCost: (item.unitCost || part.cost || 0) * item.quantity,
          });

          partsTotalCost += (item.unitCost || part.cost || 0) * item.quantity;
        }
      }
    }

    const laborHrs = parseFloat(laborHours) || 0;
    const rate = parseFloat(laborRate) || 75;
    const laborCost = laborHrs * rate;
    const totalCost = partsTotalCost + laborCost;

    repair.truckId = truckId;
    repair.date = date || repair.date;
    repair.issue = issue;
    repair.partsUsed = processedParts;
    repair.partsTotalCost = partsTotalCost;
    repair.laborHours = laborHrs;
    repair.laborRate = rate;
    repair.laborCost = laborCost;
    repair.totalCost = totalCost;
    repair.mechanic = mechanic || repair.mechanic;
    repair.notes = notes;

    await repair.save();
    await updateTruckCosts(repair.truckId);
    await logActivity(req.user.userId, req.user.username, "UPDATE_REPAIR", "Repair", repair._id, { truckId: repair.truckId, totalCost }, req);

    res.json(repair);
  } catch (error) {
    console.error("Repair update error:", error);
    res.status(400).json({ error: error.message });
  }
});

app.delete("/api/repairs/:id", authenticate, requireRole(["admin"]), async (req, res) => {
  try {
    const repair = await Repair.findById(req.params.id);
    if (repair) {
      for (const used of repair.partsUsed || []) {
        if (used.partId) {
          await Part.findByIdAndUpdate(used.partId, { $inc: { quantity: used.quantity } });
        }
      }

      const truckId = repair.truckId;
      await Repair.findByIdAndDelete(req.params.id);
      await updateTruckCosts(truckId);
      await logActivity(req.user.userId, req.user.username, "DELETE_REPAIR", "Repair", req.params.id, { truckId }, req);
    }
    res.json({ message: "Repair deleted" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ACTIVITY LOGS
app.get("/api/activity-logs", authenticate, requireRole(["admin"]), async (req, res) => {
  try {
    const logs = await ActivityLog.find().sort({ timestamp: -1 }).limit(100).populate("userId", "username name");
    res.json(logs);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// EXPORT
app.get("/api/export", authenticate, requireRole(["admin"]), async (req, res) => {
  try {
    const [parts, trucks, repairs, users] = await Promise.all([
      Part.find(),
      Truck.find(),
      Repair.find(),
      User.find().select("-password"),
    ]);
    res.json({ parts, trucks, repairs, users, exportDate: new Date() });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Health check
app.get("/health", (req, res) => {
  res.status(200).json({ status: "healthy", timestamp: new Date() });
});

// Serve frontend
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Secure Fleet Tracker running on port ${PORT}`);
});

// Create default admin
const createDefaultAdmin = async () => {
  try {
    const count = await User.countDocuments();
    if (count === 0) {
      const tempPassword = "Admin@123!";
      const hashedPassword = await bcrypt.hash(tempPassword, 12);
      await User.create({
        username: "admin",
        password: hashedPassword,
        role: "admin",
        name: "System Administrator",
        isActive: true,
      });
      console.log("Default admin created: username=admin");
      console.log("⚠️  IMPORTANT: Change default password immediately after first login!");
      console.log(`Temporary password: ${tempPassword}`);
    }
  } catch (err) {
    console.error("Error creating default admin:", err);
  }
};

createDefaultAdmin();