require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const compression = require("compression");
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();

app.use(cors());
app.use(compression());
app.use(express.json({ limit: "50mb" }));
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
    res.status(400).json({ error: "Invalid token" });
  }
};

// Role-based access control
const requireRole = (roles) => (req, res, next) => {
  if (!roles.includes(req.user.role)) {
    return res
      .status(403)
      .json({ error: "Access denied. Insufficient permissions." });
  }
  next();
};

// Connect to MongoDB
mongoose
  .connect(process.env.MONGODB_URI)
  .then(() => console.log("MongoDB Connected"))
  .catch((err) => console.error("MongoDB Error:", err));

// USER SCHEMA (New)
const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: {
    type: String,
    enum: ["admin", "mechanic", "driver", "viewer"],
    default: "mechanic",
  },
  name: String,
  email: String,
  phone: String,
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  createdAt: { type: Date, default: Date.now },
  lastLogin: Date,
  isActive: { type: Boolean, default: true },
});

// PART SCHEMA
const PartSchema = new mongoose.Schema({
  partNumber: { type: String, required: true, unique: true },
  description: { type: String, required: true },
  category: { type: String, required: true },
  quantity: { type: Number, default: 0 },
  minStock: { type: Number, default: 1 },
  location: String,
  cost: { type: Number, default: 0 },
  supplier: String,
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  updatedAt: { type: Date, default: Date.now },
});

// TRUCK SCHEMA with cost tracking
const TruckSchema = new mongoose.Schema({
  truckId: { type: String, required: true, unique: true },
  name: { type: String, required: true },
  type: { type: String, enum: ["truck", "trailer"], required: true },
  vin: String,
  year: Number,
  make: String,
  model: String,
  notes: String,
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

// REPAIR SCHEMA with cost breakdown
const RepairSchema = new mongoose.Schema({
  date: { type: Date, required: true },
  truckId: { type: String, required: true },
  truckName: String,
  issue: { type: String, required: true },
  partsUsed: [
    {
      partId: String,
      partNumber: String,
      quantity: Number,
      unitCost: Number,
      totalCost: Number,
    },
  ],
  partsTotalCost: { type: Number, default: 0 },
  laborHours: Number,
  laborRate: { type: Number, default: 75 },
  laborCost: { type: Number, default: 0 },
  totalCost: { type: Number, default: 0 },
  mechanic: String,
  mechanicId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  notes: String,
  photos: [String],
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
  timestamp: { type: Date, default: Date.now },
});

const User = mongoose.model("User", UserSchema);
const Part = mongoose.model("Part", PartSchema);
const Truck = mongoose.model("Truck", TruckSchema);
const Repair = mongoose.model("Repair", RepairSchema);
const ActivityLog = mongoose.model("ActivityLog", ActivityLogSchema);

// Helper: Log activity
const logActivity = async (
  userId,
  username,
  action,
  entityType,
  entityId,
  details,
) => {
  await ActivityLog.create({
    userId,
    username,
    action,
    entityType,
    entityId,
    details,
  });
};

// Helper: Update truck costs
const updateTruckCosts = async (truckId) => {
  const repairs = await Repair.find({ truckId });
  const totalPartsCost = repairs.reduce(
    (sum, r) => sum + (r.partsTotalCost || 0),
    0,
  );
  const totalLaborCost = repairs.reduce(
    (sum, r) => sum + (r.laborCost || 0),
    0,
  );
  const totalRepairCost = repairs.reduce(
    (sum, r) => sum + (r.totalCost || 0),
    0,
  );

  await Truck.findOneAndUpdate(
    { truckId },
    {
      totalPartsCost,
      totalLaborCost,
      totalRepairCost,
      repairCount: repairs.length,
    },
  );
};

// AUTH ROUTES

// Login
app.post("/api/auth/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username, isActive: true });

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(400).json({ error: "Invalid credentials" });
    }

    user.lastLogin = new Date();
    await user.save();

    const token = jwt.sign(
      { userId: user._id, username: user.username, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "24h" },
    );

    res.json({
      token,
      user: {
        _id: user._id,
        id: user._id,
        username: user.username,
        role: user.role,
        name: user.name,
        isActive: user.isActive,
      },
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get current user
app.get("/api/auth/me", authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select("-password");
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// USER MANAGEMENT (Admin Only)

// Create user
app.post(
  "/api/users",
  authenticate,
  requireRole(["admin"]),
  async (req, res) => {
    try {
      const { username, password, role, name, email, phone } = req.body;

      const existingUser = await User.findOne({ username });
      if (existingUser)
        return res.status(400).json({ error: "Username already exists" });

      const hashedPassword = await bcrypt.hash(password, 10);
      const user = new User({
        username,
        password: hashedPassword,
        role,
        name,
        email,
        phone,
        createdBy: req.user.userId,
        isActive: true,
      });

      await user.save();
      await logActivity(
        req.user.userId,
        req.user.username,
        "CREATE_USER",
        "User",
        user.username,
        { username, role },
      );

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
  },
);

// Get all users
app.get(
  "/api/users",
  authenticate,
  requireRole(["admin"]),
  async (req, res) => {
    try {
      const users = await User.find()
        .select("-password")
        .sort({ createdAt: -1 });
      res.json(users);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  },
);

// Update user status (Enable/Disable) - PATCH method for frontend compatibility
app.patch(
  "/api/users/:id",
  authenticate,
  requireRole(["admin"]),
  async (req, res) => {
    try {
      const { isActive } = req.body;

      // Prevent disabling yourself
      if (req.params.id === req.user.userId && isActive === false) {
        return res
          .status(400)
          .json({ error: "Cannot disable your own account" });
      }

      const user = await User.findByIdAndUpdate(
        req.params.id,
        { isActive },
        { new: true },
      ).select("-password");

      if (!user) return res.status(404).json({ error: "User not found" });

      await logActivity(
        req.user.userId,
        req.user.username,
        isActive ? "USER_ENABLED" : "USER_DISABLED",
        "User",
        user.username,
        { isActive },
      );

      res.json({
        message: `User ${isActive ? "enabled" : "disabled"} successfully`,
        user,
      });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  },
);

// Keep the old PUT endpoint for backward compatibility
app.put(
  "/api/users/:id/status",
  authenticate,
  requireRole(["admin"]),
  async (req, res) => {
    try {
      const { isActive } = req.body;

      if (req.params.id === req.user.userId && isActive === false) {
        return res
          .status(400)
          .json({ error: "Cannot disable your own account" });
      }

      await User.findByIdAndUpdate(req.params.id, { isActive });

      await logActivity(
        req.user.userId,
        req.user.username,
        isActive ? "USER_ENABLED" : "USER_DISABLED",
        "User",
        req.params.id,
        { isActive },
      );

      res.json({ message: "User updated" });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  },
);

// Delete user permanently
app.delete(
  "/api/users/:id",
  authenticate,
  requireRole(["admin"]),
  async (req, res) => {
    try {
      // Prevent deleting yourself
      if (req.params.id === req.user.userId) {
        return res
          .status(400)
          .json({ error: "Cannot delete your own account" });
      }

      const user = await User.findById(req.params.id);
      if (!user) return res.status(404).json({ error: "User not found" });

      await User.findByIdAndDelete(req.params.id);

      await logActivity(
        req.user.userId,
        req.user.username,
        "USER_DELETED",
        "User",
        user.username,
        { deletedUser: user.username, role: user.role },
      );

      res.json({ message: "User deleted permanently" });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  },
);

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

    const thisMonthRepairs = await Repair.find({
      date: { $gte: startOfMonth },
    });
    const monthCost = thisMonthRepairs.reduce(
      (sum, r) => sum + (r.totalCost || 0),
      0,
    );

    const topVehicles = await Truck.find()
      .sort({ totalRepairCost: -1 })
      .limit(5)
      .select("truckId name totalRepairCost repairCount");

    res.json({
      totalParts,
      lowStock,
      fleetSize,
      monthCost,
      topVehicles,
      userRole: req.user.role,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Vehicle-specific stats
app.get("/api/vehicles/:truckId/stats", authenticate, async (req, res) => {
  try {
    const { truckId } = req.params;
    const truck = await Truck.findOne({ truckId });
    if (!truck) return res.status(404).json({ error: "Vehicle not found" });

    const repairs = await Repair.find({ truckId }).sort({ date: -1 });

    res.json({
      truck,
      repairs,
    });
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

app.post(
  "/api/parts",
  authenticate,
  requireRole(["admin", "mechanic"]),
  async (req, res) => {
    try {
      req.body.partNumber = req.body.partNumber.toUpperCase();
      const part = new Part({ ...req.body, createdBy: req.user.userId });
      await part.save();
      await logActivity(
        req.user.userId,
        req.user.username,
        "CREATE_PART",
        "part",
        part._id,
        req.body,
      );
      res.status(201).json(part);
    } catch (error) {
      res.status(400).json({ error: error.message });
    }
  },
);

app.put(
  "/api/parts/:id",
  authenticate,
  requireRole(["admin", "mechanic"]),
  async (req, res) => {
    try {
      req.body.updatedAt = Date.now();
      const part = await Part.findByIdAndUpdate(req.params.id, req.body, {
        new: true,
      });
      await logActivity(
        req.user.userId,
        req.user.username,
        "UPDATE_PART",
        "part",
        part._id,
        req.body,
      );
      res.json(part);
    } catch (error) {
      res.status(400).json({ error: error.message });
    }
  },
);

app.delete(
  "/api/parts/:id",
  authenticate,
  requireRole(["admin"]),
  async (req, res) => {
    try {
      const part = await Part.findById(req.params.id);
      if (!part) return res.status(404).json({ error: "Part not found" });

      await Part.findByIdAndDelete(req.params.id);
      await logActivity(
        req.user.userId,
        req.user.username,
        "DELETE_PART",
        "Part",
        part.partNumber,
        {},
      );
      res.json({ message: "Part deleted" });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  },
);

// TRUCKS API

app.get("/api/trucks", authenticate, async (req, res) => {
  try {
    const trucks = await Truck.find().sort({ createdAt: -1 });
    res.json(trucks);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post(
  "/api/trucks",
  authenticate,
  requireRole(["admin"]),
  async (req, res) => {
    try {
      req.body.truckId = req.body.truckId.toUpperCase();
      const truck = new Truck(req.body);
      await truck.save();
      await logActivity(
        req.user.userId,
        req.user.username,
        "CREATE_TRUCK",
        "truck",
        truck._id,
        req.body,
      );
      res.status(201).json(truck);
    } catch (error) {
      res.status(400).json({ error: error.message });
    }
  },
);

app.put(
  "/api/trucks/:id",
  authenticate,
  requireRole(["admin"]),
  async (req, res) => {
    try {
      const truck = await Truck.findByIdAndUpdate(req.params.id, req.body, {
        new: true,
      });
      res.json(truck);
    } catch (error) {
      res.status(400).json({ error: error.message });
    }
  },
);

app.delete(
  "/api/trucks/:id",
  authenticate,
  requireRole(["admin"]),
  async (req, res) => {
    try {
      const truck = await Truck.findById(req.params.id);
      if (!truck) return res.status(404).json({ error: "Vehicle not found" });

      // Check for repairs but allow force delete via query param
      const hasRepairs = await Repair.findOne({ truckId: truck.truckId });
      if (hasRepairs && !req.query.force) {
        return res
          .status(400)
          .json({
            error:
              "Vehicle has repair history. Use ?force=true to delete anyway.",
          });
      }

      // Delete repairs if force deleting
      if (hasRepairs && req.query.force) {
        await Repair.deleteMany({ truckId: truck.truckId });
      }

      await Truck.findByIdAndDelete(req.params.id);

      await logActivity(
        req.user.userId,
        req.user.username,
        "DELETE_TRUCK",
        "Truck",
        truck.truckId,
        { force: !!req.query.force },
      );

      res.json({ message: "Vehicle deleted" });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  },
);

// REPAIRS API

app.get("/api/repairs", authenticate, async (req, res) => {
  try {
    let query = {};
    if (req.user.role === "mechanic") {
      query.mechanicId = req.user.userId;
    }
    const repairs = await Repair.find(query).sort({ date: -1 }).limit(100);

    // Enrich with truck names
    const repairsWithTruckInfo = await Promise.all(
      repairs.map(async (r) => {
        const truck = await Truck.findOne({ truckId: r.truckId });
        return {
          ...r.toObject(),
          truckName: truck ? truck.name : r.truckId,
        };
      }),
    );

    res.json(repairsWithTruckInfo);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post(
  "/api/repairs",
  authenticate,
  requireRole(["admin", "mechanic"]),
  async (req, res) => {
    try {
      const {
        truckId,
        date,
        issue,
        laborCost,
        partId,
        quantityUsed,
        mechanic,
        notes,
      } = req.body;

      // Verify truck exists
      const truck = await Truck.findOne({ truckId });
      if (!truck) return res.status(404).json({ error: "Vehicle not found" });

      let partsTotalCost = 0;
      const partsUsed = [];

      // Handle single part from frontend form
      if (partId && quantityUsed > 0) {
        const part = await Part.findById(partId);
        if (part) {
          if (part.quantity < quantityUsed) {
            return res.status(400).json({
              error: `Insufficient stock for ${part.partNumber}. Only ${part.quantity} available`,
            });
          }

          const unitCost = part.cost || 0;
          const totalCost = unitCost * quantityUsed;

          partsUsed.push({
            partId: part._id,
            partNumber: part.partNumber,
            quantity: quantityUsed,
            unitCost: unitCost,
            totalCost: totalCost,
          });

          partsTotalCost = totalCost;

          // Update inventory
          part.quantity -= quantityUsed;
          await part.save();
        }
      }

      // Calculate costs
      const laborCostNum = parseFloat(laborCost) || 0;
      const totalCost = partsTotalCost + laborCostNum;

      const repair = new Repair({
        truckId,
        date: date || new Date(),
        issue,
        partsUsed,
        partsTotalCost,
        laborCost: laborCostNum,
        laborHours: laborCostNum / 75, // Assuming $75/hr rate
        laborRate: 75,
        totalCost,
        mechanic: mechanic || req.user.username,
        mechanicId: req.user.userId,
        notes,
        truckName: truck.name,
        status: "completed",
      });

      await repair.save();

      // Update truck stats
      await updateTruckCosts(truckId);

      await logActivity(
        req.user.userId,
        req.user.username,
        "CREATE_REPAIR",
        "Repair",
        repair._id,
        {
          truckId,
          truckName: truck.name,
          totalCost,
          issue: issue.substring(0, 50),
        },
      );

      res.status(201).json(repair);
    } catch (error) {
      console.error("Repair creation error:", error);
      res.status(400).json({ error: error.message });
    }
  },
);

app.delete(
  "/api/repairs/:id",
  authenticate,
  requireRole(["admin"]),
  async (req, res) => {
    try {
      const repair = await Repair.findById(req.params.id);
      if (repair) {
        // Return parts to inventory
        for (const used of repair.partsUsed || []) {
          if (used.partId) {
            await Part.findByIdAndUpdate(used.partId, {
              $inc: { quantity: used.quantity },
            });
          }
        }

        const truckId = repair.truckId;
        await Repair.findByIdAndDelete(req.params.id);
        await updateTruckCosts(truckId);

        await logActivity(
          req.user.userId,
          req.user.username,
          "DELETE_REPAIR",
          "Repair",
          req.params.id,
          { truckId },
        );
      }
      res.json({ message: "Repair deleted" });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  },
);

// ACTIVITY LOGS (Admin)

app.get(
  "/api/activity-logs",
  authenticate,
  requireRole(["admin"]),
  async (req, res) => {
    try {
      const logs = await ActivityLog.find()
        .sort({ timestamp: -1 })
        .limit(100)
        .populate("userId", "username name");
      res.json(logs);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  },
);

// EXPORT (Admin)

app.get(
  "/api/export",
  authenticate,
  requireRole(["admin"]),
  async (req, res) => {
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
  },
);

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

// Create default admin if no users exist
const createDefaultAdmin = async () => {
  try {
    const count = await User.countDocuments();
    if (count === 0) {
      const hashedPassword = await bcrypt.hash("admin123", 10);
      await User.create({
        username: "admin",
        password: hashedPassword,
        role: "admin",
        name: "System Administrator",
        isActive: true,
      });
      console.log("Default admin created: username=admin, password=admin123");
      console.log("Please change this password after first login!");
    }
  } catch (err) {
    console.error("Error creating default admin:", err);
  }
};

createDefaultAdmin();
