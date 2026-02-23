require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const compression = require("compression");
const path = require("path");

const app = express();

// Middleware
app.use(cors());
app.use(compression());
app.use(express.json({ limit: "50mb" })); // Increased for photo uploads
app.use(express.static(path.join(__dirname, "public")));

// Health check endpoint (required for Railway)
app.get("/health", (req, res) => {
  res
    .status(200)
    .json({ status: "healthy", timestamp: new Date().toISOString() });
});

// MongoDB Connection
const connectDB = async () => {
  try {
    const conn = await mongoose.connect(process.env.MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    console.log(`✅ MongoDB Connected: ${conn.connection.host}`);
    return true;
  } catch (error) {
    console.error(`❌ MongoDB Error: ${error.message}`);
    // Retry connection after 5 seconds
    setTimeout(connectDB, 5000);
  }
};

connectDB();

// Schemas with validation
const PartSchema = new mongoose.Schema({
  partNumber: { type: String, required: true, unique: true, trim: true },
  description: { type: String, required: true, trim: true },
  category: {
    type: String,
    required: true,
    enum: [
      "Engine",
      "Transmission",
      "Brakes",
      "Electrical",
      "Body",
      "Tires",
      "Steering",
      "Other",
    ],
  },
  quantity: { type: Number, required: true, default: 0, min: 0 },
  minStock: { type: Number, required: true, default: 1, min: 0 },
  location: { type: String, trim: true },
  cost: { type: Number, default: 0, min: 0 },
  supplier: { type: String, trim: true },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
});

const TruckSchema = new mongoose.Schema({
  truckId: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    uppercase: true,
  },
  name: { type: String, required: true, trim: true },
  type: { type: String, enum: ["truck", "trailer"], required: true },
  vin: { type: String, trim: true },
  notes: { type: String, trim: true },
  createdAt: { type: Date, default: Date.now },
});

const RepairSchema = new mongoose.Schema({
  date: { type: Date, required: true },
  truckId: { type: String, required: true, index: true },
  truckName: String,
  issue: { type: String, required: true },
  partsUsed: [
    {
      partId: { type: String, required: true },
      partNumber: String,
      quantity: { type: Number, required: true, min: 1 },
    },
  ],
  laborHours: { type: Number, default: 0 },
  mechanic: String,
  notes: String,
  photos: [{ type: String }], // Array of base64 strings
  totalCost: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now, index: true },
});

// Update timestamp middleware
PartSchema.pre("save", function (next) {
  this.updatedAt = Date.now();
  next();
});

const Part = mongoose.model("Part", PartSchema);
const Truck = mongoose.model("Truck", TruckSchema);
const Repair = mongoose.model("Repair", RepairSchema);

// ==========================================
// API ROUTES
// ==========================================

// Stats Dashboard
app.get("/api/stats", async (req, res) => {
  try {
    const [totalParts, lowStock, fleetSize] = await Promise.all([
      Part.countDocuments(),
      Part.countDocuments({ $expr: { $lte: ["$quantity", "$minStock"] } }),
      Truck.countDocuments(),
    ]);

    // Calculate this month's repair costs
    const startOfMonth = new Date();
    startOfMonth.setDate(1);
    startOfMonth.setHours(0, 0, 0, 0);

    const thisMonthRepairs = await Repair.find({
      date: { $gte: startOfMonth },
    }).lean();

    let monthCost = 0;
    for (const repair of thisMonthRepairs) {
      for (const used of repair.partsUsed) {
        const part = await Part.findById(used.partId).lean();
        if (part) monthCost += (part.cost || 0) * used.quantity;
      }
    }

    res.json({
      totalParts,
      lowStock,
      fleetSize,
      monthCost: Math.round(monthCost * 100) / 100,
      lastUpdated: new Date().toISOString(),
    });
  } catch (error) {
    console.error("Stats error:", error);
    res.status(500).json({ error: "Failed to load stats" });
  }
});

// Parts Routes
app.get("/api/parts", async (req, res) => {
  try {
    const { search, lowStock } = req.query;
    let query = {};

    if (search) {
      query.$or = [
        { partNumber: { $regex: search, $options: "i" } },
        { description: { $regex: search, $options: "i" } },
      ];
    }

    if (lowStock === "true") {
      query.$expr = { $lte: ["$quantity", "$minStock"] };
    }

    const parts = await Part.find(query).sort({ updatedAt: -1 }).lean();
    res.json(parts);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post("/api/parts", async (req, res) => {
  try {
    // Check for duplicate part number
    const existing = await Part.findOne({
      partNumber: req.body.partNumber.toUpperCase(),
    });
    if (existing) {
      return res.status(400).json({ error: "Part number already exists" });
    }

    const part = new Part(req.body);
    await part.save();
    res.status(201).json(part);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.put("/api/parts/:id", async (req, res) => {
  try {
    const part = await Part.findByIdAndUpdate(
      req.params.id,
      { ...req.body, updatedAt: Date.now() },
      { new: true, runValidators: true },
    );
    if (!part) return res.status(404).json({ error: "Part not found" });
    res.json(part);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.delete("/api/parts/:id", async (req, res) => {
  try {
    // Check if part is used in repairs
    const repairsUsingPart = await Repair.findOne({
      "partsUsed.partId": req.params.id,
    });
    if (repairsUsingPart) {
      return res.status(400).json({
        error:
          "Cannot delete part that has repair history. Archive it instead.",
      });
    }

    await Part.findByIdAndDelete(req.params.id);
    res.json({ message: "Part deleted successfully" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Trucks Routes
app.get("/api/trucks", async (req, res) => {
  try {
    const trucks = await Truck.find().sort({ type: 1, truckId: 1 }).lean();
    res.json(trucks);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post("/api/trucks", async (req, res) => {
  try {
    // Auto-uppercase ID
    req.body.truckId = req.body.truckId.toUpperCase();

    const existing = await Truck.findOne({ truckId: req.body.truckId });
    if (existing) {
      return res.status(400).json({ error: "Vehicle ID already exists" });
    }

    const truck = new Truck(req.body);
    await truck.save();
    res.status(201).json(truck);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.delete("/api/trucks/:id", async (req, res) => {
  try {
    // Check for repair history
    const repairs = await Repair.findOne({ truckId: req.params.id });
    if (repairs) {
      return res.status(400).json({
        error: "Cannot delete vehicle with repair history",
      });
    }

    await Truck.findByIdAndDelete(req.params.id);
    res.json({ message: "Vehicle deleted" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Repairs Routes
app.get("/api/repairs", async (req, res) => {
  try {
    const { truckId, startDate, endDate } = req.query;
    let query = {};

    if (truckId) query.truckId = truckId;
    if (startDate || endDate) {
      query.date = {};
      if (startDate) query.date.$gte = new Date(startDate);
      if (endDate) query.date.$lte = new Date(endDate);
    }

    const repairs = await Repair.find(query).sort({ date: -1 }).lean();
    res.json(repairs);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post("/api/repairs", async (req, res) => {
  const session = await mongoose.startSession();
  session.startTransaction();

  try {
    // Calculate total cost and deduct inventory
    let totalCost = 0;
    const truck = await Truck.findOne({ truckId: req.body.truckId }).lean();

    for (const used of req.body.partsUsed || []) {
      const part = await Part.findById(used.partId).session(session);
      if (part) {
        // Check stock
        if (part.quantity < used.quantity) {
          throw new Error(
            `Insufficient stock for ${part.partNumber}. Available: ${part.quantity}`,
          );
        }

        totalCost += (part.cost || 0) * used.quantity;
        part.quantity -= used.quantity;
        await part.save({ session });
        used.partNumber = part.partNumber; // Store for reference
      }
    }

    const repair = new Repair({
      ...req.body,
      truckName: truck ? truck.name : req.body.truckId,
      totalCost,
    });

    await repair.save({ session });
    await session.commitTransaction();

    res.status(201).json(repair);
  } catch (error) {
    await session.abortTransaction();
    res.status(400).json({ error: error.message });
  } finally {
    session.endSession();
  }
});

app.delete("/api/repairs/:id", async (req, res) => {
  try {
    await Repair.findByIdAndDelete(req.params.id);
    res.json({ message: "Repair record deleted" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Bulk Import/Export
app.post("/api/import", async (req, res) => {
  try {
    const { parts, trucks, repairs } = req.body;
    const results = { parts: 0, trucks: 0, repairs: 0, errors: [] };

    if (parts && parts.length) {
      try {
        await Part.insertMany(parts, { ordered: false });
        results.parts = parts.length;
      } catch (e) {
        results.errors.push(`Parts: ${e.message}`);
      }
    }

    if (trucks && trucks.length) {
      try {
        await Truck.insertMany(trucks, { ordered: false });
        results.trucks = trucks.length;
      } catch (e) {
        results.errors.push(`Trucks: ${e.message}`);
      }
    }

    if (repairs && repairs.length) {
      try {
        await Repair.insertMany(repairs, { ordered: false });
        results.repairs = repairs.length;
      } catch (e) {
        results.errors.push(`Repairs: ${e.message}`);
      }
    }

    res.json({ message: "Import completed", results });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.get("/api/export", async (req, res) => {
  try {
    const [parts, trucks, repairs] = await Promise.all([
      Part.find().lean(),
      Truck.find().lean(),
      Repair.find().lean(),
    ]);

    res.json({
      parts,
      trucks,
      repairs,
      exportDate: new Date().toISOString(),
      version: "1.0",
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Serve React/Vue/Angular or static frontend
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: "Something broke!" });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 Fleet Parts Tracker running on port ${PORT}`);
  console.log(`📊 Health check: http://localhost:${PORT}/health`);
});
