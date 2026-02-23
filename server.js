require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const compression = require("compression");
const path = require("path");

const app = express();

app.use(cors());
app.use(compression());
app.use(express.json({ limit: "50mb" }));
app.use(express.static(path.join(__dirname, "public")));

app.get("/health", (req, res) => res.status(200).json({ status: "healthy" }));

mongoose
  .connect(process.env.MONGODB_URI)
  .then(() => console.log("MongoDB Connected"))
  .catch((err) => console.error("MongoDB Error:", err));

const PartSchema = new mongoose.Schema({
  partNumber: { type: String, required: true, unique: true },
  description: { type: String, required: true },
  category: { type: String, required: true },
  quantity: { type: Number, default: 0 },
  minStock: { type: Number, default: 1 },
  location: String,
  cost: { type: Number, default: 0 },
  supplier: String,
  updatedAt: { type: Date, default: Date.now },
});

const TruckSchema = new mongoose.Schema({
  truckId: { type: String, required: true, unique: true },
  name: { type: String, required: true },
  type: { type: String, enum: ["truck", "trailer"], required: true },
  vin: String,
  notes: String,
});

const RepairSchema = new mongoose.Schema({
  date: { type: Date, required: true },
  truckId: { type: String, required: true },
  truckName: String,
  issue: { type: String, required: true },
  partsUsed: [{ partId: String, partNumber: String, quantity: Number }],
  laborHours: Number,
  mechanic: String,
  notes: String,
  photos: [String],
  totalCost: { type: Number, default: 0 },
});

const Part = mongoose.model("Part", PartSchema);
const Truck = mongoose.model("Truck", TruckSchema);
const Repair = mongoose.model("Repair", RepairSchema);

app.get("/api/stats", async (req, res) => {
  try {
    const [totalParts, lowStock, fleetSize] = await Promise.all([
      Part.countDocuments(),
      Part.countDocuments({ $expr: { $lte: ["$quantity", "$minStock"] } }),
      Truck.countDocuments(),
    ]);

    const startOfMonth = new Date();
    startOfMonth.setDate(1);
    const repairs = await Repair.find({ date: { $gte: startOfMonth } });

    let monthCost = 0;
    for (const repair of repairs) {
      for (const used of repair.partsUsed) {
        const part = await Part.findById(used.partId);
        if (part) monthCost += (part.cost || 0) * used.quantity;
      }
    }

    res.json({ totalParts, lowStock, fleetSize, monthCost });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get("/api/parts", async (req, res) => {
  try {
    const parts = await Part.find().sort({ updatedAt: -1 });
    res.json(parts);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post("/api/parts", async (req, res) => {
  try {
    req.body.partNumber = req.body.partNumber.toUpperCase();
    const part = new Part(req.body);
    await part.save();
    res.status(201).json(part);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.delete("/api/parts/:id", async (req, res) => {
  try {
    await Part.findByIdAndDelete(req.params.id);
    res.json({ message: "Part deleted" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get("/api/trucks", async (req, res) => {
  try {
    const trucks = await Truck.find().sort({ createdAt: -1 });
    res.json(trucks);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post("/api/trucks", async (req, res) => {
  try {
    req.body.truckId = req.body.truckId.toUpperCase();
    const truck = new Truck(req.body);
    await truck.save();
    res.status(201).json(truck);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.delete("/api/trucks/:id", async (req, res) => {
  try {
    await Truck.findByIdAndDelete(req.params.id);
    res.json({ message: "Vehicle deleted" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get("/api/repairs", async (req, res) => {
  try {
    const repairs = await Repair.find().sort({ date: -1 });
    res.json(repairs);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post("/api/repairs", async (req, res) => {
  try {
    let totalCost = 0;
    const truck = await Truck.findOne({ truckId: req.body.truckId });

    for (const used of req.body.partsUsed || []) {
      const part = await Part.findById(used.partId);
      if (part) {
        totalCost += (part.cost || 0) * used.quantity;
        part.quantity -= used.quantity;
        await part.save();
        used.partNumber = part.partNumber;
      }
    }

    const repair = new Repair({
      ...req.body,
      truckName: truck ? truck.name : req.body.truckId,
      totalCost,
    });

    await repair.save();
    res.status(201).json(repair);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.delete("/api/repairs/:id", async (req, res) => {
  try {
    await Repair.findByIdAndDelete(req.params.id);
    res.json({ message: "Repair deleted" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get("/api/export", async (req, res) => {
  try {
    const [parts, trucks, repairs] = await Promise.all([
      Part.find(),
      Truck.find(),
      Repair.find(),
    ]);
    res.json({ parts, trucks, repairs, exportDate: new Date() });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server running on port ${PORT}`);
});
