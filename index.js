// Importem les llibreries
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");
require("dotenv").config();

const app = express();

// Cors: permet accés des del teu frontend (pots afinar l'origen si vols)
app.use(cors({
  origin: "*" // o el URL del frontend, per exemple "https://meufrontend.com"
}));

// Middleware per parsejar JSON
app.use(express.json());

// Clau secreta per JWT (comprova que està definida)
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  console.error("❌ ERROR: La variable d'entorn JWT_SECRET no està definida.");
  process.exit(1);
}

// Connexió a MongoDB
mongoose
  .connect(process.env.MONGO_URL, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("✅ Connectat a MongoDB"))
  .catch((err) => {
    console.error("❌ Error de connexió a MongoDB:", err);
    process.exit(1);
  });

// Esquema i model d'usuari
const userSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  email: { type: String, unique: true, required: true },
  birthDate: { type: Date, required: true },
  role: {
    type: String,
    enum: ["organitzador", "jugador"],
    default: "jugador",
  },
  isEmailVerified: { type: Boolean, default: false },
  walletBalance: { type: Number, default: 0 },
  kycStatus: {
    type: String,
    enum: ["none", "pending", "verified", "rejected"],
    default: "none",
  },
  createdAt: { type: Date, default: Date.now },
});

const User = mongoose.model("User", userSchema);

// Ruta POST /register
app.post("/register", async (req, res) => {
  try {
    const { username, password, email, birthDate } = req.body;

    if (!username || !password || !email || !birthDate) {
      return res.status(400).json({
        errorCode: "MISSING_FIELDS",
        error: "Falten camps obligatoris.",
      });
    }

    // Comprovar si l'usuari o email ja existeixen
    const existingUsername = await User.findOne({ username });
    if (existingUsername) {
      return res.status(400).json({
        errorCode: "USERNAME_EXISTS",
        error: "Aquest nom d'usuari ja existeix.",
      });
    }

    const existingEmail = await User.findOne({ email });
    if (existingEmail) {
      return res.status(400).json({
        errorCode: "EMAIL_EXISTS",
        error: "Aquest correu ja està registrat.",
      });
    }

    // Comprovació d'edat (18 anys mínim)
    const birth = new Date(birthDate);
    const today = new Date();
    let age = today.getFullYear() - birth.getFullYear();
    const monthDiff = today.getMonth() - birth.getMonth();
    if (monthDiff < 0 || (monthDiff === 0 && today.getDate() < birth.getDate())) {
      age--;
    }

    if (age < 18) {
      return res.status(403).json({
        errorCode: "UNDERAGE",
        error: "Has de tenir 18 anys o més.",
      });
    }

    // Hashejar la contrasenya
    const hashedPassword = await bcrypt.hash(password, 10);

    // Crear i guardar l'usuari
    const user = new User({
      username,
      password: hashedPassword,
      email,
      birthDate: birth,
    });

    await user.save();

    return res.status(201).json({ message: "Usuari registrat correctament." });
  } catch (error) {
    console.error("❌ Error durant registre:", error);
    return res.status(500).json({
      errorCode: "SERVER_ERROR",
      error: "Error intern del servidor.",
    });
  }
});

// Ruta POST /login
app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({
        errorCode: "MISSING_FIELDS",
        error: "Falten camps obligatoris.",
      });
    }

    const user = await User.findOne({ username });
    if (!user) {
      return res.status(401).json({
        errorCode: "USER_NOT_FOUND",
        error: "Usuari no trobat.",
      });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({
        errorCode: "INVALID_PASSWORD",
        error: "Contrasenya incorrecta.",
      });
    }

    const token = jwt.sign({ username }, JWT_SECRET, {
      expiresIn: "1h",
    });

    return res.json({ token });
  } catch (error) {
    console.error("❌ Error durant login:", error);
    return res.status(500).json({
      errorCode: "SERVER_ERROR",
      error: "Error intern del servidor.",
    });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🌐 Servidor escoltant al port ${PORT}`);
});
