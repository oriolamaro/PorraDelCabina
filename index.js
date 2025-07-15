const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");
require("dotenv").config();

const app = express();
app.use(cors());
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET;

// Connexió a MongoDB
mongoose
    .connect(process.env.MONGO_URL, {
        useNewUrlParser: true,
        useUnifiedTopology: true,
    })
    .then(() => console.log("✅ Connectat a MongoDB"))
    .catch((err) => console.error("❌ Error de connexió:", err));

// Esquema de l'usuari
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

// Ruta POST per registrar
app.post("/register", async (req, res) => {
    try {
        const { username, password, email, birthDate } = req.body;

        if (!username || !password || !email || !birthDate)
            return res.status(400).send({
                errorCode: "MISSING_FIELDS",
                error: "Falten camps obligatoris.",
            });

        // Comprovem si l'usuari ja existeix
        const existingUsername = await User.findOne({ username });
        if (existingUsername)
            return res.status(400).send({
                errorCode: "USERNAME_EXISTS",
                error: "Aquest nom d'usuari ja existeix.",
            });

        const existingEmail = await User.findOne({ email });
        if (existingEmail)
            return res.status(400).send({
                errorCode: "EMAIL_EXISTS",
                error: "Aquest correu ja està registrat.",
            });

        // Comprovació d'edat
        const birth = new Date(birthDate);
        const today = new Date();
        const age =
            today.getFullYear() -
            birth.getFullYear() -
            (today <
            new Date(today.getFullYear(), birth.getMonth(), birth.getDate())
                ? 1
                : 0);

        if (age < 18) {
            return res.status(403).send({
                errorCode: "UNDERAGE",
                error: "Has de tenir 18 anys o més.",
            });
        }

        // Xifrem la contrasenya
        const hashedPassword = await bcrypt.hash(password, 10);

        // Creem i guardem el nou usuari
        const user = new User({
            username,
            password: hashedPassword,
            email,
            birthDate: new Date(birthDate),
        });

        await user.save();

        res.status(201).send({ message: "Usuari registrat correctament." });
    } catch (error) {
        console.error("❌ Error durant registre:", error);
        res.status(500).send({
            errorCode: "SERVER_ERROR",
            error: "Error intern del servidor.",
        });
    }
});

// Ruta POST per login
app.post("/login", async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password)
            return res.status(400).send({
                errorCode: "MISSING_FIELDS",
                error: "Falten camps obligatoris.",
            });

        const user = await User.findOne({ username });
        if (!user)
            return res.status(401).send({
                errorCode: "USER_NOT_FOUND",
                error: "Usuari no trobat.",
            });

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword)
            return res.status(401).send({
                errorCode: "INVALID_PASSWORD",
                error: "Contrasenya incorrecta.",
            });

        const token = jwt.sign({ username }, JWT_SECRET, {
            expiresIn: "1h",
        });

        res.send({
            token,
            username: user.username,
            role: user.role, // 👈 Afegeix el rol aquí
        });
    } catch (error) {
        console.error("❌ Error durant login:", error);
        res.status(500).send({
            errorCode: "SERVER_ERROR",
            error: "Error intern del servidor.",
        });
    }
});

app.listen(3000, () => console.log("🌐 Servidor escoltant al port 3000"));
