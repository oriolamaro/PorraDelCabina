// ───────────────────────────────────────────────────────────
// IMPORTACIONS
// ───────────────────────────────────────────────────────────
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

// ───────────────────────────────────────────────────────────
// CONNEXIÓ A MONGO
// ───────────────────────────────────────────────────────────
mongoose
    .connect(process.env.MONGO_URL, {
        useNewUrlParser: true,
        useUnifiedTopology: true,
    })
    .then(() => console.log("✅ Connectat a MongoDB"))
    .catch((err) => console.error("❌ Error de connexió:", err));

// ───────────────────────────────────────────────────────────
// MODELS
// ───────────────────────────────────────────────────────────
const apostaSchema = new mongoose.Schema({
    apostaId: { type: mongoose.Schema.Types.ObjectId, required: true },
    tipus: {
        type: String,
        enum: ["porra", "quiniela", "partit"],
        required: true,
    },
    titol: { type: String, required: true },
    seleccio: { type: String, required: true },
    diners: { type: Number, required: true },
    data: { type: Date, default: Date.now },
});

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
    apostes: [apostaSchema], // 👈 totes les apostes del jugador
    apostesCreades: [],
});
const User = mongoose.model("User", userSchema);

const participantPorraSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, required: true },
    username: { type: String, required: true },
    seleccio: { type: String, required: true },
    diners: { type: Number, required: true },
});
const porraSchema = new mongoose.Schema({
    titol: { type: String, required: true },
    opcions: [{ type: String, required: true }],
    creador: { type: String, required: true },
    apostat: { type: Number, default: 0 },
    participants: [participantPorraSchema],
    creatA: { type: Date, default: Date.now },
});
const Porra = mongoose.model("Porra", porraSchema);

const participantQuinielaSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, required: true },
    username: { type: String, required: true },
    seleccio: { type: String, required: true },
});
const quinielaSchema = new mongoose.Schema({
    titol: { type: String, required: true },
    partits: [
        {
            equipA: { type: String, required: true },
            equipB: { type: String, required: true },
        },
    ],
    creador: { type: String, required: true },
    apostat: { type: Number, default: 0 },
    participants: [participantQuinielaSchema],
    creatA: { type: Date, default: Date.now },
});
const Quiniela = mongoose.model("Quiniela", quinielaSchema);

const participantPartitSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, required: true },
    username: { type: String, required: true },
    seleccio: { type: String, required: true },
    diners: { type: Number, required: true },
});
const partitSchema = new mongoose.Schema({
    equipA: { type: String, required: true },
    equipB: { type: String, required: true },
    empatPermes: { type: Boolean, default: true },
    opcions: [{ type: String, required: true }],
    creador: { type: String, required: true },
    participants: { type: [participantPartitSchema], default: [] },
    apostat: { type: Number, default: 0 },
    creatA: { type: Date, default: Date.now },
});
const Partit = mongoose.model("Partit", partitSchema);

// ───────────────────────────────────────────────────────────
// MIDDLEWARE D'AUTENTICACIÓ JWT
// ───────────────────────────────────────────────────────────
function authMiddleware(req, res, next) {
    const authHeader = req.headers["authorization"];
    if (!authHeader) return res.status(401).send({ error: "No autoritzat" });

    const token = authHeader.split(" ")[1];
    if (!token) return res.status(401).send({ error: "Token no trobat" });

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        return res.status(403).send({ error: "Token caducat o invàlid" });
    }
}

// ───────────────────────────────────────────────────────────
// AUTENTICACIÓ: REGISTRE I LOGIN
// ───────────────────────────────────────────────────────────
app.post("/register", async (req, res) => {
    try {
        const { username, password, email, birthDate } = req.body;
        if (!username || !password || !email || !birthDate)
            return res.status(400).json({ error: "Falten camps obligatoris." });

        const existingUsername = await User.findOne({ username });
        if (existingUsername)
            return res.status(400).json({ error: "Nom d'usuari ja existeix." });

        const existingEmail = await User.findOne({ email });
        if (existingEmail)
            return res.status(400).json({ error: "Email ja registrat." });

        const birth = new Date(birthDate);
        const today = new Date();
        const age =
            today.getFullYear() -
            birth.getFullYear() -
            (today <
            new Date(today.getFullYear(), birth.getMonth(), birth.getDate())
                ? 1
                : 0);
        if (age < 18)
            return res
                .status(403)
                .json({ error: "Has de tenir 18 anys o més." });

        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({
            username,
            password: hashedPassword,
            email,
            birthDate,
            apostes: [],
        });

        await user.save();

        res.status(201).json({ message: "Usuari registrat correctament." });
    } catch (err) {
        console.error("❌ Error registre:", err);
        res.status(500).json({ error: "Error intern del servidor." });
    }
});

app.post("/login", async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password)
            return res.status(400).json({ error: "Falten camps obligatoris." });

        const user = await User.findOne({ username });
        if (!user) return res.status(401).json({ error: "Usuari no trobat." });

        const valid = await bcrypt.compare(password, user.password);
        if (!valid)
            return res.status(401).json({ error: "Contrasenya incorrecta." });

        const token = jwt.sign(
            {
                id: user._id.toString(),
                username: user.username,
                role: user.role,
            },
            JWT_SECRET,
            { expiresIn: "1h" }
        );
        res.json({ token, username: user.username, role: user.role });
    } catch (err) {
        console.error("❌ Error login:", err);
        res.status(500).json({ error: "Error intern del servidor." });
    }
});

// ───────────────────────────────────────────────────────────
// ACCEDIR A APOSTES
// ───────────────────────────────────────────────────────────
app.get("/quinieles/mostrar", async (req, res) => {
    try {
        const totesLesQuinieles = await Quiniela.find();
        res.json(totesLesQuinieles);
    } catch (err) {
        console.error("Error obtinguent les quinieles: ", err);
        res.status(500).json({ error: "Error intern." });
    }
});

app.get("/porres/mostrar", async (req, res) => {
    try {
        const totesLesPorres = await Porra.find();
        res.json(totesLesPorres);
    } catch (err) {
        console.error("Error obtinguent les porres: ", err);
        res.status(500).json({ error: "Error intern." });
    }
});

app.get("/partits/mostrar", async (req, res) => {
    try {
        const totsElsPartits = await Partit.find();
        res.json(totsElsPartits);
    } catch (err) {
        console.error("Error obtinguent els partits: ", err);
        res.status(500).json({ error: "Error intern." });
    }
});

// ───────────────────────────────────────────────────────────
// RUTES PROTEGIDES PER CREAR APOSTES
// ───────────────────────────────────────────────────────────
app.post("/porres/afegir", authMiddleware, async (req, res) => {
    try {
        if (req.user.role !== "organitzador") {
            return res
                .status(403)
                .json({ error: "Accés denegat. No ets organitzador." });
        }

        const { titol, opcions } = req.body;
        if (!titol || !Array.isArray(opcions) || opcions.length < 2) {
            return res
                .status(400)
                .json({ error: "Títol i mínim dues opcions requerides." });
        }

        // 🔹 Crear la nova porra
        const novaPorra = new Porra({
            titol,
            opcions,
            creador: req.user.username, // o req.user.id si prefereixes
            participants: [],
        });

        await novaPorra.save();

        // 🔹 Afegir l'ID de la porra a "apostesCreades" de l'usuari
        await User.findByIdAndUpdate(req.user.id, {
            $push: { apostesCreades: novaPorra._id },
        });

        res.status(201).json({
            message: "Porra creada correctament.",
            porraId: novaPorra._id, // opcional: et retornem l'ID
        });
    } catch (err) {
        console.error("❌ Error creant porra:", err);
        res.status(500).json({ error: "Error intern." });
    }
});

app.post("/quinieles/afegir", authMiddleware, async (req, res) => {
    try {
        if (req.user.role !== "organitzador") {
            return res
                .status(403)
                .json({ error: "Accés denegat. No ets organitzador." });
        }

        const { titol, partits } = req.body;

        const partitsValids = partits.filter(
            (p) => p?.equipA?.trim() && p?.equipB?.trim()
        );

        if (partitsValids.length < 4) {
            return res
                .status(400)
                .json({ error: "Mínim quatre partits vàlids requerits." });
        }

        for (const [index, p] of partits.entries()) {
            if (
                typeof p !== "object" ||
                p === null ||
                !("equipA" in p) ||
                !("equipB" in p) ||
                typeof p.equipA !== "string" ||
                p.equipA.trim() === "" ||
                typeof p.equipB !== "string" ||
                p.equipB.trim() === ""
            ) {
                return res.status(400).json({
                    error: `El partit a la posició ${index} ha de tenir equipA i equipB com a text no buit.`,
                });
            }
        }

        const novaQuiniela = new Quiniela({
            titol,
            partits: partitsValids,
            creador: req.user.username,
            participants: [],
        });

        await novaQuiniela.save();
        await User.findByIdAndUpdate(req.user.id, {
            $push: { apostesCreades: novaQuiniela._id },
        });

        res.status(201).json({ message: "Quiniela creada." });
    } catch (err) {
        console.error("❌ Error creant quiniela:", err);
        res.status(500).json({ error: "Error intern." });
    }
});

app.post("/partits/afegir", authMiddleware, async (req, res) => {
    try {
        if (req.user.role !== "organitzador") {
            return res
                .status(403)
                .json({ error: "Accés denegat. No ets organitzador." });
        }

        const { equipA, equipB, empatPermes, opcions } = req.body;
        if (!equipA || !equipB || !Array.isArray(opcions) || opcions.length < 2)
            return res
                .status(400)
                .json({ error: "Equips i opcions requerits." });

        const nouPartit = new Partit({
            equipA,
            equipB,
            empatPermes: empatPermes ?? true,
            opcions,
            creador: req.user.username,
            participants: [], // 👈 afegit
        });

        await nouPartit.save();
        await User.findByIdAndUpdate(req.user.id, {
            $push: { apostesCreades: nouPartit._id },
        });

        res.status(201).json({ message: "Partit creat." });
    } catch (err) {
        console.error("❌ Error creant partit:", err);
        res.status(500).json({ error: "Error intern." });
    }
});

// ───────────────────────────────────────────────────────────
// RUTA PROTEGIDA PER APOSTAR
// ───────────────────────────────────────────────────────────
app.post("/aposta", authMiddleware, async (req, res) => {
    try {
        const { apostaId, tipus, seleccio, diners } = req.body;
        const userId = req.user.id; // ve del token (veure login)

        // camps obligatoris
        if (
            !apostaId ||
            !tipus ||
            seleccio === undefined ||
            seleccio === null ||
            diners === undefined
        ) {
            return res.status(400).json({ error: "Falten camps obligatoris." });
        }

        if (typeof diners !== "number" || diners <= 0) {
            return res
                .status(400)
                .json({ error: "Quantitat de diners no vàlida." });
        }

        // buscar usuari
        const user = await User.findById(userId);
        if (!user) return res.status(404).json({ error: "Usuari no trobat." });

        if (user.walletBalance < diners) {
            return res.status(403).json({ error: "Saldo insuficient." });
        }

        // tria model
        let ApostaModel;
        if (tipus === "porra") ApostaModel = Porra;
        else if (tipus === "quiniela") ApostaModel = Quiniela;
        else if (tipus === "partit") ApostaModel = Partit;
        else return res.status(400).json({ error: "Tipus d'aposta no vàlid." });

        // buscar aposta
        const aposta = await ApostaModel.findById(apostaId);
        if (!aposta)
            return res.status(404).json({ error: "Aposta no trobada." });

        // Normalitzem i validem selecció segons tipus
        let seleccioText = null;

        if (tipus === "porra") {
            // porra.opcions -> array de strings
            const opcionsArr = aposta.opcions || [];
            if (typeof seleccio === "number") {
                if (seleccio < 0 || seleccio >= opcionsArr.length) {
                    return res
                        .status(400)
                        .json({ error: "Selecció de porra fora de rang." });
                }
                seleccioText = opcionsArr[seleccio];
            } else if (typeof seleccio === "string") {
                // si s'envia "0"/"1" etc
                const maybeIdx = parseInt(seleccio, 10);
                if (
                    !isNaN(maybeIdx) &&
                    maybeIdx >= 0 &&
                    maybeIdx < opcionsArr.length
                ) {
                    seleccioText = opcionsArr[maybeIdx];
                } else {
                    // acceptem també la string exacta si existeix
                    const idx = opcionsArr.indexOf(seleccio);
                    if (idx >= 0) seleccioText = opcionsArr[idx];
                    else seleccioText = seleccio; // acceptem text lliure (no ideal, però no trenca)
                }
            } else {
                return res
                    .status(400)
                    .json({ error: "Selecció no vàlida per porra." });
            }
        } else if (tipus === "partit") {
            // Partit → acceptem 0/1/2 o textes equipA/equipB/"Empat"
            const equipA = aposta.equipA;
            const equipB = aposta.equipB;
            const empatPermes = !!aposta.empatPermes;

            if (typeof seleccio === "number") {
                if (seleccio === 0) seleccioText = equipA;
                else if (seleccio === 1) {
                    if (!empatPermes)
                        return res.status(400).json({
                            error: "Empat no permès per aquest partit.",
                        });
                    seleccioText = "Empat";
                } else if (seleccio === 2) seleccioText = equipB;
                else
                    return res
                        .status(400)
                        .json({ error: "Selecció de partit no vàlida." });
            } else if (typeof seleccio === "string") {
                const s = seleccio.trim();
                if (s.toLowerCase() === "empat" || s === "Empat") {
                    if (!empatPermes)
                        return res.status(400).json({
                            error: "Empat no permès per aquest partit.",
                        });
                    seleccioText = "Empat";
                } else if (s === equipA || s === equipB) {
                    seleccioText = s;
                } else {
                    const maybeIdx = parseInt(s, 10);
                    if (!isNaN(maybeIdx)) {
                        // rerun number logic
                        if (maybeIdx === 0) seleccioText = equipA;
                        else if (maybeIdx === 1) {
                            if (!empatPermes)
                                return res.status(400).json({
                                    error: "Empat no permès per aquest partit.",
                                });
                            seleccioText = "Empat";
                        } else if (maybeIdx === 2) seleccioText = equipB;
                        else
                            return res.status(400).json({
                                error: "Selecció de partit no vàlida.",
                            });
                    } else {
                        // no reconegut
                        return res
                            .status(400)
                            .json({ error: "Selecció de partit no vàlida." });
                    }
                }
            } else {
                return res
                    .status(400)
                    .json({ error: "Selecció no vàlida per partit." });
            }
        } else if (tipus === "quiniela") {
            // Per quiniela acceptem: string (ja format) o array/object amb dades.
            if (Array.isArray(seleccio) || typeof seleccio === "object") {
                try {
                    seleccioText = JSON.stringify(seleccio);
                } catch (err) {
                    seleccioText = String(seleccio);
                }
            } else {
                seleccioText = String(seleccio);
            }
        }

        // a aquest punt tenim seleccioText com a string
        if (!seleccioText) {
            return res
                .status(400)
                .json({ error: "No s'ha pogut normalitzar la selecció." });
        }

        // 💰 Restar diners al jugador
        user.walletBalance -= diners;

        // 📌 Guardar aposta dins de l'usuari (registre personal)
        user.apostes = user.apostes || [];
        user.apostes.push({
            apostaId: aposta._id,
            tipus,
            titol:
                aposta.titol ||
                (tipus === "partit"
                    ? `${aposta.equipA} vs ${aposta.equipB}`
                    : ""),
            seleccio: seleccioText,
            diners,
            data: new Date(),
        });
        await user.save();

        // 📌 Guardar participant dins de l'aposta
        aposta.participants = aposta.participants || [];
        aposta.participants.push({
            userId: user._id,
            username: user.username,
            seleccio: seleccioText,
            diners,
        });
        await aposta.save();

        res.status(201).json({
            message: "✅ Aposta registrada correctament.",
            walletBalance: user.walletBalance,
        });
    } catch (err) {
        console.error("❌ Error /aposta:", err);
        res.status(500).json({ error: "Error intern del servidor." });
    }
});

// ───────────────────────────────────────────────────────────
// GESTIONAR APOSTES CREADES PER L'ORGANITZADOR
// ───────────────────────────────────────────────────────────
app.get("/gestiona", authMiddleware, async (req, res) => {
    try {
        // ✅ Només organitzadors poden accedir
        if (req.user.role !== "organitzador") {
            return res
                .status(403)
                .json({ error: "Accés denegat. No ets organitzador." });
        }

        // ✅ Recuperem l'usuari i les seves apostesCreades
        const user = await User.findById(req.user.id).select("apostesCreades");
        if (!user) {
            return res.status(404).json({ error: "Usuari no trobat." });
        }

        // ✅ Recuperem les dades completes de cada aposta
        const apostes = await Porra.find({
            _id: { $in: user.apostesCreades },
        }).select("titol opcions participants");

        // ✅ Preparem dades per al frontend
        const resultat = apostes.map((porra) => {
            // participants és un array amb { usuariId, seleccio, diners }
            const totalDiners = porra.participants.reduce(
                (acc, p) => acc + (p.diners || 0),
                0
            );

            return {
                id: porra._id,
                titol: porra.titol,
                opcions: porra.opcions,
                participants: porra.participants, // ja inclou usuari, selecció i diners
                totalDiners,
            };
        });

        res.json({ apostesCreades: resultat });
    } catch (err) {
        console.error("❌ Error a /gestiona:", err);
        res.status(500).json({ error: "Error intern del servidor" });
    }
});

// ───────────────────────────────────────────────────────────
// INFO USER
// ───────────────────────────────────────────────────────────
app.get("/me", authMiddleware, async (req, res) => {
    try {
        const userId = req.user.id; // ve del token
        const user = await User.findById(userId);

        if (!user) {
            return res.status(404).json({ error: "Usuari no trobat." });
        }

        res.json({
            id: user._id,
            username: user.username,
            walletBalance: user.walletBalance,
            apostes: user.apostes || [],
        });
    } catch (err) {
        console.error("❌ Error /me:", err);
        res.status(500).json({ error: "Error intern del servidor." });
    }
});

// ───────────────────────────────────────────────────────────
// INICI SERVIDOR
// ───────────────────────────────────────────────────────────
app.listen(3000, () => console.log("🌐 Servidor escoltant al port 3000"));
