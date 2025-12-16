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
    competicionsCreades: [
        { type: mongoose.Schema.Types.ObjectId, ref: "Competició" },
    ],
});
const User = mongoose.model("User", userSchema);

const participantSchema = new mongoose.Schema({
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
    participants: [participantSchema],
    creatA: { type: Date, default: Date.now },
});
const Porra = mongoose.model("Porra", porraSchema);

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
    participants: [participantSchema],
    creatA: { type: Date, default: Date.now },
});
const Quiniela = mongoose.model("Quiniela", quinielaSchema);

const partitSchema = new mongoose.Schema({
    titol: { type: String, required: true },
    equipA: { type: String, required: true },
    equipB: { type: String, required: true },
    empatPermes: { type: Boolean, default: true },
    opcions: [{ type: String, required: true }],
    creador: { type: String, required: true },
    participants: { type: [participantSchema], default: [] },
    apostat: { type: Number, default: 0 },
    creatA: { type: Date, default: Date.now },
});
const Partit = mongoose.model("Partit", partitSchema);

const partitIncrustatSchema = new mongoose.Schema({
    equip1: { type: String },
    equip2: { type: String },
    team1: { type: String },
    team2: { type: String },
    round: { type: Number },
    position: { type: Number },
    grup: { type: String },
    data: { type: Date, default: null },
    apostable: { type: Boolean, default: false },
    resultatEquip1: { type: Number, default: null },
    resultatEquip2: { type: Number, default: null },
    guanyadorPartit: { type: String, default: null },
    estatPartit: {
        type: String,
        enum: ["pendent", "en_joc", "finalitzat", "cancel·lat"],
        default: "pendent",
    },
});

// Aquest és l'esquema principal per a la col·lecció 'competicions'
const competicioSchema = new mongoose.Schema({
    nomCompeticio: { type: String, required: true },
    organitzadorId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
        required: true,
    }, // Referència a qui la crea
    tipus: {
        type: String,
        enum: ["classificatori", "grups", "individuals"],
        required: true,
    },
    dataCreacio: { type: Date, default: Date.now },
    partits: [partitIncrustatSchema],
});

const Competició = mongoose.model("Competició", competicioSchema);

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

        const { titol, equipA, equipB, empatPermes, opcions } = req.body;
        if (
            !titol ||
            !equipA ||
            !equipB ||
            !Array.isArray(opcions) ||
            opcions.length < 2
        )
            return res.status(400).json({ error: "Títol i equips requerits." });

        const nouPartit = new Partit({
            titol,
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
        const userId = req.user.id; // del token

        // ✅ Camps obligatoris
        if (
            !apostaId ||
            !tipus ||
            seleccio === undefined ||
            seleccio === null
        ) {
            return res.status(400).json({ error: "Falten camps obligatoris." });
        }

        // ✅ Si no s’envia diners, per defecte 1
        const quantitat = typeof diners === "number" && diners > 0 ? diners : 1;

        // ✅ Buscar usuari
        const user = await User.findById(userId);
        if (!user) return res.status(404).json({ error: "Usuari no trobat." });

        if (user.walletBalance < quantitat) {
            return res.status(403).json({ error: "Saldo insuficient." });
        }

        // ✅ Tria model segons tipus
        let ApostaModel;
        if (tipus === "porra") ApostaModel = Porra;
        else if (tipus === "quiniela") ApostaModel = Quiniela;
        else if (tipus === "partit") ApostaModel = Partit;
        else return res.status(400).json({ error: "Tipus d'aposta no vàlid." });

        // ✅ Buscar aposta
        const aposta = await ApostaModel.findById(apostaId);
        if (!aposta)
            return res.status(404).json({ error: "Aposta no trobada." });

        // ✅ Normalitzar selecció
        let seleccioText = null;
        if (tipus === "porra") {
            const opcionsArr = aposta.opcions || [];
            if (typeof seleccio === "number" && opcionsArr[seleccio]) {
                seleccioText = opcionsArr[seleccio];
            } else if (typeof seleccio === "string") {
                seleccioText = seleccio;
            }
        } else if (tipus === "partit") {
            const { equipA, equipB, empatPermes } = aposta;
            if (seleccio === 0 || seleccio === equipA) seleccioText = equipA;
            else if (
                seleccio === 1 ||
                seleccio === "Empat" ||
                seleccio.toLowerCase?.() === "empat"
            ) {
                if (!empatPermes)
                    return res.status(400).json({ error: "Empat no permès." });
                seleccioText = "Empat";
            } else if (seleccio === 2 || seleccio === equipB) {
                seleccioText = equipB;
            }
        } else if (tipus === "quiniela") {
            // Quiniela → sempre guardem JSON.stringify
            seleccioText = JSON.stringify(seleccio);
        }

        if (!seleccioText) {
            return res
                .status(400)
                .json({ error: "Selecció no vàlida per aquesta aposta." });
        }

        // 💰 Restar diners al jugador
        user.walletBalance -= quantitat;

        // 📌 Guardar aposta dins usuari
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
            diners: quantitat,
            data: new Date(),
        });
        await user.save();

        // 📌 Guardar participant dins aposta
        aposta.participants = aposta.participants || [];
        aposta.participants.push({
            userId: user._id,
            username: user.username,
            seleccio: seleccioText,
            diners: quantitat, // 🔑 ara sempre hi ha diners
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
        // Només organitzadors
        if (req.user.role !== "organitzador") {
            return res
                .status(403)
                .json({ error: "Accés denegat. No ets organitzador." });
        }

        const user = await User.findById(req.user.id).select("apostesCreades");
        if (!user) return res.status(404).json({ error: "Usuari no trobat." });

        // 🔎 Busquem totes les apostes creades, independentment del tipus
        const [porres, quinieles, partits] = await Promise.all([
            Porra.find({ _id: { $in: user.apostesCreades } }).select(
                "titol opcions participants"
            ),
            Quiniela.find({ _id: { $in: user.apostesCreades } }).select(
                "titol partits participants"
            ),
            Partit.find({ _id: { $in: user.apostesCreades } }).select(
                "equipA equipB opcions participants"
            ),
        ]);

        const resultat = [];

        // Porres
        porres.forEach((p) => {
            resultat.push({
                id: p._id,
                tipus: "porra",
                titol: p.titol,
                opcions: p.opcions,
                participants: p.participants,
                totalDiners: p.participants.reduce(
                    (sum, x) => sum + (x.diners || 0),
                    0
                ),
            });
        });

        // Quinieles
        quinieles.forEach((q) => {
            resultat.push({
                id: q._id,
                tipus: "quiniela",
                titol: q.titol,
                partits: q.partits, // cada partit amb equipA i equipB
                participants: q.participants,
                totalDiners: q.participants.reduce(
                    (sum, x) => sum + (x.diners || 0),
                    0
                ),
            });
        });

        // Partits
        partits.forEach((m) => {
            resultat.push({
                id: m._id,
                titol: m.titol,
                tipus: "partit",
                equipA: m.equipA,
                equipB: m.equipB,
                opcions: m.opcions,
                participants: m.participants,
                totalDiners: m.participants.reduce(
                    (sum, x) => sum + (x.diners || 0),
                    0
                ),
            });
        });

        res.json({ apostesCreades: resultat });
    } catch (err) {
        console.error("❌ Error a /gestiona:", err);
        res.status(500).json({ error: "Error intern del servidor" });
    }
});

// ───────────────────────────────────────────────────────────
// RUTA PER AFEGIR/ACTUALITZAR RESULTAT D'UN PARTIT
// ───────────────────────────────────────────────────────────
app.post("/partits/:partitId/resultat", authMiddleware, async (req, res) => {
    try {
        // 1. Validació de Rol (Només organitzadors)
        if (req.user.role !== "organitzador") {
            return res
                .status(403)
                .json({
                    error: "Accés denegat. Només els organitzadors poden posar resultats.",
                });
        }

        const { partitId } = req.params;
        // Dades rebudes des del Popup
        const {
            equip1Resultat,
            equip2Resultat,
            guanyadorPartit,
            nextMatchDate,
            nextMatchApostable,
        } = req.body;
        const organitzadorId = req.user.id;

        // 2. Validació d'Entrades
        if (
            typeof equip1Resultat !== "number" ||
            typeof equip2Resultat !== "number" ||
            equip1Resultat < 0 ||
            equip2Resultat < 0
        ) {
            return res
                .status(400)
                .json({ error: "Els resultats han de ser números positius." });
        }

        // 3. Trobar la Competició i el Partit (i validar permisos)
        // Busquem la competició que pertany a l'usuari I que conté el partit
        const competicio = await Competició.findOne({
            organitzadorId: organitzadorId,
            "partits._id": partitId,
        });

        if (!competicio) {
            return res
                .status(404)
                .json({
                    error: "Partit no trobat o no tens permisos sobre aquesta competició.",
                });
        }

        // Extreiem el subdocument del partit
        const partit = competicio.partits.id(partitId);
        if (!partit) {
            return res
                .status(404)
                .json({
                    error: "Error intern: No s'ha pogut localitzar el partit.",
                });
        }

        // 4. Validació de Data (El partit ha d'haver començat)
        if (!partit.data) {
            return res
                .status(400)
                .json({
                    error: "El partit no té data assignada. Assigna una data abans de posar el resultat.",
                });
        }
        if (new Date(partit.data) > new Date()) {
            return res
                .status(400)
                .json({
                    error: "No es pot posar un resultat a un partit que encara no ha començat.",
                });
        }

        // 5. Validació de Lògica de Competició (Empats i Penals)
        const isEmpat = equip1Resultat === equip2Resultat;

        if (
            competicio.tipus === "classificatori" &&
            isEmpat &&
            !guanyadorPartit
        ) {
            // ERROR: És un classificatori, hi ha empat, i no s'ha enviat guanyador de penals.
            return res
                .status(400)
                .json({
                    error: "Els partits de classificatori no poden empatar. S'ha d'indicar un guanyador.",
                });
        }

        if (
            !isEmpat &&
            guanyadorPartit !== (partit.equip1 || partit.team1) &&
            guanyadorPartit !== (partit.equip2 || partit.team2)
        ) {
            // ERROR: El resultat no és empat, però el 'guanyadorPartit' enviat no coincideix amb el guanyador real
            return res
                .status(400)
                .json({
                    error: "El guanyador no coincideix amb el resultat (no empat).",
                });
        }

        // 6. Actualització a la Base de Dades
        // Mongoose pot gestionar l'actualització de subdocuments directament
        partit.resultatEquip1 = equip1Resultat;
        partit.resultatEquip2 = equip2Resultat;
        partit.guanyadorPartit = guanyadorPartit; // Guardem el guanyador (equip o null)
        partit.estatPartit = "finalitzat";

        // 7. Lògica de Torneig (Avançar Ronda)
        if (competicio.tipus === "classificatori" && guanyadorPartit) {
            const currentRound = partit.round;
            const currentPos = partit.position;
            const nextRound = currentRound + 1;
            const nextPos = Math.floor(currentPos / 2);
            const isTeam1InNextMatch = currentPos % 2 === 0; // Parell -> equip1, Imparell -> equip2

            // Buscar el partit de la següent ronda
            let nextMatch = competicio.partits.find(
                (p) => p.round === nextRound && p.position === nextPos
            );

            if (!nextMatch) {
                // Si no existeix, el creem
                nextMatch = {
                    round: nextRound,
                    position: nextPos,
                    equip1: isTeam1InNextMatch ? guanyadorPartit : null,
                    equip2: !isTeam1InNextMatch ? guanyadorPartit : null,
                    estatPartit: "pendent",
                    // ✅ APLICAR DATA I APOSTABLE
                    data: nextMatchDate ? new Date(nextMatchDate) : null,
                    apostable: nextMatchApostable || false,
                };
                competicio.partits.push(nextMatch);
            } else {
                // Si existeix, l'actualitzem
                if (isTeam1InNextMatch) {
                    nextMatch.equip1 = guanyadorPartit;
                } else {
                    nextMatch.equip2 = guanyadorPartit;
                }
                // ✅ ACTUALITZAR DATA I APOSTABLE (Si s'han passat)
                if (nextMatchDate) nextMatch.data = new Date(nextMatchDate);
                if (nextMatchApostable !== undefined)
                    nextMatch.apostable = nextMatchApostable;
            }
        }

        await competicio.save(); // Guardem el document 'Competició' pare

        res.status(200).json({ message: "Resultat guardat correctament." });
    } catch (err) {
        console.error(
            `❌ Error a POST /partits/${req.params.partitId}/resultat:`,
            err
        );
        res.status(500).json({ error: "Error intern del servidor." });
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
// RUTES PER A LA GESTIO DE COMPETICIONS
// ───────────────────────────────────────────────────────────

app.get("/competicions", async (req, res) => {
    try {
        const competicions = await Competició.find();
        res.json(competicions);
    } catch (err) {
        console.error("❌ Error a GET /competicions:", err);
        res.status(500).json({ error: "Error intern del servidor." });
    }
});

app.post("/competicions", authMiddleware, async (req, res) => {
    try {
        if (req.user.role !== "organitzador")
            return res.status(403).json({ error: "Acces denegat." });
        const { nomCompeticio, tipus, partits } = req.body;
        if (!nomCompeticio || !tipus || !Array.isArray(partits))
            return res.status(400).json({ error: "Falten camps obligatoris." });

        // 🗑️ ELIMINAR COMPETICIONS ANTERIORS (SOLITUD USUARI)
        // Busquem les competicions antigues d'aquest usuari
        const competicionsAntigues = await Competició.find({
            organitzadorId: req.user.id,
        });

        if (competicionsAntigues.length > 0) {
            // Esborrem les competicions de la col·lecció 'Competició'
            await Competició.deleteMany({ organitzadorId: req.user.id });
        }

        // 🗑️ ELIMINAR OTRAS APOSTES CREADES PER L'USUARI (PARTITS, PORRES, QUINIELES)
        // Per garantir que no quedin partits solts antics
        await Partit.deleteMany({ creador: req.user.username });
        await Porra.deleteMany({ creador: req.user.username });
        await Quiniela.deleteMany({ creador: req.user.username });

        // 🗑️ NETEJAR REFERÈNCIES A L'USUARI
        // Buidem 'competicionsCreades' I 'apostesCreades'
        await User.findByIdAndUpdate(req.user.id, {
            $set: {
                competicionsCreades: [],
                apostesCreades: [],
            },
        });

        const novaCompeticio = new Competició({
            nomCompeticio,
            tipus,
            partits,
            organitzadorId: req.user.id,
        });
        await novaCompeticio.save();

        await User.findByIdAndUpdate(req.user.id, {
            $push: { competicionsCreades: novaCompeticio._id },
        });
        res.status(201).json({
            message: "Competició creada correctament!",
            id: novaCompeticio._id,
        });
    } catch (err) {
        console.error("❌ Error a POST /competicions:", err);
        res.status(500).json({ error: "Error intern del servidor." });
    }
});

app.get("/competicions/meva", authMiddleware, async (req, res) => {
    try {
        if (req.user.role !== "organitzador")
            return res.status(403).json({ error: "Acces denegat." });
        const user = await User.findById(req.user.id).populate(
            "competicionsCreades"
        );
        if (!user) return res.status(404).json({ error: "Usuari no trobat." });
        const competicio =
            user.competicionsCreades && user.competicionsCreades.length > 0
                ? user.competicionsCreades[0]
                : null;
        res.json(competicio);
    } catch (err) {
        console.error("❌ Error a GET /competicions/meva:", err);
        res.status(500).json({ error: "Error intern del servidor." });
    }
});

app.put("/competicions/:id", authMiddleware, async (req, res) => {
    try {
        if (req.user.role !== "organitzador")
            return res.status(403).json({ error: "Acces denegat." });
        const { nomCompeticio, tipus, partits } = req.body;

        const competicioActualitzada = await Competició.findOneAndUpdate(
            { _id: req.params.id, organitzadorId: req.user.id },
            { nomCompeticio, tipus, partits },
            { new: true }
        );

        if (!competicioActualitzada) {
            return res.status(404).json({
                error: "Competició no trobada o no tens permisos per editar-la.",
            });
        }

        res.json({ message: "Competició actualitzada correctament!" });
    } catch (err) {
        console.error(`❌ Error a PUT /competicions/${req.params.id}:`, err);
        res.status(500).json({ error: "Error intern del servidor." });
    }
});

// ───────────────────────────────────────────────────────────
// INICI SERVIDOR
// ───────────────────────────────────────────────────────────
app.listen(3000, () => console.log("🌐 Servidor escoltant al port 3000"));
