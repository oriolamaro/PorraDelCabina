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
    colorA: { type: String, default: "#1a1a1a" },
    colorB: { type: String, default: "#1a1a1a" },
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
    // apostable eliminat
    apostaId: { type: mongoose.Schema.Types.ObjectId, ref: 'Partit', default: null },
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
    equips: [{
        nom: { type: String, required: true },
        color: { type: String, default: "#1FFF94" }
    }], // Llista d'equips participants amb nom i color
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
        console.log("🔵 ═══════════════════════════════════════════════════");
        console.log("🔵 [RESULTAT] Nova petició rebuda");
        console.log("🔵 ═══════════════════════════════════════════════════");
        console.log("  📋 partitId:", req.params.partitId);
        console.log("  📋 Body:", JSON.stringify(req.body, null, 2));
        console.log("  👤 User:", req.user.username, "(", req.user.role, ")");
        
        // 1. Validació de Rol (Només organitzadors)
        if (req.user.role !== "organitzador") {
            console.log("❌ [RESULTAT] Accés denegat: no és organitzador");
            return res
                .status(403)
                .json({
                    error: "Accés denegat. Només els organitzadors poden posar resultats.",
                });
        }
        console.log("  ✅ Rol validat: organitzador");

        const { partitId } = req.params;
        // Dades rebudes des del Popup
        const {
            equip1Resultat,
            equip2Resultat,
            guanyadorPartit,
        } = req.body;
        const organitzadorId = req.user.id;

        // 2. Validació d'Entrades
        console.log("  🔍 Validant entrades...");
        console.log("    - equip1Resultat:", equip1Resultat, "(type:", typeof equip1Resultat, ")");
        console.log("    - equip2Resultat:", equip2Resultat, "(type:", typeof equip2Resultat, ")");
        console.log("    - guanyadorPartit:", guanyadorPartit);
        
        if (
            typeof equip1Resultat !== "number" ||
            typeof equip2Resultat !== "number" ||
            equip1Resultat < 0 ||
            equip2Resultat < 0
        ) {
            console.log("❌ [RESULTAT] Resultats invàlids");
            return res
                .status(400)
                .json({ error: "Els resultats han de ser números positius." });
        }
        console.log("  ✅ Entrades vàlides");

        // 3. Trobar la Competició i el Partit (i validar permisos)
        console.log("  🔍 Buscant competició...");
        console.log("    - organitzadorId:", organitzadorId);
        console.log("    - partitId:", partitId);
        
        // Busquem la competició que pertany a l'usuari I que conté el partit
        const competicio = await Competició.findOne({
            organitzadorId: organitzadorId,
            "partits._id": partitId,
        });

        if (!competicio) {
            console.log("❌ [RESULTAT] Competició no trobada");
            return res
                .status(404)
                .json({
                    error: "Partit no trobat o no tens permisos sobre aquesta competició.",
                });
        }

        console.log("  ✅ Competició trobada:", competicio._id);
        console.log("    - Nom:", competicio.nomCompeticio);
        console.log("    - Tipus:", competicio.tipus);
        console.log("    - Total partits:", competicio.partits.length);

        // Extreiem el subdocument del partit
        const partit = competicio.partits.id(partitId);
        if (!partit) {
            console.log("❌ [RESULTAT] Partit no trobat dins la competició");
            return res
                .status(404)
                .json({
                    error: "Error intern: No s'ha pogut localitzar el partit.",
                });
        }

        console.log("  ✅ Partit trobat:");
        console.log("    - Equips:", partit.equip1 || partit.team1, "vs", partit.equip2 || partit.team2);
        console.log("    - Round:", partit.round, "| Position:", partit.position);
        console.log("    - Estat:", partit.estatPartit);
        console.log("    - Data:", partit.data);

        // 4. Validació de Data (El partit ha d'haver començat)
        console.log("  🔍 Validant data...");
        if (!partit.data) {
            console.log("❌ [RESULTAT] Partit sense data assignada");
            return res
                .status(400)
                .json({
                    error: "El partit no té data assignada. Assigna una data abans de posar el resultat.",
                });
        }
        if (new Date(partit.data) > new Date()) {
            console.log("❌ [RESULTAT] El partit encara no ha començat");
            console.log("    - Data partit:", partit.data);
            console.log("    - Data actual:", new Date());
            return res
                .status(400)
                .json({
                    error: "No es pot posar un resultat a un partit que encara no ha començat.",
                });
        }
        console.log("  ✅ Data vàlida");

        // 5. Validació de Lògica de Competició (Empats i Penals)
        const isEmpat = equip1Resultat === equip2Resultat;
        console.log("  🔍 Validant lògica de l'empat...");
        console.log("    - És empat?", isEmpat);
        console.log("    - Tipus competició:", competicio.tipus);
        console.log("    - Guanyador rebut:", guanyadorPartit);

        if (
            competicio.tipus === "classificatori" &&
            isEmpat &&
            !guanyadorPartit
        ) {
            console.log("❌ [RESULTAT] Empat sense guanyador en classificatori");
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
            console.log("❌ [RESULTAT] Guanyador no coincideix amb el resultat");
            console.log("    - Resultat:", equip1Resultat, "-", equip2Resultat);
            console.log("    - Guanyador rebut:", guanyadorPartit);
            console.log("    - Equip1:", partit.equip1 || partit.team1);
            console.log("    - Equip2:", partit.equip2 || partit.team2);
            // ERROR: El resultat no és empat, però el 'guanyadorPartit' enviat no coincideix amb el guanyador real
            return res
                .status(400)
                .json({
                    error: "El guanyador no coincideix amb el resultat (no empat).",
                });
        }
        console.log("  ✅ Lògica validada correctament");

        // 6. Actualització a la Base de Dades
        console.log("  💾 Actualitzant partit...");
        // Mongoose pot gestionar l'actualització de subdocuments directament
        partit.resultatEquip1 = equip1Resultat;
        partit.resultatEquip2 = equip2Resultat;
        partit.guanyadorPartit = guanyadorPartit; // Guardem el guanyador (equip o null)
        partit.estatPartit = "finalitzat";
        console.log("  ✅ Dades actualitzades localment");

        // 7. Lògica de Torneig (Avançar Ronda)
        if (competicio.tipus === "classificatori" && guanyadorPartit) {
            
            // 🛑 COMPROVAR SI ÉS LA FINAL
            // No podem basar-nos en partits existents perquè potser encara no s'han creat les rondes següents.
            // Ho calculem segons el numero d'equips: FinalRound = ceil(log2(numEquips)) - 1
            const numEquips = competicio.equips ? competicio.equips.length : 0;
            const totalRounds = Math.ceil(Math.log2(numEquips));
            const finalRoundIndex = totalRounds - 1;

            console.log(`    - Ronda actual: ${partit.round}`);
            console.log(`    - Equips totals: ${numEquips} => Rodes totals: ${totalRounds}`);
            console.log(`    - Ronda Final calculada: ${finalRoundIndex}`);
            
            if (partit.round >= finalRoundIndex) {
                console.log("  🏆 AQUEST PARTIT ERA LA FINAL! TENIM GUANYADOR DEL TORNEIG.");
                console.log("    - Guanyador:", guanyadorPartit);

                // Guardem el resultat de la final
                await competicio.save();

                res.json({
                    message: "Resultat guardat!",
                    torneigFinalitzat: true,
                    guanyadorTorneig: guanyadorPartit
                });
                return;
            }

            console.log("  🔄 Avançant ronda...");
            const nextRound = partit.round + 1;
            const nextPosition = Math.floor(partit.position / 2);
            const isFirstTeam = partit.position % 2 === 0;

            console.log(`    - Buscant match: Round ${nextRound}, Pos ${nextPosition}`);

            let nextMatch = competicio.partits.find(
                p => p.round === nextRound && p.position === nextPosition
            );

            if (nextMatch) {
                console.log("    - Match trobat! Actualitzant equip...");
                if (isFirstTeam) {
                    nextMatch.equip1 = guanyadorPartit;
                    console.log(`      -> Equip 1 set to ${guanyadorPartit}`);
                } else {
                    nextMatch.equip2 = guanyadorPartit;
                    console.log(`      -> Equip 2 set to ${guanyadorPartit}`);
                }
                nextMatch.estatPartit = "pendent"; 
            } else {
                console.log("    - Match NO trobat. Creant-lo automàticament...");
                const nouPartitRonda = {
                    equip1: isFirstTeam ? guanyadorPartit : "Pendent",
                    equip2: !isFirstTeam ? guanyadorPartit : "Pendent",
                    round: nextRound,
                    position: nextPosition,
                    grup: null,
                    data: null, 
                    apostable: false,
                    estatPartit: "pendent",
                    resultatEquip1: null,
                    resultatEquip2: null,
                    guanyadorPartit: null
                };
                competicio.partits.push(nouPartitRonda);
                console.log("    ✅ Pushed new match. Length:", competicio.partits.length);
            }
        }

        console.log("  💾 Guardant competició a MongoDB...");
        competicio.markModified('partits');
        const savedDoc = await competicio.save(); 
        console.log("  ✅ Competició guardada! Partits count:", savedDoc.partits.length);

        console.log("🔵 ═══════════════════════════════════════════════════");
        console.log("✅ [RESULTAT] Procés completat amb èxit!");
        console.log("🔵 ═══════════════════════════════════════════════════");
        
        res.status(200).json({ message: "Resultat guardat correctament." });
    } catch (err) {
        console.log("🔵 ═══════════════════════════════════════════════════");
        console.error("❌ [RESULTAT] ERROR EN EL SERVIDOR");
        console.log("🔵 ═══════════════════════════════════════════════════");
        console.error("  💥 Error:", err.message);
        console.error("  📚 Stack trace:");
        console.error(err.stack);
        console.log("🔵 ═══════════════════════════════════════════════════");
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
        console.log("📖 [GET COMPETICIONS] Obtenint llista de competicions...");
        const competicions = await Competició.find();
        console.log("  ✅ Competicions trobades:", competicions.length);
        res.json(competicions);
    } catch (err) {
        console.error("❌ [GET COMPETICIONS] Error:", err.message);
        console.error(err.stack);
        res.status(500).json({ error: "Error intern del servidor." });
    }
});

// Helper per normalitzar strings (treure accents, espais, minúscules)
function normalitzarString(str) {
    if (!str) return "";
    return str.toString().toLowerCase()
        .normalize("NFD").replace(/[\u0300-\u036f]/g, "") // Treure accents
        .trim();
}

// ───────────────────────────────────────────────────────────
// HELPER: CREAR APOSTA PER A UN PARTIT
// ───────────────────────────────────────────────────────────
async function crearApostaPerPartit(partit, nomCompeticio, creadorUsername, creadorUserId) {
    try {
        const rawEquip1 = partit.equip1 || partit.team1;
        const rawEquip2 = partit.equip2 || partit.team2;
        
        // 🛑 VALIDACIÓ: Si falta algun dels dos equips, NO creem l'aposta encara.
        if (!rawEquip1 || !rawEquip2 || rawEquip1.toString().trim() === "" || rawEquip2.toString().trim() === "") {
             console.log(`    ⚠️ Aposta no creada: Equips incomplets (${rawEquip1} vs ${rawEquip2})`);
             return null;
        }

        const equip1 = rawEquip1;
        const equip2 = rawEquip2;
        const color1 = partit.colorEquip1 || partit.colorTeam1 || "#1a1a1a";
        const color2 = partit.colorEquip2 || partit.colorTeam2 || "#1a1a1a";
        
        // Generate unique title
        let titol = `${nomCompeticio} - ${equip1} vs ${equip2}`;
        if (partit.grup) {
            titol = `${nomCompeticio} - ${partit.grup} - ${equip1} vs ${equip2}`;
        } else if (partit.round !== undefined) {
            const roundNames = ["Final", "Semifinal", "Quarts", "Vuitens", "Setzens"];
            const roundName = roundNames[partit.round] || `Round ${partit.round}`;
            titol = `${roundName}: ${equip1} vs ${equip2}`;
        }
        
        // 🔒 SAFETY NET: Check if bet with same title already exists (Idempotency)
        // Això evita duplicats si tota la resta de lògica falla
        const apostaExistent = await Partit.findOne({ 
            titol: titol, 
            creador: creadorUsername,
            // Opcional: comprovar equips també per seguretat extra
            // equipA: equip1,
            // equipB: equip2
        });

        if (apostaExistent) {
            console.log(`    ⚠️ Aposta recuperada per títol (Idempotència): ${titol} (ID: ${apostaExistent._id})`);
            return apostaExistent._id;
        }

        const novaAposta = new Partit({
            titol,
            equipA: equip1,
            equipB: equip2,
            colorA: color1,
            colorB: color2,
            empatPermes: true,
            opcions: [equip1, "Empat", equip2],
            creador: creadorUsername,
            participants: [],
            apostat: 0,
        });
        
        await novaAposta.save();
        console.log(`    ✅ Aposta creada: ${titol} (ID: ${novaAposta._id})`);
        
        // Afegir l'aposta a la llista d'apostes creades de l'organitzador
        if (creadorUserId) {
            await User.findByIdAndUpdate(creadorUserId, {
                $push: { apostesCreades: novaAposta._id },
            });
            console.log(`    ✅ Aposta afegida a apostesCreades de l'organitzador`);
        }
        return novaAposta._id;
    } catch (err) {
        console.error(`    ❌ Error creant aposta per partit:`, err.message);
        return null;
    }
}

// ───────────────────────────────────────────────────────────
// HELPER: SINCRONITZAR APOSTA (Actualitzar noms si canvien)
// ───────────────────────────────────────────────────────────
async function syncPartitAposta(partit, nomCompeticio) {
    if (!partit.apostaId) return;

    try {
        const aposta = await Partit.findById(partit.apostaId);
        if (!aposta) return;

        const equip1 = partit.equip1 || partit.team1 || "Equip 1";
        const equip2 = partit.equip2 || partit.team2 || "Equip 2";

        // Si els equips de la competició són placeholders ("Equip X"), 
        // i l'aposta ja té noms reals, NO sobreescrivim.
        // Però si la competició té noms reals i l'aposta té "Equip X" o noms vells, actualitzem.
        const isPlaceholder = (name) => name.toLowerCase().includes("equip") || name.toLowerCase().includes("team");
        
        // Si la competició té noms vàlids (no placeholders), intentem sincronitzar
        if (!isPlaceholder(equip1) && !isPlaceholder(equip2)) {
            
            // Si l'aposta té noms diferents, actualitzem
            if (aposta.equipA !== equip1 || aposta.equipB !== equip2) {
                console.log(`    🔄 Sincronitzant aposta: ${aposta.equipA} vs ${aposta.equipB} -> ${equip1} vs ${equip2}`);
                
                // Regenerar títol
                let titol = `${nomCompeticio} - ${equip1} vs ${equip2}`;
                if (partit.grup) {
                    titol = `${nomCompeticio} - ${partit.grup} - ${equip1} vs ${equip2}`;
                } else if (partit.round !== undefined) {
                    const roundNames = ["Final", "Semifinal", "Quarts", "Vuitens", "Setzens"];
                    const roundName = roundNames[partit.round] || `Round ${partit.round}`;
                    titol = `${roundName}: ${equip1} vs ${equip2}`;
                }

                aposta.titol = titol;
                aposta.equipA = equip1;
                aposta.equipB = equip2;
                if (partit.colorEquip1) aposta.colorA = partit.colorEquip1;
                if (partit.colorEquip2) aposta.colorB = partit.colorEquip2;
                
                // Actualitzar opcions mantenint "Empat"
                // NOTA: Això podria desincronitzar apostes d'usuaris si havien apostat pel nom antic.
                // Assumim que si els noms canvien, ningú hauria d'haver apostat seriosament encara.
                aposta.opcions = [equip1, "Empat", equip2];
                
                await aposta.save();
                console.log(`       ✅ Aposta actualitzada correctament`);
            }
        }
    } catch (err) {
        console.error(`    ⚠️ Error sincronitzant aposta:`, err.message);
    }
}


app.post("/competicions", authMiddleware, async (req, res) => {
    try {
        console.log("🟢 ═══════════════════════════════════════════════════");
        console.log("🟢 [COMPETICIÓ] Nova petició de creació rebuda");
        console.log("🟢 ═══════════════════════════════════════════════════");
        console.log("  👤 User:", req.user.username, "(", req.user.id, ")");
        console.log("  📋 Body keys:", Object.keys(req.body));
        
        if (req.user.role !== "organitzador") {
            console.log("❌ [COMPETICIÓ] Accés denegat: no és organitzador");
            return res.status(403).json({ error: "Acces denegat." });
        }
        console.log("  ✅ Rol validat");
        
        const { nomCompeticio, tipus, partits, equips, confirmarBorrado } = req.body;
        console.log("  📋 Dades rebudes:");
        console.log("    - nomCompeticio:", nomCompeticio);
        console.log("    - tipus:", tipus);
        console.log("    - partits:", Array.isArray(partits) ? `Array(${partits.length})` : typeof partits);
        console.log("    - equips:", Array.isArray(equips) ? `Array(${equips.length})` : typeof equips);
        console.log("    - confirmarBorrado:", confirmarBorrado);
        
        if (!nomCompeticio || !tipus || !Array.isArray(partits)) {
            console.log("❌ [COMPETICIÓ] Falten camps obligatoris");
            return res.status(400).json({ error: "Falten camps obligatoris." });
        }
        console.log("  ✅ Camps obligatoris presents");

        // 🛡️ VERIFICACIÓ D'APOSTES EXISTENTS (EXCEPTE PORRA)
        // 🛡️ VERIFICACIÓ D'APOSTES EXISTENTS (EXCEPTE PORRA)
        // [MODIFICAT]: Eliminada la validació per permetre editar sense borrar apostes
        /*
        console.log("  🔍 Verificant apostes existents...");
        if (!confirmarBorrado) {
            const betsExistents = await Quiniela.countDocuments({ creador: req.user.username });
            console.log("    - Quinieles trobades:", betsExistents);
            if (betsExistents > 0) {
                console.log("❌ [COMPETICIÓ] Hi ha apostes existents");
                return res.status(409).json({ 
                    error: "EXISTING_BETS", 
                    message: "Tens apostes (Quinieles) actives. Has de validar-les o anular-les abans de crear una nova competició." 
                });
            }
        }
        console.log("  ✅ No hi ha apostes que bloquegin");
        */

        // 🗑️ ELIMINAR COMPETICIONS ANTERIORS
        console.log("  🗑️ Buscant competicions anteriors...");
        const competicionsAntigues = await Competició.find({
            organitzadorId: req.user.id,
        });
        console.log("    - Competicions anteriors trobades:", competicionsAntigues.length);

        if (competicionsAntigues.length > 0) {
            console.log("    - Esborrant competicions anteriors...");
            await Competició.deleteMany({ organitzadorId: req.user.id });
            console.log("    ✅ Competicions anteriors esborrades");
        }

        // 🗑️ ELIMINAR QUINIELES SI CONFIRMAT
        // 🗑️ ELIMINAR QUINIELES SI CONFIRMAT
        // [MODIFICAT]: Eliminada la lògica d'esborrat per preservar les apostes
        /*
        if (confirmarBorrado) {
            console.log("  🗑️ Esborrant quinieles...");
            const result = await Quiniela.deleteMany({ creador: req.user.username });
            console.log("    - Quinieles esborrades:", result.deletedCount);
        }
        */

        // 🧹 NETEJAR REFERÈNCIES A L'USUARI
        console.log("  🧹 Netejant referències d'usuari...");
        await User.findByIdAndUpdate(req.user.id, {
            $set: {
                competicionsCreades: [],
                // apostesCreades: [], // [MODIFICAT]: No esborrem les referències a les apostes
            },
        });
        console.log("  ✅ Referències netejades");

        // 🔄 PROCESSAR PARTITS - Filtrar només partits vàlids
        console.log("  🔄 Processant partits...");
        console.log("    - Partits rebuts:", partits.length);
        
        // Log each match received
        console.log("  📋 Detalls dels partits rebuts:");
        partits.forEach((p, idx) => {
            console.log(`    [${idx + 1}] ${p.equip1 || '???'} vs ${p.equip2 || '???'}`);
            console.log(`        - resultatEquip1: ${p.resultatEquip1}`);
            console.log(`        - resultatEquip2: ${p.resultatEquip2}`);
            console.log(`        - guanyadorPartit: ${p.guanyadorPartit || 'NULL'}`);
            console.log(`        - estatPartit: ${p.estatPartit || 'NULL'}`);
            console.log(`        - round: ${p.round}, position: ${p.position}`);
        });
        
        // Filtrar i netejar partits: eliminar _id temporal i camps no necessaris
        const partitsNetejats = partits
            .filter(p => {
                // Filtrar partits sense equips o amb equips buits
                const hasTeams = (p.equip1 && p.equip1.trim()) || (p.equip2 && p.equip2.trim());
                return hasTeams;
            })
            .map(p => {
                // Eliminar el _id temporal del frontend (és un timestamp, no un ObjectId vàlid)
                const { id, _id, ...partitNetejat } = p;
                return partitNetejat;
            });
        
        console.log("    - Partits vàlids (després de filtrar):", partitsNetejats.length);
        
        // Log cleaned matches
        console.log("  📋 Partits netejats per guardar:");
        partitsNetejats.forEach((p, idx) => {
            console.log(`    [${idx + 1}] ${p.equip1 || '???'} vs ${p.equip2 || '???'}`);
            console.log(`        - resultatEquip1: ${p.resultatEquip1}`);
            console.log(`        - resultatEquip2: ${p.resultatEquip2}`);
            console.log(`        - guanyadorPartit: ${p.guanyadorPartit || 'NULL'}`);
            console.log(`        - estatPartit: ${p.estatPartit || 'NULL'}`);
        });

        // CREAR NOVA COMPETICIÓ amb partits com a subdocuments
        console.log("  💾 Creant nova competició...");
        const novaCompeticio = new Competició({
            nomCompeticio,
            tipus,
            equips: Array.isArray(equips) ? equips : [], // ✅ Guardem equips participants
            partits: partitsNetejats, // ✅ Els partits són subdocuments, no ObjectIds
            organitzadorId: req.user.id,
        });
        await novaCompeticio.save();
        console.log("  ✅ Competició creada amb ID:", novaCompeticio._id);
        console.log("    - Partits guardats:", novaCompeticio.partits.length);
        console.log("    - Equips guardats:", novaCompeticio.equips?.length || 0);
        
        // 🎲 CREAR APOSTES AUTOMÀTICAMENT PER A CADA PARTIT
        console.log("  🎲 Creant apostes per a cada partit...");
        for (let i = 0; i < novaCompeticio.partits.length; i++) {
            const partit = novaCompeticio.partits[i];
            const apostaId = await crearApostaPerPartit(partit, nomCompeticio, req.user.username, req.user.id);
            if (apostaId) {
                novaCompeticio.partits[i].apostaId = apostaId;
            }
        }
        
        // Guardar competició amb les referències a les apostes
        await novaCompeticio.save();
        console.log("  ✅ Apostes creades i referències actualitzades");

        
        // Verify what was actually saved
        console.log("  🔍 Verificant dades guardades a MongoDB:");
        novaCompeticio.partits.forEach((p, idx) => {
            console.log(`    [${idx + 1}] ${p.equip1 || '???'} vs ${p.equip2 || '???'}`);
            console.log(`        - resultatEquip1: ${p.resultatEquip1} (type: ${typeof p.resultatEquip1})`);
            console.log(`        - resultatEquip2: ${p.resultatEquip2} (type: ${typeof p.resultatEquip2})`);
            console.log(`        - guanyadorPartit: ${p.guanyadorPartit || 'NULL'}`);
            console.log(`        - estatPartit: ${p.estatPartit || 'NULL'}`);
        });

        console.log("  🔗 Actualitzant referència d'usuari...");
        await User.findByIdAndUpdate(req.user.id, {
            $push: { competicionsCreades: novaCompeticio._id },
        });
        console.log("  ✅ Referència actualitzada");

        console.log("🟢 ═══════════════════════════════════════════════════");
        console.log("✅ [COMPETICIÓ] Competició creada correctament!");
        console.log("🟢 ═══════════════════════════════════════════════════");
        
        res.status(201).json({
            message: "Competició creada correctament!",
            id: novaCompeticio._id,
        });
    } catch (err) {
        console.log("🟢 ═══════════════════════════════════════════════════");
        console.error("❌ [COMPETICIÓ] ERROR EN CREAR COMPETICIÓ");
        console.log("🟢 ═══════════════════════════════════════════════════");
        console.error("  💥 Error:", err.message);
        console.error("  📚 Stack trace:");
        console.error(err.stack);
        console.log("🟢 ═══════════════════════════════════════════════════");
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
        console.log("🔵 ═══════════════════════════════════════════════════");
        console.log("🔵 [UPDATE COMPETICIÓ] Actualitzant competició");
        console.log("🔵 ═══════════════════════════════════════════════════");
        console.log("  👤 User:", req.user.username, "(", req.user.id, ")");
        console.log("  🆔 Competition ID:", req.params.id);
        
        if (req.user.role !== "organitzador") {
            console.log("❌ [UPDATE] Accés denegat: no és organitzador");
            return res.status(403).json({ error: "Acces denegat." });
        }
        
        const { nomCompeticio, tipus, partits } = req.body;
        console.log("  📋 Dades rebudes:");
        console.log("    - nomCompeticio:", nomCompeticio);
        console.log("    - tipus:", tipus);
        console.log("    - partits:", Array.isArray(partits) ? `Array(${partits.length})` : typeof partits);
        
        // Log match results summary
        if (Array.isArray(partits)) {
            const partitsAmbResultats = partits.filter(p => 
                p.resultatEquip1 !== null && p.resultatEquip1 !== undefined &&
                p.resultatEquip2 !== null && p.resultatEquip2 !== undefined
            );
            console.log("    - Partits amb resultats:", partitsAmbResultats.length);
            
            if (partitsAmbResultats.length > 0) {
                console.log("  📊 Resultats detectats:");
                partitsAmbResultats.forEach((p, idx) => {
                    console.log(`    [${idx + 1}] ${p.equip1 || '???'} ${p.resultatEquip1}-${p.resultatEquip2} ${p.equip2 || '???'}`);
                    console.log(`        → Guanyador: ${p.guanyadorPartit || 'NULL'} | Estat: ${p.estatPartit || 'pendent'}`);
                });
            }
        }

        // 🎲 GESTIONAR APOSTES: preservar existents i crear noves
        console.log("  🎲 Gestionant apostes per als partits...");
        
        // Carregar competició actual per obtenir apostes existents
        const competicioActual = await Competició.findById(req.params.id);
        const apostesExistents = new Map(); // Mapa per _id -> apostaId
        const apostesPerContingut = new Map(); // Mapa per contingut -> apostaId
        
        if (competicioActual && competicioActual.partits) {
            competicioActual.partits.forEach(p => {
                if (p._id && p.apostaId) {
                    // Indexar per _id
                    apostesExistents.set(p._id.toString(), p.apostaId);
                    
                    // Indexar per contingut (equips) - Usem array per gestionar duplicats (anada/tornada)
                    const equip1 = normalitzarString(p.equip1 || p.team1);
                    const equip2 = normalitzarString(p.equip2 || p.team2);
                    
                    const clauContingut = `${equip1}|${equip2}`;
                    
                    if (!apostesPerContingut.has(clauContingut)) {
                        apostesPerContingut.set(clauContingut, []);
                    }
                    
                    apostesPerContingut.get(clauContingut).push({
                        apostaId: p.apostaId,
                        data: p.data ? new Date(p.data).toISOString() : null,
                        estat: p.estatPartit
                    });
                }
            });
            console.log("    - Apostes per _id:", apostesExistents.size);
            console.log("    - Apostes per contingut:", apostesPerContingut.size);
        }
        

        // Processar cada partit: preservar apostaId o crear nova aposta
        for (let i = 0; i < partits.length; i++) {
            const partit = partits[i];
            
            // PRIORITAT 1: Si el partit ja té apostaId (del frontend o base de dades), preservar-la
            if (partit.apostaId) {
                console.log(`    ✓ Aposta preservada (apostaId existent): ${partit.equip1 || partit.team1} vs ${partit.equip2 || partit.team2} (ID: ${partit.apostaId})`);
                // Mantenir l'apostaId que ja té
            }
            // PRIORITAT 2: Si el partit té _id i existeix a la base de dades amb aposta, recuperar-la
            else if (partit._id && apostesExistents.has(partit._id.toString())) {
                partit.apostaId = apostesExistents.get(partit._id.toString());
                console.log(`    ✓ Aposta recuperada per _id: ${partit.equip1 || partit.team1} vs ${partit.equip2 || partit.team2} (ID: ${partit.apostaId})`);
            } 
            // PRIORITAT 3: Buscar aposta existent pel contingut (equips) - Queue consumption
            else {
                const equip1 = normalitzarString(partit.equip1 || partit.team1);
                const equip2 = normalitzarString(partit.equip2 || partit.team2);
                
                const clauContingut = `${equip1}|${equip2}`;
                
                let foundBet = null;
                
                if (apostesPerContingut.has(clauContingut)) {
                    const candidats = apostesPerContingut.get(clauContingut);
                    
                    if (candidats && candidats.length > 0) {
                        // Estratègia: 
                        // 1. Buscar coincidència de data exacta (si existeix)
                        // 2. Si no, agafar el primer disponible (FIFO)
                        
                        const incomingDate = partit.data ? new Date(partit.data).toISOString() : null;
                        
                        let matchIndex = -1;
                        
                        // Intent 1: Coincidència de data
                        if (incomingDate) {
                            matchIndex = candidats.findIndex(c => c.data === incomingDate);
                        }
                        
                        // Intent 2: Primer disponible
                        if (matchIndex === -1) {
                            matchIndex = 0; // Agafem el primer
                        }
                        
                        // Assignar i consumir (treure de la llista per no reutilitzar)
                        const match = candidats[matchIndex];
                        foundBet = match.apostaId;
                        partit.apostaId = match.apostaId;
                        
                        console.log(`    ✓ Aposta reutilitzada per contingut (${incomingDate === match.data ? 'Data exacta' : 'Primer disp.'}): ${partit.equip1} vs ${partit.equip2} (ID: ${foundBet})`);
                        
                        // Eliminar de la llista de candidats disponibles
                        candidats.splice(matchIndex, 1);
                    }
                }
                
                if (!foundBet) {
                    // PRIORITAT 4: Crear nova aposta només si no existeix cap coincidència disponible
                    const apostaId = await crearApostaPerPartit(partit, nomCompeticio, req.user.username, req.user.id);
                    if (apostaId) {
                        partit.apostaId = apostaId;
                        console.log(`    ✅ Nova aposta creada: ${partit.equip1 || partit.team1} vs ${partit.equip2 || partit.team2} (ID: ${apostaId})`);
                        
                        // NO afegim al mapa de candidats perquè és nou i ja està assignat a aquest partit
                        // Si ve un altre duplicat exactament igual, se li crearà una altra aposta (correcte, són 2 partits nous iguals)
                    }
                }
            }
            
            // 🔄 SYNCHRONIZE BET (Update names if they changed from placeholder to real)
            await syncPartitAposta(partit, nomCompeticio);
        }


        console.log("  💾 Actualitzant a MongoDB...");
        const competicioActualitzada = await Competició.findOneAndUpdate(
            { _id: req.params.id, organitzadorId: req.user.id },
            { nomCompeticio, tipus, partits },
            { new: true }
        );


        if (!competicioActualitzada) {
            console.log("❌ [UPDATE] Competició no trobada");
            return res.status(404).json({
                error: "Competició no trobada o no tens permisos per editar-la.",
            });
        }

        console.log("  ✅ Competició actualitzada!");
        console.log("    - Partits guardats:", competicioActualitzada.partits.length);
        
        // Verify results were saved
        const partitsGuardatsAmbResultats = competicioActualitzada.partits.filter(p =>
            p.resultatEquip1 !== null && p.resultatEquip1 !== undefined &&
            p.resultatEquip2 !== null && p.resultatEquip2 !== undefined
        );
        console.log("    - Partits amb resultats guardats:", partitsGuardatsAmbResultats.length);
        
        // 🧹 ORPHAN BET CLEANUP (Neteja d'apostes que ja no es fan servir)
        if (competicioActual && competicioActualitzada) {
             const idsAbans = new Set(competicioActual.partits
                .map(p => p.apostaId ? p.apostaId.toString() : null)
                .filter(id => id));

             const idsAra = new Set(competicioActualitzada.partits
                .map(p => p.apostaId ? p.apostaId.toString() : null)
                .filter(id => id));

             const apostesEliminar = [...idsAbans].filter(id => !idsAra.has(id));

             if (apostesEliminar.length > 0) {
                 console.log(`  🧹 Eliminant ${apostesEliminar.length} apostes orfes (ja no existeixen a la competició):`, apostesEliminar);
                 try {
                     await Partit.deleteMany({ _id: { $in: apostesEliminar } });
                     await User.updateMany(
                         { apostesCreades: { $in: apostesEliminar } },
                         { $pull: { apostesCreades: { $in: apostesEliminar } } }
                     );
                     console.log("     ✅ Apostes orfes eliminades correctament.");
                 } catch (cleanupErr) {
                     console.error("     ⚠️ Error durant la neteja d'apostes orfes:", cleanupErr);
                 }
             }
        }
        
        console.log("🔵 ═══════════════════════════════════════════════════");
        console.log("✅ [UPDATE COMPETICIÓ] Actualització completada!");
        console.log("🔵 ═══════════════════════════════════════════════════");

        res.json({ message: "Competició actualitzada correctament!" });
    } catch (err) {
        console.log("🔵 ═══════════════════════════════════════════════════");
        console.error("❌ [UPDATE COMPETICIÓ] ERROR");
        console.log("🔵 ═══════════════════════════════════════════════════");
        console.error("  💥 Error:", err.message);
        console.error("  📚 Stack trace:");
        console.error(err.stack);
        console.log("🔵 ═══════════════════════════════════════════════════");
        res.status(500).json({ error: "Error intern del servidor." });
    }
});

// ───────────────────────────────────────────────────────────
// INICI SERVIDOR
// ───────────────────────────────────────────────────────────
app.listen(3000, () => console.log("🌐 Servidor escoltant al port 3000"));
