import express from "express";
import cors from "cors";
import bcrypt from "bcrypt";
import pg from "pg";
import multer from "multer";
import path from "path";
import fs from "fs";
import jwt from "jsonwebtoken";
import { fileURLToPath } from "url";
import { dirname } from "path";

const { Pool } = pg;

const app = express();

// Allow common frontend dev ports (Vite/CRA) during development
const allowedOrigins = [
  "http://localhost:8080",
  "http://localhost:8081",
  "http://127.0.0.1:8080",
  "http://127.0.0.1:8081"
];

app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or curl)
    if (!origin) return callback(null, true);
    
    // Check if the origin is in our allowed list
    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      console.log("CORS blocked for origin:", origin);
      callback(new Error("Not allowed by CORS"));
    }
  },
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With", "Accept"]
}));

// ---------------------------------------------
// DB CONNECTION
// ---------------------------------------------
const pool = new Pool({
  user: "postgres",
  host: "localhost",
  database: "Admindb",
  password: "Admin@123",
  port: 5432,
});
const JWT_SECRET = "your_super_secret_key_12345";

app.use(express.json());

// ---------------------------------------------
// SIGNUP /api/signup
// ---------------------------------------------
app.post("/api/signup", async (req, res) => {
  const { name, email, password, role } = req.body;

  if (!name || !email || !password || !role) {
    return res.status(400).json({
      error: "Missing required fields: name, email, password, and role are needed.",
    });
  }

  const client = await pool.connect();

  try {
    await client.query("BEGIN"); 
    const saltRounds = 10;
    const password_hash = await bcrypt.hash(password, saltRounds);

    // 2. Insert the User
    const userSqlQuery = `
      INSERT INTO cd.users_login (full_name, email, password_hash, role)
      VALUES ($1, $2, $3, $4)
      RETURNING id, full_name, email, role, created_at;
    `;
    const userValues = [name, email, password_hash, role];
    const userResult = await client.query(userSqlQuery, userValues);
    const newUser = userResult.rows[0];
    const tenantSqlQuery = `
      INSERT INTO cd.tenants (tenant_id, name)
      VALUES ($1, $2);
    `;
    const tenantValues = [newUser.id, name]; 
    await client.query(tenantSqlQuery, tenantValues);

    await client.query("COMMIT");

    res.status(201).json({
      message: "User and Tenant created successfully",
      user: newUser,
      tenant_id: newUser.id,
    });

  } catch (err) {
    await client.query("ROLLBACK"); 
    console.error("SERVER ERROR during signup:", err.stack);

    
    if (err.code === "23505") {
      return res.status(409).json({
        error: "A user with this email already exists.",
      });
    }

    // Foreign key violation
    if (err.code === "23503") {
      return res.status(500).json({
        error: "Database constraint error. Please check database schema relations.",
      });
    }

    res.status(500).json({
      error: "An unexpected internal server error occurred during signup.",
    });
  } finally {
    client.release(); 
  }
});

// --- JWT Authentication Middleware (Verification) ---
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (token == null) {
    return res.status(401).json({ error: "Unauthorized: Token missing." });
  }
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res
        .status(403)
        .json({ error: "Forbidden: Token is invalid or expired." });
    }

    req.user = user;
    req.tenant_id =
      user?.tenant_id || user?.tenant || user?.id || user?._id || null;
    try {
      const shortId = req.tenant_id
        ? String(req.tenant_id).slice(0, 8)
        : "null";
      console.debug(`[Auth] verified token for tenant: ${shortId}`);
    } catch (e) {}

    next();
  });
};

app.post("/api/login", async (req, res) => {
  const { email, password, role } = req.body;
  if (!email || !password || !role) {
    return res.status(400).json({ error: "Missing email, password, or role." });
  }
  try {
    const result = await pool.query(
      `SELECT id, tenant_id, full_name, email, role, password_hash FROM cd.users_login WHERE email = $1`,
      [email]
    );
    const user = result.rows[0];
    if (!user) {
      return res.status(401).json({ error: "Invalid email or password." });
    }
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      return res.status(401).json({ error: "Invalid email or password." });
    }
    // Compare roles case-insensitively to avoid mismatches like 'Admin' vs 'admin'
    const storedRole = user.role ? String(user.role).toLowerCase() : "";
    const requestedRole = role ? String(role).toLowerCase() : "";
    if (storedRole !== requestedRole) {
      return res
        .status(403)
        .json({ error: `Access denied: You must log in as a ${user.role}.` });
    }
    const token = jwt.sign(
      {
        id: user.id,
        tenant_id: user.tenant_id,
        email: user.email,
        role: user.role,
      },
      JWT_SECRET,
      { expiresIn: "1h" }
    );
    res.json({
      message: "Login success",
      token: token,
      user: {
        id: user.id,
        tenant_id: user.tenant_id,
        name: user.full_name,
        role: user.role,
        email: user.email,
      },
    });
  } catch (error) {
    console.error("Login Server Error (500):", error.stack);
    res
      .status(500)
      .json({ error: "Internal Server Error during login process." });
  }
});
// ---------------------------------------------
// GET PLAYERS
// ---------------------------------------------

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const UPLOAD_DIR = path.join(__dirname, "uploads");
if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}

app.use("/uploads", express.static(UPLOAD_DIR));

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, UPLOAD_DIR);
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname) || "";
    const safeBase = path.basename(file.originalname, ext).replace(/\s+/g, "_");
    cb(null, `${Date.now()}_${safeBase}${ext}`);
  },
});

const fileFilter = (req, file, cb) => {
  const allowedMime = [
    "image/jpeg",
    "image/png",
    "image/webp",
    "image/jpg",
    "application/pdf",
  ];
  if (allowedMime.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(
      new Error("Unsupported file type. Allowed: jpeg, jpg, png, webp, pdf"),
      false
    );
  }
};

const upload = multer({
  storage,
  fileFilter,
  limits: { fileSize: 5 * 1024 * 1024 },
});

const cpUpload = upload.fields([
  { name: "profile_photo_path", maxCount: 1 },
  { name: "aadhar_upload_path", maxCount: 1 },
  { name: "birth_certificate_path", maxCount: 1 },
]);

//Players Data show the page
app.get("/api/players", authenticateToken, async (req, res) => {
  const tenantId = req.user && req.user.tenant_id;
  if (!tenantId) {
    console.error(
      "❌ Auth Error: Tenant ID missing in verified token payload."
    );
    return res
      .status(403)
      .json({ error: "Forbidden: Token lacks required tenant ID scope." });
  }
  try {
    const query = `
            SELECT id, player_id, name, age, address, phone_no, center_name, coach_name, category, status
            FROM cd.player_details
            WHERE tenant_id = $1;
        `;
    const result = await pool.query(query, [tenantId]);
    res.status(200).json({ players: result.rows });
  } catch (error) {
    console.error("❌ Database query failed in /api/players:", error);
    res
      .status(500)
      .json({ error: "Internal Server Error while fetching players." });
  }
});

// ADD PLAYER ROUTE (Fixed)
app.post("/api/players-add", authenticateToken, (req, res) => {
  cpUpload(req, res, async (err) => {
    if (err) {
      console.log("❌ Multer upload error:", err);
      const errorMessage = err.message || "File upload failed";
      return res.status(400).json({ error: errorMessage });
    }
    const tenant_id = req.user.tenant_id;
    const data = req.body;
    const numericAge = data.age === "" ? null : Number(data.age);
    const numericCoachId =
      data.coach_id === "" || data.coach_id === undefined
        ? null
        : Number(data.coach_id);
    const filePath = (field) => {
      if (req.files && req.files[field] && req.files[field].length > 0) {
        return `/uploads/${req.files[field][0].filename}`;
      }
      return null;
    };
    const profile_photo_path = filePath("profile_photo_path");
    const aadhar_upload_path = filePath("aadhar_upload_path");
    const birth_certificate_path = filePath("birth_certificate_path");

    if (!data.name || !data.date_of_birth || !tenant_id) {
      return res
        .status(400)
        .json({ error: "Missing required fields (name, DOB, or tenant ID)." });
    }

    try {
      const query = `
                INSERT INTO cd.player_details ( 
                    tenant_id, name, father_name, mother_name, gender, 
                    date_of_birth, age, blood_group, email_id, phone_no, 
                    emergency_contact_number, guardian_contact_number, guardian_email_id, 
                    address, medical_condition,
                    aadhar_upload_path, birth_certificate_path, profile_photo_path
                )
                VALUES (
                    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, 
                    $12, $13, $14, $15, $16, $17, $18) 
                RETURNING id, player_id, name;
            `.trim();

      const values = [
        tenant_id,
        data.name,
        data.father_name,
        data.mother_name,
        data.gender,
        data.date_of_birth,
        numericAge,
        data.blood_group,
        data.email_id,
        data.phone_no,
        data.emergency_contact_number,
        data.guardian_contact_number,
        data.guardian_email_id,
        data.address,
        data.medical_condition,
        aadhar_upload_path,
        birth_certificate_path,
        profile_photo_path, // $18
      ];
      const result = await pool.query(query, values);
      res
        .status(201)
        .json({ message: "Player added successfully", player: result.rows[0] });
    } catch (error) {
      console.error("❌ Database insert failed:", error);
      const errorCode = error.code || "UNKNOWN_DB_ERROR";
      res.status(500).json({
        error: "Internal Server Error: Database insertion failed.",
        code: errorCode,
      });
    }
  });
});

//---------------------------------------------
//Edit the player details
//---------------------------------------------
app.get("/api/Player-edit", async (req, res) => {
  // We will use a dedicated client from the pool to ensure proper transaction management (though optional for a SELECT)
  let client;
  try {
    const { id, player_id } = req.query;
    if (!id || !player_id) {
      return res
        .status(400)
        .json({ error: "Missing required parameters: id and player_id" });
    }
    client = await pool.connect();
    const queryText = `
            SELECT 
                id,
                name,
                age,
                address,
                center_name,
                coach_name,
                category,
                active,
                status,
                father_name,
                mother_name,
                gender,
                date_of_birth,
                blood_group,
                email_id,
                emergency_contact_number,
                guardian_contact_number,
                guardian_email_id,
                medical_condition,
                aadhar_upload_path,
                birth_certificate_path,
                profile_photo_path,
                phone_no 
            FROM 
                cd.player_details 
            WHERE 
                id = $1 
                AND player_id = $2;
        `;

    const result = await client.query(queryText, [id, player_id]);
    if (result.rows.length === 0) {
      return res
        .status(404)
        .json({ message: "Player details not found for the given IDs." });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error("Error fetching player details:", error);
    res.status(500).json({
      error: "Internal Server Error",
      details: error.message,
    });
  } finally {
    if (client) {
      client.release();
    }
  }
});

// ---------------------------------------------
// UPDATE PLAYER (FIXED)
// ---------------------------------------------
app.put("/api/Player-Edit/:id", async (req, res) => {
  try {
    const playerIdFromUrl = req.params.id;
    if (!playerIdFromUrl) {
      return res.status(400).json({ error: "Missing player id in URL." });
    }

    // Destructure expected fields (will be undefined if not provided)
    const {
      name,
      age,
      address,
      center_name,
      coach_name,
      category,
      active,
      status,
      father_name,
      mother_name,
      gender,
      date_of_birth,
      blood_group,
      email_id,
      emergency_contact_number,
      guardian_contact_number,
      guardian_email_id,
      medical_condition,
      aadhar_upload_path,
      birth_certificate_path,
      profile_photo_path,
      phone_no,
    } = req.body;

    // Basic validation example: at least one field to update
    if (
      name === undefined &&
      age === undefined &&
      address === undefined &&
      center_name === undefined &&
      coach_name === undefined &&
      category === undefined &&
      active === undefined &&
      status === undefined &&
      father_name === undefined &&
      mother_name === undefined &&
      gender === undefined &&
      date_of_birth === undefined &&
      blood_group === undefined &&
      email_id === undefined &&
      emergency_contact_number === undefined &&
      guardian_contact_number === undefined &&
      guardian_email_id === undefined &&
      medical_condition === undefined &&
      aadhar_upload_path === undefined &&
      birth_certificate_path === undefined &&
      profile_photo_path === undefined &&
      phone_no === undefined
    ) {
      return res.status(400).json({ error: "No fields provided to update." });
    }

    // Convert types if DB expects specific types
    // Example: if 'active' is stored as boolean in DB, ensure boolean
    const activeBool =
      typeof active === "boolean"
        ? active
        : active === "true" || active === 1 || active === "1";

    // If date_of_birth might include time, try to keep only date part for DB DATE column
    const dob = date_of_birth
      ? new Date(date_of_birth).toISOString().split("T")[0]
      : null;

    const sql = `
      UPDATE cd.player_details
      SET
        name = $1, age = $2, address = $3, center_name = $4, coach_name = $5,
        category = $6, active = $7, status = $8, father_name = $9,
        mother_name = $10, gender = $11, date_of_birth = $12, blood_group = $13,
        email_id = $14, emergency_contact_number = $15,
        guardian_contact_number = $16, guardian_email_id = $17,
        medical_condition = $18, aadhar_upload_path = $19,
        birth_certificate_path = $20, profile_photo_path = $21, phone_no = $22
      WHERE player_id = $23
    `;

    const values = [
      name ?? null,
      age ?? null,
      address ?? null,
      center_name ?? null,
      coach_name ?? null,
      category ?? null,
      activeBool,
      status ?? null,
      father_name ?? null,
      mother_name ?? null,
      gender ?? null,
      dob,
      blood_group ?? null,
      email_id ?? null,
      emergency_contact_number ?? null,
      guardian_contact_number ?? null,
      guardian_email_id ?? null,
      medical_condition ?? null,
      aadhar_upload_path ?? null,
      birth_certificate_path ?? null,
      profile_photo_path ?? null,
      phone_no ?? null,
      playerIdFromUrl,
    ];

    // Log input for debugging (remove/disable in production)
    console.log("Updating player:", playerIdFromUrl, "payload:", req.body);

    const result = await pool.query(sql, values);

    if (result.rowCount === 0) {
      return res
        .status(404)
        .json({ error: "Player not found or player_id incorrect." });
    }

    return res.status(200).json({
      message: "Player details updated successfully",
      rowCount: result.rowCount,
    });
  } catch (err) {
    console.error("Error executing update query:", err);
    // Return the error message to the client, but avoid leaking stack in production
    return res.status(500).json({
      error: "Failed to update player details",
      details: err.message || String(err),
    });
  }
});

// ---------------------------------------------
//DELETE route to remove a player by ID
// ---------------------------------------------
// DELETE Route (Deactivate Player) - Logic provided by user
app.delete("/api/Player-Delete/:id", async (req, res) => {
  try {
    const playerIdFromUrl = req.params.id;

    // SQL to logically delete (deactivate) the player
    const sql = `
            UPDATE cd.player_details 
            SET active = FALSE, status = 'Inactive' 
            WHERE id = $1
            RETURNING id, name;
        `;

    const result = await pool.query(sql, [playerIdFromUrl]);

    if (result.rowCount === 0) {
      return res.status(404).json({
        message: "Player not found or ID was incorrect. No record updated.",
      });
    }

    // Success response
    res.status(200).json({
      message: `Player ID ${result.rows[0].id} successfully deactivated`,
      playerId: result.rows[0].id,
    });
  } catch (error) {
    console.error("Error executing delete query:", error.message);
    res.status(500).json({
      error: "Failed to deactivate player details",
      details: error.message,
    });
  }
});

// 1. POST Route for adding a new coach (INSERT)
app.post("/api/coaches", authenticateToken, async (req, res) => {
  const tenant_id = req.user.tenant_id;
  
  // Destructure with a fallback for 'location_name' if the frontend sends that instead
  const {
    coach_name,
    phone_numbers,
    email,
    location,
    location_name, 
    players,
    salary,
    week_salary,
    category,
    active,
    status,
    attendance,
  } = req.body;

  // Final location value to be inserted
  const finalLocation = location || location_name || null;

  if (!coach_name || !email) {
    return res.status(400).send({ message: "Coach name and email are required." });
  }

  if (!tenant_id) {
    return res.status(401).send({ message: "Authentication failed. Tenant ID is missing." });
  }

  const sqlQuery = `
    INSERT INTO cd.coaches_details 
    (tenant_id, coach_name, phone_numbers, email, location, players, 
     salary, week_salary, category, active, status, attendance)
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
    RETURNING coach_id, coach_name, location, tenant_id;
  `;

  const values = [
    tenant_id,      // $1
    coach_name,     // $2
    phone_numbers,  // $3
    email,          // $4
    finalLocation,  // $5 (This matches the 'location' column in your DB)
    players,        // $6
    salary,         // $7
    week_salary,    // $8
    category,       // $9
    active,         // $10
    status,         // $11
    attendance,     // $12
  ];

  console.log("SQL VALUES being inserted:", values);

  try {
    const result = await pool.query(sqlQuery, values);
    res.status(201).send({
      message: "Coach details successfully inserted.",
      coach: result.rows[0],
    });
  } catch (error) {
    console.error("--- Database Error during INSERT /api/coaches ---");
    console.error(error);
    res.status(500).send({
      message: "Failed to insert coach details due to a server error.",
    });
  }
});

// The authenticateToken middleware runs first to set req.user.tenant_id
app.get("/api/coaches-list", authenticateToken, async (req, res) => {
  const tenantId = req.user.tenant_id;
  const sqlQuery = `
        SELECT coach_id, coach_name, phone_numbers
        FROM cd.coaches_details
        WHERE tenant_id = $1 AND active = TRUE
        ORDER BY coach_id ASC;
    `;

  try {
    const result = await pool.query(sqlQuery, [tenantId]);
    res.json({
      status: "success",
      count: result.rowCount,
      data: result.rows,
    });
  } catch (err) {
    console.error("Database query error:", err.stack);
    res
      .status(500)
      .json({ error: "Failed to fetch coach details from the database." });
  }
});

// ---------------------------------------------
//COACHES GET ROUTE
// ---------------------------------------------
// You will need to define `app`, `authenticateToken`, and `pool` elsewhere.
app.get("/api/coach-details", authenticateToken, async (req, res) => {
  const tenantId = req.user?.tenant_id;
  if (!tenantId) {
    return res.status(401).json({
      error: "Authentication failed: Tenant ID not found in user session.",
    });
  }
  const sqlQuery = `
         SELECT coach_id,
               coach_name,
               phone_numbers,
               salary,
               email,
               location,
               week_salary,
               category,
               status
        FROM cd.coaches_details
        WHERE tenant_id = $1 AND active = TRUE
        ORDER BY coach_id DESC;
    `;

  try {
    const result = await pool.query(sqlQuery, [tenantId]);

    if (result.rows.length > 0) {
      console.log(
        `Fetched ${result.rows.length} coaches for tenant_id: ${tenantId}`
      );
      return res.status(200).json({
        message: "Coach details retrieved successfully.",
        tenant_id: tenantId,
        data: result.rows,
      });
    }

    console.log(`No coaches found for tenant_id: ${tenantId}`);
    return res.status(200).json({
      message: "No coach details found for this tenant.",
      tenant_id: tenantId,
      data: [],
    });
  } catch (err) {
    console.error("Database query error:", err.stack);
    return res.status(500).json({
      error: "Failed to retrieve coach details due to a server error.",
      details: err.message,
    });
  }
});

// ---------------------------------------------
//update the coach details
// ---------------------------------------------
app.put("/api/coaches-update/:id", async (req, res) => {
  try {
    // 1. Get ID from URL path (most reliable source for a RESTful update)
    const coachIdFromParams = req.params.id; // This will be "CO31"

    const {
      coach_name,
      phone_numbers,
      email,
      location,
      salary,
      week_salary,
      active,
      status,
      // Note: We don't need to destructure coach_id from req.body anymore
    } = req.body;

    // --- Data Preparation ---

    // Safely convert salary to a number, ensuring null if empty or undefined.
    const numericSalary =
      salary !== undefined && salary !== null && salary !== ""
        ? Number(salary)
        : null;

    const numericWeekSalary = Number(week_salary) || 0;
    const isActive = active === true || active === "true" || active === 1;

    // 2. SQL Query
    const sql = `UPDATE cd.coaches_details
SET 
  coach_name = $1,
  phone_numbers = $2,
  email = $3,
  location = $4,
  salary = $5,
  week_salary = $6,
  active = $7,
  status = $8
WHERE coach_id = $9
RETURNING "coach_id", "coach_name", "status";`;

    // 3. Values Array
    const values = [
      coach_name, // $1
      phone_numbers, // $2
      email, // $3
      location, // $4
      numericSalary, // $5
      numericWeekSalary, // $6
      isActive, // $7
      status, // $8
      coachIdFromParams, // $9 <-- FIXED: Using ID from req.params.id
    ];

    const result = await pool.query(sql, values);

    // 4. Response Handling

    // FIX: Use the reliable ID from the URL (coachIdFromParams) in the message
    if (result.rowCount === 0) {
      return res.status(404).json({
        error: `Coach with ID ${coachIdFromParams} not found.`,
      });
    }

    res.status(200).json({
      message: "Coach successfully updated.",
      coach: result.rows[0],
    });
  } catch (error) {
    console.error("❌ Database update error for coach:", error.message);
    res.status(500).json({
      error: "Failed to update coach details due to a server error.",
      details: error.message,
    });
  }
});

// ---------------------------------------------
//DELETE the coach details
// ---------------------------------------------
app.put("/api/coaches-deactivate/:coach_id", async (req, res) => {
  try {
    const coachIdParam = String(req.params.coach_id || "").trim();
    let identifier = coachIdParam;
    let isNumeric = !isNaN(Number(identifier));
    if (identifier === "") {
      return res
        .status(400)
        .json({ error: "Invalid coach ID provided in the URL." });
    }
    const sql = `
        UPDATE cd.coaches_details 
        SET 
            active = FALSE, 
            status = 'Inactive' 
        WHERE coach_id::text = $1
        RETURNING coach_id, coach_name, status; 
    `;
    const values = [identifier];
    const result = await pool.query(sql, values);

    if (result.rowCount === 0) {
      return res.status(404).json({
        error: `Coach with ID ${identifier} not found.`,
      });
    }

    res.status(200).json({
      message: "Coach successfully deactivated.",
      coach: result.rows[0],
    });
  } catch (error) {}
});

// 4. API Endpoint to fetch player data
app.get("/api/players-agssign", authenticateToken, async (req, res) => {
  const tenantId = req.user && req.user.tenant_id;
  if (!tenantId) {
    console.warn("/api/players-agssign: tenant_id missing on authenticated user", { user: req.user });
    return res.status(403).json({ error: "Forbidden: Tenant not resolved for this user." });
  }
  const sqlQuery = `
        SELECT player_id, id, name, coach_name, ''::text AS coach_id
        FROM cd.player_details
        WHERE tenant_id = $1 AND active = TRUE
        ORDER BY player_id, id ASC;
    `;

  try {
    console.log(`Executing query for tenant_id: ${tenantId}`);
    const result = await pool.query(sqlQuery, [tenantId]);
    res.json({
      status: "success",
      count: result.rowCount,
      data: result.rows,
    });
  } catch (err) {
    console.error("Error executing query", err.stack);
    res
      .status(500)
      .json({ error: "Failed to fetch player details from the database." });
  }
});

//Update the assigned coach to player
app.post("/api/update-coach", authenticateToken, async (req, res) => {
  const {
    coach_name: incomingCoachName,
    coach_id, 
    player_id,
    id,
  } = req.body || {};
  
  const tenant_id = req.user && req.user.tenant_id;
  console.log("[/api/update-coach] Attempting update for Player:", player_id, "with Coach ID:", coach_id);

  if (!tenant_id) {
    return res.status(403).json({ error: "Forbidden: Tenant ID missing." });
  }
  const numericId = id ? Number(id) : NaN;
  const playerIdValue = player_id ? String(player_id) : "";

  if (isNaN(numericId) || !playerIdValue) {
    return res.status(400).json({ error: "Missing required fields: id or player_id." });
  }

  try {
    let resolvedCoachId = coach_id;
    let resolvedCoachName = incomingCoachName;

    let coachCheck;
    if (coach_id && !isNaN(Number(coach_id))) {
      coachCheck = await pool.query(
        `SELECT coach_id, coach_name FROM cd.coaches_details WHERE coach_id = $1 AND tenant_id = $2 LIMIT 1`,
        [Number(coach_id), tenant_id]
      );
    } else if (incomingCoachName) {
      coachCheck = await pool.query(
        `SELECT coach_id, coach_name FROM cd.coaches_details WHERE LOWER(coach_name) = LOWER($1) AND tenant_id = $2 LIMIT 1`,
        [String(incomingCoachName), tenant_id]
      );
    }

    if (coachCheck && coachCheck.rowCount > 0) {
      resolvedCoachId = coachCheck.rows[0].coach_id;
      resolvedCoachName = coachCheck.rows[0].coach_name;
    } else {
      return res.status(404).json({ error: "Coach not found in your organization." });
    }

    // Note: If this fails with "coach_code" error, you MUST check your DB triggers.
    const sqlQuery = `
        UPDATE cd.player_details
        SET coach_name = $1,
            coach_id = $2
        WHERE player_id = $3 
          AND id = $4 
          AND tenant_id = $5
        RETURNING *;
    `;

    const values = [
      resolvedCoachName,
      resolvedCoachId,
      playerIdValue,
      numericId,
      tenant_id,
    ];

    const result = await pool.query(sqlQuery, values);

    if (result.rowCount === 0) {
      return res.status(404).json({ error: "Player record not found." });
    }

    return res.status(200).json({
      message: "Coach assigned successfully.",
      player: result.rows[0],
    });

  } catch (err) {
    console.error("SQL Error Details:", err.message);
    return res.status(500).json({
      error: "Database error during assignment.",
      details: err.message, // This helps you see if a trigger is causing the 'coach_code' error
    });
  }
});

//fetch venue data
app.get("/api/venues-Details", authenticateToken, async (req, res) => {
  const tenantId = req.user.tenant_id;
  const client = await pool.connect();
  const venueQuery = `
        SELECT
            v.tenant_id,
            v.id,
            v.name AS name,
            v.status,
            v.center_head AS "centerHead",
            v.address,
            v.google_url AS "googleMapsUrl",
            ts.id AS "timeslotId",
            ts.start_time AS "startTime",
            ts.end_time AS "endTime",
            d.day AS day
        FROM cd.venues_data v
        LEFT JOIN cd.venuetime_slots ts
            ON ts.venue_id = v.id
        LEFT JOIN cd.venuetimeslot_days d
            ON d.time_slot_id::integer = ts.id
        WHERE v.active = true AND v.tenant_id = $1
        ORDER BY v.id, ts.id, d.day;
    `;

  try {
    const result = await client.query(venueQuery, [tenantId]);
    const rows = result.rows;
    const venuesMap = new Map();
    rows.forEach((row) => {
      const venueId = row.id;

      if (!venuesMap.has(venueId)) {
        venuesMap.set(venueId, {
          id: row.id,
          tenant_id: row.tenant_id,
          name: row.name,
          status: row.status,
          centerHead: row.centerHead,
          address: row.address,
          googleMapsUrl: row.googleMapsUrl,
          timeSlots: [],
        });
      }
      if (row.timeslotId && row.day) {
        const venue = venuesMap.get(venueId);
        venue.timeSlots.push({
          day: row.day,
          startTime: row.startTime,
          endTime: row.endTime,
        });
      }
    });
    const structuredVenues = Array.from(venuesMap.values());
    res.status(200).json(structuredVenues);
  } catch (error) {
    console.error("Database Error during venue fetch:", error.message);
    res
      .status(500)
      .json({ error: "Failed to fetch venue data due to a server error." });
  } finally {
    client.release();
  }
});

// Apply the authentication middleware to secure the route
app.post("/api/venue-add", authenticateToken, async (req, res) => {
  const tenantId = req.user.tenant_id;
  const { name, centerHead, address, googleUrl, timeSlots } = req.body;
  const isActive = true;
  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    const venueInsertQuery = `
            INSERT INTO cd.venues_data
                (tenant_id, name, center_head, address, active, google_url)
                VALUES ($1, $2, $3, $4, $5, $6)
                RETURNING id;
        `;
    const venueResult = await client.query(venueInsertQuery, [
      tenantId,
      name,
      centerHead,
      address,
      isActive,
      googleUrl,
    ]);
    const venueId = venueResult.rows[0].id;
    const uniqueSlots = {};
    timeSlots.forEach((slot) => {
      const key = `${slot.startTime}-${slot.endTime}`;
      if (!uniqueSlots[key]) {
        uniqueSlots[key] = {
          startTime: slot.startTime,
          endTime: slot.endTime,
          days: [],
        };
      }
      uniqueSlots[key].days.push(slot.day);
    });

    for (const key in uniqueSlots) {
      const { startTime, endTime, days } = uniqueSlots[key];
      const slotActive = true;

      const slotInsertQuery = `
                INSERT INTO cd.venuetime_slots
                    (tenant_id, venue_id, start_time, end_time, active)
                    VALUES ($1, $2, $3, $4, $5)
                    RETURNING id;
            `;
      const slotResult = await client.query(slotInsertQuery, [
        tenantId,
        venueId,
        startTime,
        endTime,
        slotActive,
      ]);
      const timeSlotId = slotResult.rows[0].id;

      const dayActive = true;
      for (const day of days) {
        const dayInsertQuery = `
                    INSERT INTO cd.venuetimeslot_days
                        (tenant_id, time_slot_id, day, active)
                        VALUES ($1, $2, $3, $4);
                `;
        await client.query(dayInsertQuery, [
          tenantId,
          timeSlotId,
          day,
          dayActive,
        ]);
      }
    }

    await client.query("COMMIT");
    res.status(201).json({
      message: "Venue and Time Slots inserted successfully.",
      venue_id: venueId,
    });
  } catch (error) {
    await client.query("ROLLBACK");
    console.error("Transaction Error:", error.message);
    res
      .status(500)
      .json({ error: "Failed to insert data due to a database error." });
  } finally {
    client.release();
  }
});

// server.js (or wherever your route lives)
app.delete("/api/venues-delete/:id", async (req, res) => {
  const venueId = Number(req.params.id);
  if (!Number.isInteger(venueId) || venueId <= 0) {
    return res.status(400).json({ error: "Invalid venue ID provided." });
  }

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const deleteDaysQuery = `
      UPDATE cd.venuetimeslot_days
      SET active = false,
          updated_at = CURRENT_TIMESTAMP
      WHERE id = $1
    `;
    const resultDays = await client.query(deleteDaysQuery, [venueId]);

    const deleteSlotsQuery = `
      UPDATE cd.venuetime_slots
      SET active = false,
          updated_at = CURRENT_TIMESTAMP
      WHERE id = $1
    `;
    const resultSlots = await client.query(deleteSlotsQuery, [venueId]);

    const deleteVenueQuery = `
      UPDATE cd.venues_data
      SET active = false,
          updated_at = CURRENT_TIMESTAMP
      WHERE id = $1
    `;
    const resultVenue = await client.query(deleteVenueQuery, [venueId]);

    if (resultVenue.rowCount === 0) {
      await client.query("ROLLBACK");
      return res
        .status(404)
        .json({ error: `Venue with ID ${venueId} not found.` });
    }

    await client.query("COMMIT");
    res.status(200).json({
      message: `Venue ID ${venueId} and related data deactivated successfully.`,
    });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("Venue deletion failed:", err.stack);
    res.status(500).json({
      error: "Failed to delete venue due to a server or database error.",
    });
  } finally {
    client.release();
  }
});

//Start this serever coach details and Database dashboard working fine
// The SQL Query Constant
const sql = (strings, ...values) => {
  let query = strings.reduce(
    (acc, str, i) => acc + str + (values[i] !== undefined ? values[i] : ""),
    ""
  );
  query = query.trim();
  const lines = query.split("\n").map((line) => line.trim());
  return lines.filter((line) => line.length > 0).join(" ");
};

app.get("/api/coach-data", authenticateToken, async (req, res) => {
  if (req.user.role !== "coach") {
    return res
      .status(403)
      .json({ error: "Access denied. Only coaches can view this data." });
  }
  const coachEmail = req.user.email;
  if (!coachEmail) {
    return res
      .status(400)
      .json({ error: "Authenticated user email is missing." });
  }

  try {
    const queryString = sql`
SELECT 
    p.player_id AS id,
    p.name,
    p.age,
    p.category,
    p.status,
    ROUND(
        (SUM(CASE WHEN a.is_present = TRUE THEN 1 ELSE 0 END) * 100.0)
        / NULLIF(COUNT(a.attendance_id), 0),
        2
    ) AS attendance
FROM cd.player_details p
LEFT JOIN cd.attendance_sheet a ON p.player_id = a.player_id
INNER JOIN cd.coaches_details c ON p.coach_id = c.coach_id
INNER JOIN cd.users_login u ON c.email = u.email
WHERE
    u.email = $1
    AND u.role = 'coach'
    AND p.active = TRUE
GROUP BY
    p.player_id, p.name, p.age, p.category, p.status
ORDER BY
    p.name;
    `;

    const result = await pool.query(queryString, [coachEmail]);
    res.json({
      coach_email: coachEmail,
      players: result.rows,
    });
  } catch (err) {
    console.error("Error executing coach data query:", err.stack);
    res
      .status(500)
      .json({ error: "Internal server error while fetching player data." });
  }
});
// ---------------------------------------------
// Attendance Recording Endpoint
// ---------------------------------------------
app.post("/api/attendance", authenticateToken, async (req, res) => {
  const tenantId = req.user?.tenantId; 
  const authenticatedUserId = req.user?.userId;
  let { 
    playerId, 
    attendanceDate, 
    isPresent, 
    coachId, 
    latitude, 
    longitude, 
    locationAddress, 
    timezone 
  } = req.body || {};

  console.debug("/api/attendance payload:", { playerId, attendanceDate, isPresent, coachId, latitude, longitude });

  if (!playerId || !attendanceDate || isPresent === undefined) {
    return res.status(400).json({
      error: "Missing required data. Required: playerId, attendanceDate, isPresent.",
    });
  }
  
  if (typeof isPresent === "string") {
    isPresent = isPresent.toLowerCase() === "true";
  } else {
    isPresent = Boolean(isPresent);
  }

  const parsedDate = new Date(attendanceDate);
  if (Number.isNaN(parsedDate.getTime())) {
    return res.status(400).json({
      error: "Invalid attendanceDate format (YYYY-MM-DD).",
      received: attendanceDate,
    });
  }

  let numericCoachId = Number(coachId || authenticatedUserId);

  try {
    if (isNaN(numericCoachId)) {
      const lookup = await pool.query(
        `SELECT coach_id FROM cd.coaches_details WHERE coach_name = $1 LIMIT 1;`,
        [String(coachId).trim()]
      );
      if (lookup.rows.length > 0) {
        numericCoachId = lookup.rows[0].coach_id;
      } else {
        return res.status(400).json({ error: `Could not find coach: ${coachId}` });
      }
    }

    const formattedDate = parsedDate.toISOString().split("T")[0];
    const normalizedPlayerId = String(playerId).trim();

    const queryText = `
      INSERT INTO cd.attendance_sheet 
        (tenant_id, player_id, attendance_date, is_present, recorded_by_coach_id,
         latitude, longitude, location_address, timezone, submitted_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())
      RETURNING *;
    `;

    const queryValues = [
      tenantId,           // $1
      normalizedPlayerId, // $2
      formattedDate,      // $3
      isPresent,          // $4
      numericCoachId,     // $5
      latitude || null,   // $6
      longitude || null,  // $7
      locationAddress || "Not provided", // $8
      timezone || "UTC"   // $9
    ];

    const result = await pool.query(queryText, queryValues);

    res.status(201).json({
      message: "Attendance successfully recorded.",
      data: result.rows[0],
    });

  } catch (err) {
    console.error("Database Error:", err);
    
    if (err.code === "23505") { 
        return res.status(409).json({ error: "Attendance already exists for this player on this date." });
    }

    return res.status(500).json({
      error: "Failed to record attendance.",
      details: err.message,
    });
  }
});

//Fetches player details, attendance percentage, and recent activities for a player guardian
app.get("/api/player-details/:email/:playerId", authenticateToken, async (req, res) => {
  const { email: parentEmail, playerId } = req.params;
  if (req.user.role !== "parent" || req.user.email.toLowerCase().trim() !== parentEmail.toLowerCase().trim()) {
    return res.status(403).json({
      error: "Forbidden: You do not have permission to access this data.",
    });
  }

  try {
    const sqlQuery = `
      SELECT
          pd.player_id,
          pd.name,
          pd.age,
          pd.center_name AS center,
          pd.coach_name AS coach,
          pd.category AS position,
          pd.phone_no,
          pd.email_id AS player_email,
          COALESCE(
              CAST(SUM(CASE WHEN a.is_present = TRUE THEN 1 ELSE 0 END) AS NUMERIC) * 100 /
              NULLIF(COUNT(a.attendance_id), 0),
              0
          ) AS attendance_percentage,
          (
              SELECT json_agg(activity_list)
              FROM (
                  SELECT 
                      a_recent.attendance_date AS date,
                      'Training Session' AS activity,
                      CASE WHEN a_recent.is_present THEN 'Present' ELSE 'Absent' END AS status
                  FROM cd.attendance_sheet a_recent
                  WHERE a_recent.player_id = pd.player_id
                    AND a_recent.attendance_date >= CURRENT_DATE - INTERVAL '1 month'
                  ORDER BY a_recent.attendance_date DESC
              ) activity_list
          ) AS recent_activities_json
      FROM cd.player_details pd
      LEFT JOIN cd.attendance_sheet a 
          ON pd.player_id = a.player_id
      INNER JOIN cd.users_login ul 
          ON LOWER(TRIM(ul.email)) = LOWER(TRIM(pd.guardian_email_id))
      WHERE
          LOWER(TRIM(ul.email)) = LOWER(TRIM($1))
          AND ul.role = 'parent'
          AND pd.player_id = $2
      GROUP BY
          pd.player_id,
          pd.name,
          pd.age,
          pd.center_name,
          pd.coach_name,
          pd.category,
          pd.phone_no,
          pd.email_id;
    `;

    const result = await pool.query(sqlQuery, [parentEmail, playerId]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: "No player found for this parent." });
    }
    res.json(result.rows[0]);

  } catch (err) {
    console.error("Error executing query:", err.message);
    res.status(500).json({ error: "Internal server error while fetching player data." });
  }
});

// New: Fetch all players for a guardian (by guardian email)
app.get("/api/player-details-by-guardian/:email", authenticateToken, async (req, res) => {
  const { email: parentEmail } = req.params;
  if (req.user.role !== "parent" || req.user.email.toLowerCase().trim() !== parentEmail.toLowerCase().trim()) {
    return res.status(403).json({ error: "Forbidden: You do not have permission to access this data." });
  }

  try {
    const sqlQuery = `
      SELECT
          pd.player_id,
          pd.name,
          pd.age,
          pd.center_name AS center,
          pd.coach_name AS coach,
          pd.category AS position,
          pd.phone_no,
          pd.email_id AS player_email,
          COALESCE(
              CAST(SUM(CASE WHEN a.is_present = TRUE THEN 1 ELSE 0 END) AS NUMERIC) * 100 /
              NULLIF(COUNT(a.attendance_id), 0),
              0
          ) AS attendance_percentage,
          (
              SELECT json_agg(activity_list)
              FROM (
                  SELECT 
                      a_recent.attendance_date AS date,
                      'Training Session' AS activity,
                      CASE WHEN a_recent.is_present THEN 'Present' ELSE 'Absent' END AS status
                  FROM cd.attendance_sheet a_recent
                  WHERE a_recent.player_id = pd.player_id
                    AND a_recent.attendance_date >= CURRENT_DATE - INTERVAL '1 month'
                  ORDER BY a_recent.attendance_date DESC
              ) activity_list
          ) AS recent_activities_json
      FROM cd.player_details pd
      LEFT JOIN cd.attendance_sheet a ON pd.player_id = a.player_id
      INNER JOIN cd.users_login ul ON LOWER(TRIM(ul.email)) = LOWER(TRIM(pd.guardian_email_id))
      WHERE LOWER(TRIM(ul.email)) = LOWER(TRIM($1))
        AND ul.role = 'parent'
      GROUP BY
          pd.player_id,
          pd.name,
          pd.age,
          pd.center_name,
          pd.coach_name,
          pd.category,
          pd.phone_no,
          pd.email_id
      ORDER BY pd.player_id ASC;
    `;

    const result = await pool.query(sqlQuery, [parentEmail]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: "No players found for this parent." });
    }
    // Return array of player objects
    res.json(result.rows);

  } catch (err) {
    console.error("Error executing query (by guardian):", err.message);
    res.status(500).json({ error: "Internal server error while fetching player data." });
  }
});

app.use(express.json());

//fech data registrations API and code
app.get("/api/registrations", authenticateToken, async (req, res) => {
  const tenant_id =
    req.tenant_id ||
    req.user?.tenant_id ||
    req.user?.id ||
    req.body?.tenant_id ||
    req.headers["x-tenant-id"];

  if (!tenant_id) {
    return res
      .status(403)
      .json({ error: "Access denied. Tenant ID not resolved." });
  }
  const queryText = `
        SELECT
            tenant_id,
            regist_id,
            name,
            phone_number,
            email_id,
            address,
            age,
            application_date,
            parent_name,
            Status,
            active
        FROM cd.registrations_details 
        WHERE tenant_id = $1
        ORDER BY regist_id DESC;
    `;

  const values = [tenant_id];
  try {
    console.log(`Fetching registrations for tenant: ${tenant_id}`);
    const result = await pool.query(queryText, values);

    return res.status(200).json({
      success: true,
      tenant_id: tenant_id,
      count: result.rowCount,
      registrations: result.rows,
    });
  } catch (err) {
    console.error("!!! DB ERROR (Fetch Failed) !!!", err);
    return res.status(500).json({
      error: "Failed to fetch registrations.",
      details: err.message,
    });
  }
});

//Endpoint for Bulk Uploading New Registrations from Excel
app.post(
  "/api/registrations/bulk-upload",
  authenticateToken,
  async (req, res) => {
    const registrations = req.body;
    const tenant_id =
      req.user?.tenant_id ||
      req.body?.tenant_id ||
      req.headers["x-tenant-id"] ||
      null;

    if (!tenant_id) {
      console.error(
        "Bulk upload rejected: Tenant ID missing (token/body/header)"
      );
      return res
        .status(403)
        .json({ error: "Tenant ID missing. Check authentication middleware." });
    }

    if (!Array.isArray(registrations) || registrations.length === 0) {
      return res.status(400).json({ error: "Invalid or empty array" });
    }

    console.log(
      `Received ${registrations.length} registrations for bulk upload for tenant ${tenant_id}.`
    );

    const allColumns = [
      "tenant_id",
      "name",
      "phone_number",
      "email_id",
      "address",
      "age",
      "application_date",
      "parent_name",
    ];

    let values = [];
    const columnCount = allColumns.length;

    const placeholders = registrations
      .map((reg, index) => {
        const base = index * columnCount + 1;

        values.push(
          tenant_id,
          reg.name || null,
          reg.phone_number || null,
          reg.email_id || null,
          reg.address || null,
          reg.age !== undefined && reg.age !== null ? reg.age : null,
          reg.application_date || null,
          reg.parent_name || null
        );
        return `(${allColumns.map((_, i) => `$${base + i}`).join(",")})`;
      })
      .join(",");
    const sql = `
        INSERT INTO cd.registrations_details
        (${allColumns.join(",")}) 
        VALUES ${placeholders}
        ON CONFLICT (tenant_id, email_id) DO NOTHING
        RETURNING *;
    `;

    console.log("Generated SQL (Snippet):", sql.substring(0, 100) + "...");

    try {
      const result = await pool.query(sql, values);
      console.log(
        `Database query successful. Inserted: ${result.rowCount} rows.`
      );
      return res.status(201).json({
        success: true,
        tenant_id: tenant_id,
        inserted: result.rowCount,
        totalRecordsAttempted: registrations.length,
        newRecords: result.rows,
      });
    } catch (err) {
      console.error("!!! DB ERROR (Bulk Insert Failed) !!!", err);
      return res.status(500).json({
        error: "Database insert failed",
        details: err.message,
      });
    }
  }
);

//updated the reaject and approved Registrations Excell
app.put("/api/registrations/status/:id", async (req, res) => {
  const { id } = req.params;
  const { status } = req.body;

  if (!status || !id) {
    return res
      .status(400)
      .json({ error: "Missing required fields: status or registration ID." });
  }

  const sqlQuery = `
      UPDATE cd.registrations_details 
      SET Status = $1 
      WHERE regist_id = $2
    `;
  const values = [status, id];

  try {
    const client = await pool.connect();
    const result = await client.query(sqlQuery, values);
    client.release();

    if (result.rowCount === 0) {
      return res.status(404).json({
        success: false,
        message: `Registration with ID ${id} not found.`,
      });
    }

    res.status(200).json({
      success: true,
      message: `Registration ${id} status updated to ${status}.`,
    });
  } catch (err) {
    console.error("Error executing PUT query:", err);
    res.status(500).json({ error: "Database update failed." });
  }
});

//Delete the Registrations Serever.js and API
app.delete("/api/registrations/:id", async (req, res) => {
  const { id } = req.params;
  if (!id) {
    return res.status(400).json({ error: "Registration ID (id) is required." });
  }

  try {
    const queryText = `
      DELETE FROM cd.registrations_details 
      WHERE regist_id = $1;
    `;
    const result = await pool.query(queryText, [id]);
    if (result.rowCount === 0) {
      return res
        .status(404)
        .json({ message: `Registration with ID ${id} not found.` });
    }
    res.status(204).send();
  } catch (error) {
    console.error("Error deleting registration:", error.stack);
    res
      .status(500)
      .json({ error: "Failed to delete registration due to a server error." });
  }
});

// A. Route for Coach Data: /api/coachdata/:coachId
app.get("/api/coachdata/:coachId", async (req, res) => {
  try {
    const { coachId } = req.params;
    const query = "SELECT * FROM cd.coaches_details WHERE coach_id = $1";
    const { rows } = await pool.query(query, [coachId]);
    if (rows.length === 0) {
      return res.status(404).json({ error: `Coach ID ${coachId} not found.` });
    }

    res.json(rows[0]);
  } catch (error) {
    console.error("Error fetching coach details:", error);
    res.status(500).json({ error: "Internal server error." });
  }
});

// B. Route for Players: /api/coachplayers/:coachId/players
app.get("/api/coachplayers/:coachId/players", async (req, res) => {
  const { coachId } = req.params;
  try {
    const query = `
      SELECT 
    p.player_id,
    p.name,
    p.age,
    p.category,
    p.active,
    ROUND(
        (COUNT(a.attendance_id) FILTER (WHERE a.is_present = TRUE)::decimal 
        / NULLIF(COUNT(a.attendance_id), 0)) * 100, 2
    ) AS attendance_percentage
FROM 
    cd.player_details p
LEFT JOIN 
    cd.attendance_sheet a 
ON 
    p.player_id = a.player_id
WHERE 
    p.coach_code = $1
GROUP BY 
    p.player_id, p.name, p.age, p.category, p.active
ORDER BY 
    p.name;
    `;
    const result = await pool.query(query, [coachId]);
    res.json(result.rows);
  } catch (error) {
    console.error("Error fetching coach players:", error);
    res.status(500).send({
      error: "Internal Server Error (Coach Players)",
      details: error.message,
    });
  }
});

//show the all session query and code
app.get("/api/sessions-data/:coachId", async (req, res) => {
  try {
    const { coachId } = req.params;

    let finalCoachId = coachId;
    if (typeof coachId === "string" && coachId.toUpperCase().startsWith("CO")) {
      finalCoachId = coachId.substring(2);
    }

    if (!finalCoachId || finalCoachId.trim().length === 0) {
      return res
        .status(400)
        .json({ message: "Invalid or missing coach ID parameter." });
    }
    const numericCoachId = parseInt(finalCoachId, 10);

    if (isNaN(numericCoachId)) {
      return res
        .status(400)
        .json({ message: "Coach ID must resolve to a valid number." });
    }
    console.log(`Fetching sessions for numeric coach ID: ${numericCoachId}`);
    const queryText = `
      SELECT 
        session_id,
        day_of_week,
        start_time,
        end_time,
        group_category,
        location,
        status,
        coach_id
      FROM cd.training_sessions
      WHERE coach_id = $1 
      ORDER BY session_id DESC;
    `;
    const result = await pool.query(queryText, [numericCoachId]);
    if (result.rows.length === 0) {
      return res.status(200).json([]);
    }

    res.status(200).json(result.rows);
  } catch (error) {
    console.error("Error fetching sessions:", error.message, error.stack);
    res.status(500).json({
      error: "Internal Server Error during session fetch",
      details: error.message,
    });
  }
});

// Assuming 'app' is your Express app instance:
app.post("/api/sessions-insert", authenticateToken, async (req, res) => {
  try {
    let {
      coach_id,
      coach_name,
      day_of_week,
      start_time,
      end_time,
      group_category,
      location,
      status,
      active,
    } = req.body ?? {};

    // FALLBACK: If coach_id isn't in body, try to get it from the authenticated user token
    if (!coach_id && req.user) {
        coach_id = req.user.coach_id || req.user.id;
    }

    if (!coach_id) {
      return res.status(400).json({ error: "Invalid or missing coach_id" });
    }

    // Logic to ensure coach_id is a clean number
    let resolvedCoachId = Number(String(coach_id).replace(/\D/g, ""));

    if (isNaN(resolvedCoachId)) {
      return res.status(400).json({ error: "Coach ID must be a valid numeric value." });
    }

    // Default Values
    status = (typeof status === "string" && status.trim() !== "") ? status.trim() : "Upcoming";
    active = active !== undefined ? (String(active).toLowerCase() === "true") : true;

    const queryText = `
      INSERT INTO cd.training_sessions 
      (coach_id, coach_name, day_of_week, start_time, end_time, group_category, location, status, active) 
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) 
      RETURNING *;
    `;

    const values = [
      resolvedCoachId,
      coach_name,
      day_of_week,
      start_time,
      end_time,
      group_category ?? null,
      location ?? null,
      status,
      active,
    ];

    const { rows } = await pool.query(queryText, values);
    return res.status(201).json(rows[0]);

  } catch (error) {
    console.error("Error adding session:", error);
    return res.status(500).json({ error: "Internal Server Error", details: error.message });
  }
});

//Update the coach session query
app.put("/api/sessions-updated/:session_id", async (req, res) => {
  try {
    const { session_id: sessionIdParam } = req.params;
    const session_id = parseInt(sessionIdParam, 10);
    if (isNaN(session_id) || session_id <= 0) {
      console.error(
        "Attempted update with invalid session ID format:",
        sessionIdParam
      );
      return res.status(400).json({
        error: "Invalid session ID format. ID must be a positive integer.",
        details: `Received ID: ${sessionIdParam}`,
      });
    }

    const {
      day_of_week,
      start_time,
      end_time,
      group_category,
      location,
      status,
    } = req.body;

    const queryText = `
      UPDATE cd.training_sessions 
      SET 
        day_of_week = $1,
        start_time = $2,
        end_time = $3,
        group_category = $4,
        location = $5,
        status = $6
      WHERE session_id = $7
      RETURNING *;
    `;

    const values = [
      day_of_week,
      start_time,
      end_time,
      group_category,
      location,
      status,
      session_id,
    ];
    const result = await pool.query(queryText, values);

    if (result.rowCount === 0) {
      return res.status(404).json({ error: "Training session not found." });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error("Error updating session:", error);
    res
      .status(500)
      .json({ error: "Internal Server Error", details: error.message });
  }
});

// Delete session route
app.delete("/api/sessions/:session_id", async (req, res) => {
  try {
    const { session_id: sessionIdParam } = req.params;
    console.log(
      `[${new Date().toISOString()}] DELETE /api/sessions/:session_id called. param=`,
      sessionIdParam
    );

    const session_id = parseInt(sessionIdParam, 10);
    if (isNaN(session_id) || session_id <= 0) {
      console.error(
        "Attempted delete with invalid session ID format:",
        sessionIdParam
      );
      return res.status(400).json({
        error: "Invalid session ID format. ID must be a positive integer.",
      });
    }

    const queryText = `
      DELETE FROM cd.training_sessions
      WHERE session_id = $1;
    `;
    const values = [session_id];
    const result = await pool.query(queryText, values);
    if (result.rowCount === 0) {
      console.warn(
        `Delete attempted but no rows affected for session_id ${session_id}`
      );
      return res
        .status(404)
        .json({ error: "Training session not found or already deleted." });
    }
    console.log(`Successfully deleted session ID: ${session_id}`);
    return res.status(204).send();
  } catch (error) {
    console.error("Error deleting session:", error);
    return res
      .status(500)
      .json({ error: "Internal Server Error", details: error.message });
  }
});

//Payment details API and code
app.get("/api/payments", authenticateToken, async (req, res) => {
  const tenant_id = req.user?.tenant_id ?? req.user?.tenant ?? null;

  if (!tenant_id) {
    return res
      .status(401)
      .json({ message: "Authentication failed: Tenant ID missing." });
  }

  const queryText = `
        SELECT 
            payment_id,
            full_name,
            email,
            phone,
            amount_paid,
            hire_date,
            end_date,
            status
        FROM cd.payment_details
        WHERE tenant_id = $1 AND active = TRUE
        ORDER BY payment_id DESC;
    `;

  try {
    const result = await pool.query(queryText, [tenant_id]);
    return res.status(200).json({
      message: "Payment records retrieved successfully.",
      data: result.rows,
    });
  } catch (err) {
    console.error(
      "Database retrieval error (payments):",
      err.stack || err.message || err
    );
    return res
      .status(500)
      .json({
        message: "Error retrieving payment details.",
        error: err.message,
      });
  }
});

//payment insert the data
app.post("/api/payment", authenticateToken, async (req, res) => {
  const tenant_id = req.user?.tenant_id ?? req.user?.tenant ?? null;
  console.log(`A user is inserting payment details for tenant ${tenant_id}.`);
  const { full_name, email, phone, amount_paid, hire_date, end_date } =
    req.body || {};
  if (!full_name || !email || amount_paid == null || !hire_date || !end_date) {
    return res
      .status(400)
      .json({ message: "Missing required payment fields." });
  }
  const amount = Number(amount_paid);
  if (Number.isNaN(amount) || amount < 0) {
    return res.status(400).json({ message: "Invalid amount_paid value." });
  }
  const hireDateStr = String(hire_date);
  const endDateStr = String(end_date);

  const queryText = `
    INSERT INTO cd.payment_details (tenant_id, full_name, email, phone, amount_paid, hire_date, end_date)
    VALUES ($1, $2, $3, $4, $5, $6, $7)
    RETURNING *;
  `;

  const values = [
    tenant_id,
    full_name,
    email,
    phone,
    amount,
    hireDateStr,
    endDateStr,
  ];

  try {
    const result = await pool.query(queryText, values);
    return res.status(201).json({
      message: "Payment details inserted successfully.",
      requester: { tenant_id },
      data: result.rows[0],
    });
  } catch (err) {
    console.error(
      "Database insertion error (payment):",
      err.stack || err.message || err
    );
    return res
      .status(500)
      .json({
        message: "Error inserting payment details.",
        error: err.message,
      });
  }
});

// Example: GET /api/payment_details?login_id=USER-12345
app.get("/api/payment_details", authenticateToken, async (req, res) => {
  // Get the login_id from the query parameters (e.g., ?login_id=...)
  const loginId = req.query.login_id;

  // Check if loginId was provided
  if (!loginId) {
    return res
      .status(400)
      .json({ error: "Missing required query parameter: login_id" });
  }

  // The SQL query with the parameter placeholder $1
  const queryText = `
    SELECT
      tenant_id,
      payment_id,
      full_name,
      email,
      amount_paid,
      end_date
    FROM
      cd.payment_details
    WHERE
      login_id = $1;
  `;

  try {
    const result = await pool.query(queryText, [loginId]);
    res.json(result.rows);
  } catch (err) {
    console.error("Error executing query", err.stack);
    res
      .status(500)
      .json({ error: "Database query failed", details: err.message });
  }
});

// The middleware runs BEFORE the route handler (async (req, res) => { ... })
app.get("/api/payments-details", authenticateToken, async (req, res) => {
  const tenant_id = req.user?.tenant_id ?? req.user?.tenant ?? null;

  if (!tenant_id) {
    return res
      .status(401)
      .json({ message: "Authentication failed: Tenant ID missing." });
  }

  const queryText = `
        SELECT
          tenant_id,
          payment_id,
          full_name,
          email,
          amount_paid,
          end_date
        FROM cd.payment_details
        WHERE tenant_id = $1 AND active = TRUE
        ORDER BY payment_id DESC;
    `;

  try {
    const result = await pool.query(queryText, [tenant_id]);
    return res.status(200).json({
      message: "Payment records retrieved successfully.",
      data: result.rows,
    });
  } catch (err) {
    console.error(
      "Database retrieval error (payments):",
      err.stack || err.message || err
    );
    return res
      .status(500)
      .json({
        message: "Error retrieving payment details.",
        error: err.message,
      });
  }
});

// Apply the authentication middleware to the route
app.get("/api/payments/my-details", authenticateToken, async (req, res) => {
  const tenantId = req.user.tenant_id;
  const sqlQuery = `
        SELECT
            tenant_id,
            payment_id,
            full_name,
            phone,
            email,
            amount_paid,
            hire_date,
            end_date,
            status
        FROM
            cd.payment_details
        WHERE
            tenant_id = $1 AND active = TRUE
        ORDER BY
            payment_id DESC;
    `;

  try {
    const { rows } = await pool.query(sqlQuery, [tenantId]);
    res.json({
      message: `Payment details for tenant_id: ${tenantId}`,
      data: rows,
    });
  } catch (err) {
    console.error("Database query error:", err);
    res.status(500).json({
      error: "Failed to retrieve payment details.",
      details: err.message,
    });
  }
});

//delete the payment details API and code
app.put("/api/payment/deactivate/:id", async (req, res) => {
  const paymentId = req.params.id;
  const queryText = `
    UPDATE cd.payment_details
    SET active = FALSE
    WHERE payment_id = $1;
  `;
  const queryParams = [paymentId];
  try {
    const result = await pool.query(queryText, queryParams);
    if (result.rowCount > 0) {
      res.status(200).json({
        message: `Payment method with ID ${paymentId} has been successfully deactivated.`,
        updatedRows: result.rowCount,
      });
    } else {
      res.status(404).json({
        error: `Payment method with ID ${paymentId} not found.`,
      });
    }
  } catch (err) {
    console.error("Error executing update query", err.stack);
    res.status(500).json({
      error:
        "An internal server error occurred while deactivating the payment method.",
    });
  }
});

//edit the payment details
app.get("/api/payment/:id", async (req, res) => {
  const paymentId = req.params.id;
  if (!paymentId || isNaN(paymentId)) {
    return res.status(400).json({ error: "Invalid or missing payment ID." });
  }
  const queryText = `
    SELECT 
        payment_id,
        full_name,
        email,
        phone,
        amount_paid,
        hire_date,
        end_date,
        status
    FROM cd.payment_details
    WHERE payment_id = $1 AND active = TRUE
    ORDER BY payment_id DESC;
  `;

  try {
    const result = await pool.query(queryText, [paymentId]);
    if (result.rows.length === 0) {
      return res
        .status(404)
        .json({
          error: `Payment record with ID ${paymentId} not found or is inactive.`,
        });
    }
    res.json(result.rows[0]);
  } catch (error) {
    console.error(`Database query error fetching payment ${paymentId}:`, error);
    res
      .status(500)
      .json({ error: "Internal server error while fetching payment details." });
  }
});

// Update payment details API and code
app.put("/api/payment/:id", async (req, res) => {
  const paymentId = req.params.id;
  const { full_name, email, phone, amount_paid, hire_date, end_date, status } =
    req.body;
  const queryText = `
        UPDATE cd.payment_details
        SET full_name = $1,
            email = $2,
            phone = $3,
            amount_paid = $4,
            hire_date = $5,
            end_date = $6,
            status = $7
        WHERE payment_id = $8
        RETURNING *; -- RETURNING * sends the updated record back
    `;

  const queryParams = [
    full_name,
    email,
    phone,
    amount_paid,
    hire_date,
    end_date,
    status,
    paymentId,
  ];

  try {
    // Use the established Postgres pool instance
    const result = await pool.query(queryText, queryParams);
    if (result.rowCount > 0) {
      res.status(200).json(result.rows[0]);
    } else {
      res.status(404).json({
        error: `Payment record with ID ${paymentId} not found.`,
      });
    }
  } catch (err) {
    console.error("Error executing payment update query:", err.stack);
    res.status(500).json({
      error:
        "An internal server error occurred while updating the payment record.",
    });
  }
});

// pending amount and paid amount API and code
app.get("/api/payment-summary", authenticateToken, async (req, res) => {
  const tenantId = req.tenantId;
  const sqlQuery = `
   SELECT
    CAST(DATE_TRUNC('month', hire_date) AS DATE) AS payment_date,
    SUM(CASE WHEN status IN ('paid', 'completed') THEN amount_paid ELSE 0 END) AS total_paid_amount,
    SUM(CASE WHEN status IN ('pending', 'overdue') THEN amount_paid ELSE 0 END) AS total_pending_amount
FROM
    cd.payment_details  WHERE tenant_id = $1 AND active = TRUE
GROUP BY
    payment_date 
ORDER BY
    payment_date;
  `;

  try {
    const result = await pool.query(sqlQuery, [tenantId]);
    const summary = result.rows[0];

    if (!summary) {
      return res.status(404).json({ message: "No payment summary found." });
    }
    res.json({
      tenant_id: tenantId,
      total_paid_amount: parseFloat(summary.total_paid_amount) || 0,
      total_pending_amount: parseFloat(summary.total_pending_amount) || 0,
    });
  } catch (err) {
    console.error("Database query error:", err.stack);
    res
      .status(500)
      .send("Internal Server Error while fetching payment summary.");
  }
});

// GET Route for Locations
app.get('/api/venues-drop', authenticateToken, async (req, res) => {
  try {
    const tenantId = req.user.tenant_id; 
    const query = `
      SELECT id, center_head 
      FROM cd.venues_data
      WHERE active = true AND tenant_id = $1
      ORDER BY id DESC
    `;
    const result = await pool.query(query, [tenantId]);
    res.json(result.rows);
  } catch (err) {
    console.error(err.message);
    res.status(500).send("Server Error");
  }
});

// 2. The API Route to fetch attendance by Coach ID
app.get('/api/attendance-records/:coachId', async (req, res) => {
    const coachId = req.params.coachId;

    const query = `
        SELECT 
            pd.name,
            at.player_id,
            at.attendance_date,
            CASE 
                WHEN at.is_present THEN 'Present'
                ELSE 'Absent'
            END AS attendance_status,
            pd.coach_name,
            TO_CHAR(at.created_at, 'HH24:MI:SS') AS created_time
        FROM cd.attendance_sheet at
        INNER JOIN cd.player_details pd 
            ON at.player_id = pd.player_id
        WHERE at.recorded_by_coach_id = $1
        ORDER BY at.created_at DESC;
    `;

    try {
        const result = await pool.query(query, [coachId]);
        
        if (result.rows.length === 0) {
            return res.status(404).json({ message: "No data found for this coach ID" });
        }

        res.status(200).json(result.rows);
    } catch (err) {
        console.error('Error executing query', err.stack);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// 3. Protected Route to create a schedule event
app.post('/api/schedule-addevents', authenticateToken, async (req, res) => {
  const { 
    tenant_id, 
    title, 
    event_type, 
    event_date, 
    event_time, 
    duration, 
    location, 
    team, 
    description 
  } = req.body;
  
  const coach_id = req.user.id; 
  const coach_name = req.user.name || req.user.email; 

  const query = `
    INSERT INTO cd.schedule_events (
        tenant_id,
        title,
        event_type,
        event_date,
        event_time,
        duration,
        location,
        team,
        description,
        coach_id,
        coach_name
    )
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
    RETURNING *;
  `;

  const values = [
    tenant_id,
    title,
    event_type,
    event_date,
    event_time,
    duration,
    location,
    team,
    description,
    coach_id,    
    coach_name   
  ];

  try {
    const result = await pool.query(query, values);
    res.status(201).json({
      success: true,
      message: "Event scheduled successfully",
      data: result.rows[0]
    });
  } catch (err) {
    console.error("Database Error:", err.message);
    res.status(500).json({ 
      success: false, 
      error: "Failed to insert schedule event" 
    });
  }
});

// fetch the event details API and code
app.get('/api/events-fetch/:tenant_id/:coach_id', authenticateToken, async (req, res) => {
  const { tenant_id, coach_id } = req.params;
  if (!tenant_id || !coach_id) {
    return res.status(400).json({ success: false, error: 'Missing tenant_id or coach_id' });
  }

  const queryText = `
    SELECT 
        id, 
        tenant_id, 
        title, 
        event_type, 
        event_date, 
        event_time, 
        duration, 
        team, 
        location, 
        description, 
        coach_name 
    FROM cd.schedule_events
    WHERE active = TRUE 
    AND tenant_id = $1 
    AND coach_id = $2
    ORDER BY id DESC;
  `;

  try {
    const values = [tenant_id, coach_id];
    const result = await pool.query(queryText, values);
    res.status(200).json({
      success: true,
      data: result.rows
    });
  } catch (err) {
    console.error('DB Error:', err.message);
    res.status(500).json({ 
      success: false, 
      error: 'Database error',
      message: err.message 
    });
  }
});

//update the event details API and code
app.put('/api/events-update/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { 
    title, 
    event_type, 
    team, 
    event_date, 
    event_time, 
    duration, 
    location, 
    description, 
    tenant_id: bodyTenantId
  } = req.body;
  // Accept tenant_id from request body, query param, or verified token
  const tenant_id = bodyTenantId || req.query?.tenant_id || req.user?.tenant_id || null;

  const queryText = `
    UPDATE cd.schedule_events SET 
      title = $1,    
      event_type = $2,
      team = $3,
      event_date = $4,
      event_time = $5,
      duration = $6,
      location = $7,
      description = $8
    WHERE id = $9 AND tenant_id = $10
    RETURNING *;
  `;

  const values = [
    title, 
    event_type, 
    team, 
    event_date, 
    event_time, 
    duration, 
    location, 
    description, 
    id, 
    tenant_id
  ];

  try {
    const result = await pool.query(queryText, values);

    if (result.rowCount === 0) {
      return res.status(404).json({ 
        success: false, 
        message: "Event not found or unauthorized" 
      });
    }

    res.status(200).json({
      success: true,
      message: "Event updated successfully",
      data: result.rows[0]
    });
  } catch (err) {
    console.error('Update Error:', err.message);
    res.status(500).json({ 
      success: false, 
      error: 'Database error',
      message: err.message 
    });
  }
});

//delete the event details API and code
app.delete('/api/events-delete/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  // Accept tenant_id from body, query string, or authenticated token
  const { tenant_id: bodyTenant } = req.body || {};
  const tenant_id = bodyTenant || req.query?.tenant_id || req.user?.tenant_id || null;
  const queryText = `
    UPDATE cd.schedule_events 
    SET active = FALSE 
    WHERE id = $1 AND tenant_id = $2
    RETURNING *;
  `;

  try {
    const result = await pool.query(queryText, [id, tenant_id]);

    if (result.rowCount === 0) {
      return res.status(404).json({ 
        success: false, 
        message: "Event not found or unauthorized" 
      });
    }

    res.status(200).json({
      success: true,
      message: "Event deactivated successfully",
      data: result.rows[0]
    });
  } catch (err) {
    console.error('Delete Error:', err.message);
    res.status(500).json({ 
      success: false, 
      error: 'Database error',
      message: err.message 
    });
  }
});


// The Dashboard API Endpoint
app.get('/api/dashboard/stats', authenticateToken, async (req, res) => {
  try {
    const tenantId = req.user.tenant_id;
    if (!tenantId) {
      return res.status(400).json({ success: false, error: "Tenant ID missing in token" });
    }

    const dashboardQuery = `
       WITH summary_stats AS (
          SELECT 
            (SELECT COUNT(*) as total_players FROM cd.player_details WHERE active = TRUE AND tenant_id = $1),
            (SELECT COUNT(*) AS total_coaches FROM cd.coaches_details WHERE active = TRUE AND tenant_id = $1),
            (SELECT COUNT(*) AS total_venues FROM cd.venues_data WHERE active = TRUE AND tenant_id = $1),
            (SELECT COALESCE(SUM(amount_paid), 0) as monthly_revenue FROM cd.payment_details 
             WHERE created_date >= date_trunc('month', current_date) AND tenant_id = $1),
            (SELECT COUNT(*) FROM cd.registrations_details WHERE status = 'pending' AND tenant_id = $1)
           
      ),

      recent_activities AS (
          SELECT action, name, activity_time, type FROM (
            SELECT 'New registration' AS action, name, application_date AS activity_time, 'registration' AS type
            FROM cd.registrations_details
            WHERE tenant_id = $1
            UNION ALL
            SELECT 'Payment received: ₹' || amount_paid AS action, full_name AS name, created_date AS activity_time, 'payment' AS type
            FROM cd.payment_details
            WHERE tenant_id = $1
          ) t
          ORDER BY activity_time DESC
          LIMIT 5
      ),

        goals AS (
          SELECT 
            'Registration Goal' as title, 
            (SELECT COUNT(*) FROM cd.player_details WHERE tenant_id = $1) as current_val, 
            400 as target_val
          UNION ALL
          SELECT 
            'Revenue Target', 
            (SELECT COALESCE(SUM(amount_paid), 0) FROM cd.payment_details WHERE created_date >= date_trunc('month', current_date) AND tenant_id = $1), 
            300000 
        )

      SELECT 
          (SELECT row_to_json(summary_stats) FROM summary_stats) as stats,
          (SELECT json_agg(recent_activities) FROM recent_activities) as activities,
          (SELECT json_agg(goals) FROM goals) as goals_data;
    `;
    const result = await pool.query(dashboardQuery, [tenantId]);    
    const dashboardData = result.rows[0];

    res.json({
      success: true,
      data: {
        stats: dashboardData.stats || {},
        activities: dashboardData.activities || [],
        goals_data: dashboardData.goals_data || []
      }
    });

  } catch (err) {
    console.error("Database Error:", err.message);
    res.status(500).json({ success: false, error: "Internal Server Error" });
  }
});


//show the data baar graph API and code
app.get('/api/dashboard-graph/stats', authenticateToken, async (req, res) => {
    const tenantId = req.user.tenant_id;
    const query = `
        SELECT 
            TO_CHAR(m.month, 'Mon') AS name,
            COALESCE(p.players, 0) AS players,
            COALESCE(c.coaches, 0) AS coaches
        FROM (
            SELECT generate_series(
                date_trunc('year', CURRENT_DATE),
                date_trunc('year', CURRENT_DATE) + INTERVAL '11 months',
                INTERVAL '1 month'
            ) AS month
        ) m
        LEFT JOIN (
            SELECT 
                date_trunc('month', created_at) AS month,
                COUNT(*) AS players
            FROM cd.player_details
            WHERE active = TRUE 
            AND tenant_id::text = $1::text
              AND created_at >= date_trunc('year', CURRENT_DATE)
              AND created_at <  date_trunc('year', CURRENT_DATE) + INTERVAL '1 year'
            GROUP BY 1
        ) p ON m.month = p.month
        LEFT JOIN (
            SELECT 
                date_trunc('month', create_date) AS month,
                COUNT(*) AS coaches
            FROM cd.coaches_details
            WHERE active = TRUE 
            AND tenant_id::text = $1::text
              AND create_date >= date_trunc('year', CURRENT_DATE)
              AND create_date <  date_trunc('year', CURRENT_DATE) + INTERVAL '1 year'
            GROUP BY 1
        ) c ON m.month = c.month
        ORDER BY m.month;
    `;

    try {
        const result = await pool.query(query, [tenantId]);
        res.json({ data: result.rows });
    } catch (err) {
        console.error('Database Error:', err.stack);
        res.status(500).send('Server Error');
    }
});

//show the pie chart API and code
app.get('/api/player-stats/:tenantId', authenticateToken, async (req, res) => {
  const { tenantId } = req.params;
  const query = `
    SELECT 
      INITCAP(status) AS name, 
      COUNT(*) AS value 
    FROM cd.player_details 
    WHERE tenant_id = $1 
    GROUP BY status 
    ORDER BY name;
  `;

  try {
    const result = await pool.query(query, [tenantId]);
    res.json(result.rows);
  } catch (err) {
    console.error('Database Error:', err.stack);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// Dashboard pie-chart endpoint (player status distribution)
app.get('/api/dashboard-piechart/stats', authenticateToken, async (req, res) => {
  try {
    const tenantId = req.user?.tenant_id;
    if (!tenantId) return res.status(400).json({ success: false, error: 'Tenant ID missing' });

    const query = `
        SELECT
    CASE
        WHEN status = 'pending' THEN 'Pending'
        WHEN active = TRUE THEN 'Active'
        ELSE 'Inactive'
    END AS name,
    COUNT(*) AS value
FROM cd.player_details
WHERE tenant_id = $1
GROUP BY
    CASE
        WHEN status = 'pending' THEN 'Pending'
        WHEN active = TRUE THEN 'Active'
        ELSE 'Inactive'
    END
ORDER BY name;
    `;

    const result = await pool.query(query, [tenantId]);

    // Define specific colors for statuses for better UX
    const statusColors = {
      'Active': '#22c55e',   // Green
      'Pending': '#f59e0b',  // Orange/Amber
      'Inactive': '#ef4444'  // Red
    };

    const data = result.rows.map((r) => ({
      name: r.name,
      value: Number(r.value) || 0,
      color: statusColors[r.name] || '#6366f1', // Default to Indigo if status unknown
    }));

    return res.json({ success: true, data });
  } catch (err) {
    console.error('Dashboard Pie Error:', err.stack || err.message);
    return res.status(500).json({ success: false, error: 'Internal Server Error' });
  }
});

//line chart show the API code 
// THE ROUTE (Must match /api/revenue)
app.get('/api/revenue', authenticateToken, async (req, res) => {
  const tenantId = req.user.tenant_id;
  const query = `
    SELECT
        EXTRACT(WEEK FROM created_date) 
        - EXTRACT(WEEK FROM date_trunc('month', created_date)) + 1 AS week_no,
        COALESCE(SUM(amount_paid), 0) AS revenue
    FROM cd.payment_details
    WHERE
        created_date >= date_trunc('month', CURRENT_DATE)
        AND tenant_id = $1
    GROUP BY week_no
    ORDER BY week_no;
  `;

  try {
    const result = await pool.query(query, [tenantId]);
    res.json({ success: true, data: result.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ---------------------------------------------
// START SERVER
// ---------------------------------------------
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
