import express from "express";
import postgres from "postgres";
import multer from "multer";
import cors from "cors";
import crypto from "crypto";
import rateLimit, { ipKeyGenerator } from "express-rate-limit";
import "dotenv/config";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

const app = express();
const PORT = process.env.PORT || 5000;

const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET || "your-default-jwt-secret";

if (!DATABASE_URL) {
    console.error("Error: DATABASE_URL must be set in .env");
    process.exit(1);
}

const sql = postgres(DATABASE_URL);

async function setupDatabase() {
    try {
        console.log("Checking and creating database tables...");

        await sql`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                api_key TEXT UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT NOW()
            )
        `;

        await sql`
            CREATE TABLE IF NOT EXISTS files (
                id SERIAL PRIMARY KEY,
                user_id INT NOT NULL,
                filename TEXT NOT NULL,
                hash TEXT UNIQUE NOT NULL,
                size BIGINT NOT NULL,
                storage_path TEXT NOT NULL,
                uploaded_at TIMESTAMP DEFAULT NOW(),
                content TEXT NOT NULL,
                
                CONSTRAINT fk_user
                    FOREIGN KEY(user_id) 
                    REFERENCES users(id) 
                    ON DELETE CASCADE
            )
        `;

        console.log("Database tables are ready.");
    } catch (error) {
        console.error("Error setting up database:", error);
        process.exit(1);
    }
}

app.use(cors());
app.use(express.json());

const storage = multer.memoryStorage();
const upload = multer({
    storage: storage,
    limits: { fileSize: 10 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        cb(null, true);
    },
});

const verifyToken = (req, res, next) => {
    const token = req.headers["authorization"]?.split(" ")[1];
    if (!token)
        return res
            .status(401)
            .json({ error: "Access denied, no token provided" });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: "Invalid token" });
        req.user = user;
        next();
    });
};

const verifyApiKey = async (req, res, next) => {
    const apiKey = req.headers["x-api-key"];
    if (!apiKey) return res.status(401).json({ error: "API key required" });

    try {
        const [user] = await sql`
            SELECT id, username 
            FROM users 
            WHERE api_key = ${apiKey}
        `;

        if (!user) {
            return res.status(401).json({ error: "Invalid API key" });
        }

        req.user = user;
        next();
    } catch (e) {
        console.error("Database error fetching user (verifyApiKey):", e);
        return res
            .status(500)
            .json({ error: "Internal server error during API key lookup." });
    }
};

const apiRateLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message:
        "Too many upload requests from this IP/User, please try again after 15 minutes",
    keyGenerator: (req, res) => {
        if (req.user && req.user.id) {
            return `user_${req.user.id}`;
        }
        return ipKeyGenerator(req, res);
    },
    statusCode: 429,
    standardHeaders: true,
    legacyHeaders: false,
});
app.get('/', (req,res) => {
    return res.status(200).json({ 
        status: "online", 
        message: "you can use this route to uptime your server using online tools like betterstack or uptimerobot etc" 
    })
})

app.post("/api/signup", async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password)
        return res
            .status(400)
            .json({ error: "Username and password required" });

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const apiKey = crypto.randomBytes(32).toString("hex");

        const [user] = await sql`
            INSERT INTO users (username, password_hash, api_key) 
            VALUES (${username}, ${hashedPassword}, ${apiKey})
            RETURNING id
        `;

        const token = jwt.sign({ id: user.id, username }, JWT_SECRET, {
            expiresIn: "7d",
        });

        res.json({
            message: "User created and logged in",
            token,
            api_key: apiKey,
            user: { id: user.id, username },
        });
    } catch (e) {
        console.error("Signup error:", e);
        if (e.code === "23505") {
            return res.status(400).json({ error: "Username already taken" });
        }
        return res
            .status(500)
            .json({ error: "Failed to create user due to a server error." });
    }
});

app.post("/api/login", async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password)
        return res
            .status(400)
            .json({ error: "Username and password required" });

    try {
        const [user] = await sql`
            SELECT id, username, password_hash, api_key 
            FROM users 
            WHERE username = ${username}
        `;

        if (!user || !(await bcrypt.compare(password, user.password_hash))) {
            return res.status(401).json({ error: "Invalid credentials" });
        }

        const token = jwt.sign(
            { id: user.id, username: user.username },
            JWT_SECRET,
            { expiresIn: "7d" },
        );

        res.json({
            token,
            api_key: user.api_key,
            user: { id: user.id, username: user.username },
        });
    } catch (e) {
        console.error("Login error:", e);
        return res
            .status(500)
            .json({ error: "Internal server error during login." });
    }
});


const handleFileUpload = async (req, res) => {
    if (!req.file) return res.status(400).json({ error: "No file uploaded" });

    const userId = req.user.id;
    const hash = crypto.randomBytes(16).toString("hex");
    const file = req.file;

    const storagePath = `db/${userId}/${hash}/${file.originalname}`;
    
    const base64Content = file.buffer.toString("base64");
    const fileSize = file.size;

    try {
        await sql`
            INSERT INTO files (user_id, filename, hash, size, storage_path, content) 
            VALUES (${userId}, ${file.originalname}, ${hash}, ${fileSize}, ${storagePath}, ${base64Content})
        `;

        res.json({ message: "File uploaded", hash });
    } catch (e) {
        console.error("Database insert error:", e);
        return res
            .status(500)
            .json({ error: "Upload failed, could not save file metadata or content" });
    }
};

app.post(
    "/api/upload",
    verifyToken,
    apiRateLimiter,
    upload.single("file"),
    handleFileUpload,
);

app.post(
    "/api/upload-api",
    verifyApiKey,
    apiRateLimiter,
    upload.single("file"),
    handleFileUpload,
);

app.get("/api/files", verifyToken, async (req, res) => {
    const userId = req.user.id;
    try {
        const data = await sql`
            SELECT id, filename, hash, size, uploaded_at 
            FROM files 
            WHERE user_id = ${userId}
        `;
        res.json(data);
    } catch (e) {
        console.error("Failed to fetch files:", e);
        return res.status(500).json({ error: "Failed to fetch files" });
    }
});

app.get("/api/files-api", verifyApiKey, async (req, res) => {
    const userId = req.user.id;
    try {
        const data = await sql`
            SELECT id, filename, hash, size, uploaded_at 
            FROM files 
            WHERE user_id = ${userId}
        `;
        res.json(data);
    } catch (e) {
        console.error("Failed to fetch files:", e);
        return res.status(500).json({ error: "Failed to fetch files" });
    }
});

app.put("/api/files/:id", verifyToken, async (req, res) => {
    const { id } = req.params;
    const { newName } = req.body;
    const userId = req.user.id;

    if (!newName) return res.status(400).json({ error: "New name required" });

    try {
        const [file] = await sql`
            SELECT storage_path, filename 
            FROM files 
            WHERE id = ${id} AND user_id = ${userId}
        `;

        if (!file) {
            return res.status(404).json({ error: "File not found" });
        }

        if (file.filename === newName) {
            return res.json({ message: "File already has that name" });
        }

        const oldPath = file.storage_path;
        const pathParts = oldPath.split("/");
        pathParts[pathParts.length - 1] = newName;
        const newPath = pathParts.join("/");

        const updated = await sql`
            UPDATE files 
            SET filename = ${newName}, storage_path = ${newPath} 
            WHERE id = ${id} AND user_id = ${userId}
        `;

        if (updated.length === 0) {
            console.error("DB update failed after move (0 rows affected).");
            return res
                .status(500)
                .json({ error: "Failed to update file metadata" });
        }

        res.json({ message: "File renamed" });
    } catch (e) {
        console.error("Rename error:", e);
        return res
            .status(500)
            .json({ error: "Internal server error during rename." });
    }
});

app.delete("/api/files/:id", verifyToken, async (req, res) => {
    const { id } = req.params;
    const userId = req.user.id;

    try {
        const [deleted] = await sql`
            DELETE FROM files 
            WHERE id = ${id} AND user_id = ${userId}
            RETURNING storage_path
        `;

        if (!deleted) {
            return res
                .status(404)
                .json({ error: "File not found or failed to delete" });
        }

        res.json({ message: "File deleted" });
    } catch (e) {
        console.error("Delete error:", e);
        return res
            .status(500)
            .json({ error: "Internal server error during deletion." });
    }
});

app.get("/api/files/:id/content", verifyToken, async (req, res) => {
    const { id } = req.params;
    const userId = req.user.id;

    try {
        const [file] = await sql`
            SELECT content, filename 
            FROM files 
            WHERE id = ${id} AND user_id = ${userId}
        `;

        if (!file) {
            return res.status(404).json({ error: "File not found" });
        }
        
        const base64Content = file.content || ""; 
        
        res.json({ content: base64Content, filename: file.filename });

    } catch (e) {
        console.error("Get content error:", e);
        return res
            .status(500)
            .json({ error: "Internal server error during content retrieval." });
    }
});


app.put("/api/files/:id/content", verifyToken, async (req, res) => {
    const { id } = req.params;
    const { content } = req.body;
    const userId = req.user.id;

    if (content === undefined) {
        return res.status(400).json({ error: "Content required" });
    }

    const newBase64Content = content;
    
    const buffer = Buffer.from(newBase64Content, "base64");

    try {
        const [file] = await sql`
            SELECT id 
            FROM files 
            WHERE id = ${id} AND user_id = ${userId}
        `;

        if (!file) {
            return res.status(404).json({ error: "File not found" });
        }

        await sql`
            UPDATE files 
            SET size = ${buffer.length}, content = ${newBase64Content} 
            WHERE id = ${id}
        `;

        res.json({ message: "File content updated" });
    } catch (e) {
        console.error("Update content error:", e);
        return res
            .status(500)
            .json({ error: "Internal server error during content update." });
    }
});

app.get("/download/:hash", async (req, res) => {
    const { hash } = req.params;

    try {
        const [file] = await sql`
            SELECT content, filename 
            FROM files 
            WHERE hash = ${hash}
        `;

        if (!file) {
            return res.status(404).json({ error: "File not found" });
        }
        
        const base64Content = file.content; 
        if (!base64Content) {
             return res.status(500).json({ error: "File content missing from database" });
        }
        
        const fileContentBuffer = Buffer.from(base64Content, "base64"); 

        res.setHeader(
            "Content-Disposition",
            `attachment; filename="${file.filename}"`,
        );
        res.setHeader("Content-Type", "application/octet-stream");
        
        res.send(fileContentBuffer); 
    } catch (e) {
        console.error("Download error:", e);
        return res
            .status(500)
            .json({ error: "Internal server error during download." });
    }
});

async function startServer() {
    await setupDatabase(); 
    
    app.listen(PORT, () => {
        console.log(`Server running on port ${PORT}`);
    });
}

startServer();
