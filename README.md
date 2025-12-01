# Node.js Secure File Upload API

A secure REST API built with Express and PostgreSQL. This application handles user authentication (JWT & API Keys), manages file uploads (stored directly in the database as Base64), and implements rate limiting for security.

## 🚀 Features

* **User System:** Secure Signup and Login with password hashing (`bcrypt`).
* **Authentication:** Dual support for `Bearer Token` (JWT) and `x-api-key`.
* **Database Storage:** Files are stored within PostgreSQL tables (not on the disk).
* **Security:**
    * IP and User-based Rate Limiting.
    * CORS protection.
    * Input validation.
* **File Operations:** Upload, Download (via public hash), Rename, Delete, and Update Content.

## 📋 Prerequisites

* **Node.js** (v18+ recommended)
* **PostgreSQL Database**

## 🛠️ Installation & Setup

1.  **Clone the repository:**
    ```bash
    git clone <your-repo-url>
    cd <project-folder>
    ```

2.  **Install dependencies:**
    ```bash
    npm install
    ```

3.  **Configure Environment Variables:**
    Create a `.env` file in the root directory and add the following:

    ```ini
    PORT=5000
    # Replace with your actual Postgres connection string
    DATABASE_URL=postgres://username:password@localhost:5432/your_database_name
    JWT_SECRET=super_secret_random_key_here
    ```

4.  **Start the Server:**
    
    * **Development (Auto-reload):**
        ```bash
        npm run dev
        ```
    * **Production:**
        ```bash
        node main.js
        ```

> **Note:** The application attempts to create the necessary database tables (`users` and `files`) automatically on startup.

## 🔌 API Documentation

### Status Check
* **GET** `/` - Check if the server is online.

### Authentication

| Method | Endpoint | Body | Description |
| :--- | :--- | :--- | :--- |
| **POST** | `/api/signup` | `{ "username": "...", "password": "..." }` | Register a new user. Returns Token & API Key. |
| **POST** | `/api/login` | `{ "username": "...", "password": "..." }` | Login to receive a Token. |

### Authorization Headers
For the endpoints below, you must include one of the following headers:
* **JWT:** `Authorization: Bearer <your_token>`
* **API Key:** `x-api-key: <your_api_key>`

### File Management

| Method | Endpoint | Description | Auth Required |
| :--- | :--- | :--- | :--- |
| **POST** | `/api/upload` | Upload a file (Form-data: `file`). Max 10MB. | 🔒 Token |
| **POST** | `/api/upload-api` | Upload a file (Form-data: `file`). | 🔑 API Key |
| **GET** | `/api/files` | Get list of all uploaded files. | 🔒 Token |
| **GET** | `/api/files-api` | Get list of all uploaded files. | 🔑 API Key |
| **PUT** | `/api/files/:id` | Rename file. Body: `{ "newName": "..." }` | 🔒 Token |
| **DELETE** | `/api/files/:id` | Delete a file permanently. | 🔒 Token |
| **GET** | `/api/files/:id/content` | Get raw Base64 content of a file. | 🔒 Token |
| **PUT** | `/api/files/:id/content` | Update file content. Body: `{ "content": "base64..." }` | 🔒 Token |

### Public Download
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| **GET** | `/download/:hash` | Public download link using the file hash (no auth required). |

## 📦 Deployment

### Using PM2 (Recommended)
To keep the app running permanently on a server (like VPS/EC2):

1.  Install PM2: `npm install -g pm2`
2.  Start the app: `pm2 start main.js --name "file-api"`
3.  Save process: `pm2 save`

### Database Note
This app stores file binaries in the database. Ensure your PostgreSQL instance has enough storage space, as the database size will grow linearly with file uploads.

## ⚠️ Limits
* **File Size:** Max 10MB per upload.
* **Rate Limit:** 100 requests per 15 minutes per IP/User.
