const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const md5 = require('md5'); 
const jwt = require('jsonwebtoken');

const app = express();
const PORT = 3000;
const SECRET_KEY = "chave_secreta_barbearia_marcos"; // Em produção, usar variável de ambiente

app.use(express.json());
app.use(cors());

// --- 1. BANCO DE DADOS ---
const db = new sqlite3.Database('./barbearia.db', (err) => {
    if (err) console.error('Erro ao conectar no banco:', err.message);
    else console.log('Conectado ao banco de dados SQLite.');
});

// Cria as tabelas se não existirem
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        email TEXT UNIQUE,
        password TEXT,
        role TEXT DEFAULT 'client'
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS appointments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        barber_name TEXT,
        services TEXT,
        date TEXT,
        time TEXT,
        total REAL,
        status TEXT DEFAULT 'Confirmado',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        canceled_at DATETIME
    )`);

    // Cria o Admin Padrão (Senha: Barbeiro)
    const adminPass = md5("Barbeiro");
    db.run(`INSERT OR IGNORE INTO users (name, email, password, role) VALUES ('Barbeiro Chefe', 'Barbeiro2003@gmail.com', ?, 'admin')`, [adminPass]);
});

// --- 2. MIDDLEWARE DE AUTH (Segurança) ---
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ message: "Token não fornecido" });

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.status(403).json({ message: "Token inválido" });
        req.user = user;
        next();
    });
}

// --- 3. ROTAS DE LOGIN/CADASTRO ---
app.post('/login', (req, res) => {
    const { email, password } = req.body;
    const hashedPassword = md5(password);

    db.get("SELECT * FROM users WHERE email = ? AND password = ?", [email, hashedPassword], (err, user) => {
        if (err || !user) return res.status(401).json({ message: "Email ou senha incorretos" });
        
        const token = jwt.sign({ id: user.id, email: user.email, role: user.role, name: user.name }, SECRET_KEY, { expiresIn: '24h' });
        res.json({ token, user: { name: user.name, email: user.email, role: user.role } });
    });
});

app.post('/register', (req, res) => {
    const { name, email, password } = req.body;
    const hashedPassword = md5(password);

    db.run("INSERT INTO users (name, email, password) VALUES (?, ?, ?)", [name, email, hashedPassword], function(err) {
        if (err) return res.status(400).json({ message: "Email já cadastrado." });
        res.json({ message: "Usuário criado com sucesso!" });
    });
});

// --- 4. ROTAS DE AGENDAMENTO ---
app.get('/appointments', authenticateToken, (req, res) => {
    if (req.user.role === 'admin') {
        // Admin vê tudo
        const query = `SELECT a.*, u.name as clientName, u.email as clientEmail FROM appointments a JOIN users u ON a.user_id = u.id ORDER BY date DESC, time ASC`;
        db.all(query, [], (err, rows) => {
            if (err) res.status(500).json({ error: err.message });
            else res.json(rows);
        });
    } else {
        // Cliente vê só os seus
        db.all("SELECT * FROM appointments WHERE user_id = ? ORDER BY date DESC", [req.user.id], (err, rows) => {
            if (err) res.status(500).json({ error: err.message });
            else res.json(rows);
        });
    }
});

app.post('/appointments', authenticateToken, (req, res) => {
    const { barber_name, services, date, time, total } = req.body;

    // VERIFICAÇÃO DE CONFLITO (Double Booking)
    db.get("SELECT id FROM appointments WHERE barber_name = ? AND date = ? AND time = ? AND status != 'Cancelado'", 
    [barber_name, date, time], (err, row) => {
        if (row) return res.status(409).json({ message: "Horário já reservado por outro cliente." });

        const query = `INSERT INTO appointments (user_id, barber_name, services, date, time, total) VALUES (?, ?, ?, ?, ?, ?)`;
        db.run(query, [req.user.id, barber_name, services, date, time, total], function(err) {
            if (err) res.status(500).json({ error: err.message });
            else res.json({ message: "Agendado com sucesso!" });
        });
    });
});

app.put('/appointments/:id', authenticateToken, (req, res) => {
    const { status } = req.body;
    const id = req.params.id;

    if (req.user.role === 'admin') {
        let query = "UPDATE appointments SET status = ? WHERE id = ?";
        if (status === 'Cancelado') query = "UPDATE appointments SET status = ?, canceled_at = CURRENT_TIMESTAMP WHERE id = ?";
        
        db.run(query, [status, id], function(err) {
            if (err) res.status(500).json({ error: err.message });
            else res.json({ message: "Status atualizado" });
        });
    } else {
        // Cliente cancelando
        if (status !== 'Cancelado') return res.status(403).json({ message: "Não autorizado" });
        
        db.run("UPDATE appointments SET status = ?, canceled_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?", 
        [status, id, req.user.id], function(err) {
            if (this.changes === 0) res.status(404).json({ message: "Agendamento não encontrado" });
            else res.json({ message: "Cancelado com sucesso" });
        });
    }
});

// --- 5. ROTA PÚBLICA DE DISPONIBILIDADE ---
app.get('/availability', (req, res) => {
    const { date, barber } = req.query;
    db.all("SELECT time FROM appointments WHERE date = ? AND barber_name = ? AND status != 'Cancelado'", [date, barber], (err, rows) => {
        if (err) res.status(500).json({ error: err.message });
        else res.json(rows.map(r => r.time));
    });
});

// Iniciar Servidor
app.listen(PORT, () => {
    console.log(`Servidor rodando em http://localhost:${PORT}`);
    console.log('Banco de dados criado/conectado com sucesso.');
});