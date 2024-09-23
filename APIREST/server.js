require('dotenv').config();

const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');

const app = express();
app.use(bodyParser.json());

const users = [];  // Esto simula una base de datos pero no es lo correcto.

const JWT_SECRET = process.env.JWT_SECRET || 'mi_super_secreto';

// Función para autenticar y proteger rutas
function authenticateToken(req, res, next) {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.sendStatus(401);

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

// 1. Registro de usuario
app.post('/api/register', async (req, res) => {
    const { username, password, email } = req.body;

    // Verifica si el usuario ya existe
    if (users.find(user => user.username === username)) {
        return res.status(400).json({ message: 'El usuario ya existe' });
    }

    // Cifra la contraseña antes de guardarla
    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = { username, email, password: hashedPassword };
    users.push(newUser);

    res.status(201).json({ message: 'Usuario registrado exitosamente', user: newUser });
});

// 2. Inicio de sesión
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;

    const user = users.find(user => user.username === username);
    if (!user) {
        return res.status(400).json({ message: 'Usuario no encontrado' });
    }

    // Verifica la contraseña
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
        return res.status(400).json({ message: 'Contraseña incorrecta' });
    }

    // Genera un token JWT
    const token = jwt.sign({ username: user.username }, JWT_SECRET, { expiresIn: '1h' });

    res.status(200).json({ message: 'Inicio de sesión exitoso', token });
});

// 3. Recurso protegido
app.get('/api/protected-resource', authenticateToken, (req, res) => {
    res.status(200).json({ message: 'Acceso al recurso protegido', user: req.user });
});

// 4. Cierre de sesión 
app.post('/api/logout', authenticateToken, (req, res) => {
    
    res.status(200).json({ message: 'Cierre de sesión exitoso' });
});

// Inicializa el servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Servidor corriendo en el puerto ${PORT}`);
});