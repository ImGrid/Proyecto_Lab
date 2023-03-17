const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const cookieParser = require("cookie-parser");

const app = express();

// Configuración de la llave secreta
const secretKey = "SEPTIMO_SEMESTRE";

// Configuración de tiempo de expiración
const expirationTime = 900; // 15 minutos en segundos

// Configuración del middleware
app.use(express.json());
app.use(cookieParser());

// Simulación de una base de datos de usuarios
const users = [
  { username: "admin1", password: "$2a$10$5Y5GmUh5ilZD5m6XhU6JQeLapF8yv5K81O1.gIuKjW/eV7Jv47O9m" }, // Contraseña: "password1"
  { username: "admin2", password: "$2a$10$6Z1BgsK5z5C5f5kRNMKj9eD71FKpy8AKv/E6l1KZw4.Bq3Pxt20dS" } // Contraseña: "admin1234"
];

// Endpoint para autenticar al usuario
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  // Busca al usuario en la base de datos
  const user = users.find(user => user.username === username);

  if (!user) {
    return res.status(401).json({ message: "Credenciales inválidas" });
  }

  try {
    // Compara la contraseña proporcionada por el usuario con el hash almacenado en la base de datos
    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      return res.status(401).json({ message: "Credenciales inválidas" });
    }

    // Si el usuario y la contraseña son válidos, crea el token JWT
    const token = jwt.sign({ username }, secretKey, { expiresIn: expirationTime });

    // Configura una cookie para almacenar el token
    res.cookie("token", token, { maxAge: expirationTime * 1000, httpOnly: true });

    // Retorna una respuesta exitosa con el token
    res.status(200).json({ message: "Autenticación exitosa", token });
  } catch (err) {
    // Retorna un error si hay un problema con la comparación de contraseñas
    res.status(500).json({ message: "Ha ocurrido un error" });
  }
});

// Endpoint para validar el token JWT
app.get("/protected", async (req, res) => {
  const token = req.cookies.token;

  if (!token) {
    return res.status(401).json({ message: "No se encontró el token" });
  }

  try {
    // Verifica y decodifica el token JWT
    const decoded = jwt.verify(token, secretKey);

    // Retorna una respuesta exitosa con los datos
    res.status(200).json({ message: "Autenticación exitosa", username: decoded.username });
  } catch (err) {
    // Retorna un error si el token no es válido
    res.status(401).json({ message: "Token inválido" });
  }
});

// Inicia el servidor en el puerto 3000
app.listen(3000, () => console.log("Servidor iniciado en el puerto 3000"));
