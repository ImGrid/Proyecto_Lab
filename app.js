const express = require('express');
const app = express();
const bcryptjs = require('bcryptjs');
const jwt = require('jsonwebtoken');
const keys = require('./settings/keys');
const cookieParser = require('cookie-parser');

app.set('key', keys.key);
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(cookieParser());

app.get('/', (req, res) => {
  res.send('hola mundo');
});
app.post('/login', async (req, res) => {
    const user = req.body.user;
    const password = req.body.password;
  
    if (user === 'admin' && password === 'admin1234') {
      const passwordHash = await bcryptjs.hash(password, 10);
      const match = await bcryptjs.compare(password, passwordHash);
  
      if (match) {
        const payload = { check: true };
        const token = jwt.sign(payload, app.get('key'), {
          expiresIn: '15m',
        });
  
        res.cookie('token', token, {
          httpOnly: true,
          maxAge: 900000,
        });
  
        res.json({
          mensaje: 'autentificacion correcta',
          token: token,
          
        });
      } else {
        res.json({
          mensaje: 'Usuario o contraseña incorrecta',
        });
      }
    } else {
      res.json({
        mensaje: 'Usuario o contraseña incorrecta',
      });
    }
  });
  const verificacion = express.Router();

  verificacion.use((req, res, next) => {
    const token = req.cookies.token || req.headers['x-access-token'] || req.headers.authorization;
  
    if (!token) {
      res.status(401).send({
        error: 'es necesario un token de autentificacion',
      });
      return;
    }
  
    if (token.startsWith('Bearer ')) {
      token = token.slice(7, token.length);
    }
  
    if (token) {
      jwt.verify(token, app.get('key'), (error, decoded) => {
        if (error) {
          return res.json({
            mensaje: 'token no valido',
          });
        } else {
          req.decoded = decoded;
          next();
        }
      });
    }
  });
  
  app.get('/info', verificacion, (req, res) => {
    res.json('INFORMACION TRANSFERIDA');
  });
  
  app.listen(3000, () => {
    console.log('Servidor UP en http://localhost:3000');
  });