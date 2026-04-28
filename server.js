require('dotenv').config();
const app = require('./src/app');

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Servidor corriendo en puerto ${PORT}`);
});

// POST
// https://proyecto-software-api-login.onrender.com/api/auth/login - LOGIN
// https://proyecto-software-api-login.onrender.com/api/auth/register - REGISTER
