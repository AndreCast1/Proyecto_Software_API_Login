const supabase = require('../config/db');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

exports.register = async (req, res) => {
  const { nombre, email, password, rol } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    const { data, error } = await supabase
      .from('usuario')
      .insert([
        { nombre, email, contrasena_hash: hashedPassword, rol }
      ])
      .select();

    if (error) {
      console.error('Supabase error:', error);
      if (error.code === '23505') {
        return res.status(400).json({ error: 'Email ya existe' });
      }
      return res.status(500).json({ error: 'Error en Supabase' });
    }

    res.json({
      message: 'Usuario creado',
      user: data[0]
    });

  } catch (error) {
    console.error('Server error:', error);
    res.status(500).json({ error: 'Error en el servidor' });
  }
};

exports.login = async (req, res) => {
  const { email, password } = req.body;

  try {
    const { data: user, error } = await supabase
      .from('usuario')
      .select('*')
      .eq('email', email)
      .maybeSingle();

    if (error) {
      console.error('Supabase error:', error);
      return res.status(500).json({ error: 'Error en Supabase' });
    }

    if (!user) {
      return res.status(400).json({ error: 'Usuario no existe' });
    }

    const valid = await bcrypt.compare(password, user.contrasena_hash);

    if (!valid) {
      return res.status(400).json({ error: 'Contraseña incorrecta' });
    }

    const token = jwt.sign(
      { id: user.id_usuario, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.json({
      message: 'Login exitoso',
      token
    });

  } catch (error) {
    console.error('Server error:', error);
    res.status(500).json({ error: 'Error en el servidor' });
  }
};