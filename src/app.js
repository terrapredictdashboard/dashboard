const express = require('express');
const session = require('express-session');
const helmet = require('helmet');
const path = require('path');
const { auth, requiresAuth } = require('express-openid-connect');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const config = require('./config');
const { notFound, errorHandler } = require('./errorHandler');
const logger = require('./logger');
const { lookUp } = require("geojson-places");
const axios = require('axios');

const app = express();

// Database setup
const db = new sqlite3.Database('./terrapredict.db', (err) => {
  if (err) {
    console.error(err.message);
  }
  logger.info('Connected to the SQLite database.');
});

db.run(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  auth0_id TEXT UNIQUE,
  nombre TEXT,
  apellido TEXT,
  compania TEXT,
  empleados TEXT,
  correo TEXT UNIQUE,
  telefono TEXT,
  sitio_web TEXT,
  pais TEXT,
  sector TEXT,
  services TEXT,
  setup_completed BOOLEAN DEFAULT 0
)`);

db.run(`CREATE TABLE IF NOT EXISTS zones (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  name TEXT,
  coordinates TEXT,
  geojson TEXT,
  microclimates TEXT,
  microclimates_loading BOOLEAN DEFAULT 1,
  FOREIGN KEY (user_id) REFERENCES users(id)
)`);

db.run(`CREATE TABLE IF NOT EXISTS notifications (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  message TEXT,
  type TEXT,
  read BOOLEAN DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id)
)`);

// Middleware configuration
// app.use(helmet()); // Comenta esta línea temporalmente
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, '../public')));


//Helper function to get user ID from auth0 ID
function getUserId(auth0Id) {
  return new Promise((resolve, reject) => {
    db.get('SELECT id FROM users WHERE auth0_id = ?', [auth0Id], (err, row) => {
      if (err) {
        reject(err);
      } else if (!row) {
        reject(new Error('User not found'));
      } else {
        resolve(row.id);
      }
    });
  });
}

// Session configuration
app.use(session({
  secret: config.sessionSecret,
  resave: false,
  saveUninitialized: true
}));

// Auth0 configuration
app.use(auth({
  authRequired: false,
  auth0Logout: true,
  secret: config.auth0ClientSecret,
  baseURL: 'https://dashboard-exuw.onrender.com',
  clientID: config.auth0ClientId,
  issuerBaseURL: `https://${config.auth0Domain}`,
  routes: {
    login: false,
  },
}));

// Routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

app.get('/api/auth/status', (req, res) => {
  res.json({
    isAuthenticated: req.oidc.isAuthenticated(),
    user: req.oidc.user
  });
});

app.get('/login', (req, res) => {
  res.oidc.login({
    returnTo: '/dashboard'
  });
});

app.get('/dashboard', requiresAuth(), (req, res) => {
  const auth0Id = req.oidc.user.sub;
  db.get('SELECT setup_completed FROM users WHERE auth0_id = ?', [auth0Id], (err, row) => {
    if (err) {
      logger.error('Error checking setup status:', err);
      return res.status(500).json({ error: 'Internal server error' });
    }
    if (!row || !row.setup_completed) {
      return res.redirect('/setup');
    }
    res.sendFile(path.join(__dirname, '../public/dashboard.html'));
  });
});

app.get('/dashboard/prediccion-de-microclimas', requiresAuth(), (req, res) => {
  const auth0Id = req.oidc.user.sub;
  db.get('SELECT setup_completed FROM users WHERE auth0_id = ?', [auth0Id], (err, row) => {
    if (err) {
      logger.error('Error checking setup status:', err);
      return res.status(500).json({ error: 'Internal server error' });
    }
    if (!row || !row.setup_completed) {
      return res.redirect('/setup');
    }
    res.sendFile(path.join(__dirname, '../public/prediccion-de-microclimas.html'));
  });
});

app.get('/setup', requiresAuth(), (req, res) => {
  const auth0Id = req.oidc.user.sub;
  db.get('SELECT setup_completed FROM users WHERE auth0_id = ?', [auth0Id], (err, row) => {
    if (err) {
      logger.error('Error checking setup status:', err);
      return res.status(500).json({ error: 'Internal server error' });
    }
    if (row && row.setup_completed) {
      return res.redirect('/dashboard');
    }
    res.sendFile(path.join(__dirname, '../public/setup.html'));
  });
});

app.get('/api/user', requiresAuth(), (req, res) => {
  const auth0Id = req.oidc.user.sub;
  db.get('SELECT * FROM users WHERE auth0_id = ?', [auth0Id], (err, row) => {
    if (err) {
      logger.error('Error fetching user data:', err);
      return res.status(500).json({ error: 'Internal server error' });
    }
    if (!row) {
      return res.status(404).json({ error: 'User not found' });
    }
    if (row.sector) row.sector = JSON.parse(row.sector);
    if (row.services) row.services = JSON.parse(row.services);
    res.json(row);
  });
});

app.post('/api/setup', requiresAuth(), (req, res) => {
  const { nombre, apellido, compania, empleados, correo, telefono, sitio_web, pais, sector, services } = req.body;
  const auth0Id = req.oidc.user.sub;

  db.get('SELECT * FROM users WHERE auth0_id = ?', [auth0Id], (err, existingUser) => {
    if (err) {
      logger.error('Error checking existing user:', err);
      return res.status(500).json({ success: false, error: 'Internal server error' });
    }

    const query = existingUser
      ? `UPDATE users SET 
          nombre = ?, apellido = ?, compania = ?, empleados = ?, correo = ?, 
          telefono = ?, sitio_web = ?, pais = ?, sector = ?, services = ?, setup_completed = 1
          WHERE auth0_id = ?`
      : `INSERT INTO users 
          (auth0_id, nombre, apellido, compania, empleados, correo, telefono, sitio_web, pais, sector, services, setup_completed) 
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)`;

    const params = existingUser
      ? [nombre, apellido, compania, empleados, correo, telefono, sitio_web, pais, JSON.stringify(sector), JSON.stringify(services), auth0Id]
      : [auth0Id, nombre, apellido, compania, empleados, correo, telefono, sitio_web, pais, JSON.stringify(sector), JSON.stringify(services)];

    db.run(query, params, function(err) {
      if (err) {
        logger.error('Error saving user data:', err);
        return res.status(500).json({ success: false, error: err.message });
      }
      logger.info('User setup completed:', { auth0Id, nombre, apellido });
      res.json({ success: true });
    });
  });
});

// Debug route to log database contents
app.get('/api/debug/users', (req, res) => {
  db.all('SELECT * FROM users', [], (err, rows) => {
    if (err) {
      logger.error('Error fetching users:', err);
      return res.status(500).json({ error: 'Internal server error' });
    }
    logger.info('Current database contents:', rows);
    res.json(rows);
  });
});

// Función para verificar si un punto está en el mar
function isPointInSea(lat, lon) {
  const result = lookUp(lat, lon);
  return result === null;
}

// Función para calcular la distancia entre dos puntos
function calculateDistance(lat1, lon1, lat2, lon2) {
  const earthRadius = 6371; // km
  const dLat = (lat2 - lat1) * Math.PI / 180;
  const dLon = (lon2 - lon1) * Math.PI / 180;
  const a = Math.sin(dLat/2) * Math.sin(dLat/2) +
            Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) *
            Math.sin(dLon/2) * Math.sin(dLon/2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
  return earthRadius * c;
}


// Debug route to log database contents
app.get('/api/debug/users', (req, res) => {
  db.all('SELECT * FROM users', [], (err, rows) => {
    if (err) {
      logger.error('Error fetching users:', err);
      return res.status(500).json({ error: 'Internal server error' });
    }
    logger.info('Current database contents:', rows);
    res.json(rows);
  });
});

const abortControllers = new Map();

//New endpoint to handle zone creation
app.post('/api/user/zone', requiresAuth(), async (req, res) => {
  const auth0Id = req.oidc.user.sub;
  const { name, coordinates } = req.body;

  console.log('Received zone data:', { name, coordinates });

  if (!name || !coordinates || !Array.isArray(coordinates) || coordinates.length < 3) {
    return res.status(400).json({ error: 'Se requiere un nombre y al menos 3 coordenadas para definir una zona.' });
  }

  let seaPointsCount = 0;
  for (let coord of coordinates) {
    if (isPointInSea(coord[0], coord[1])) {
      seaPointsCount++;
    }
  }

  if (seaPointsCount > coordinates.length * 0.2) {
    return res.status(400).json({ error: 'La zona seleccionada incluye demasiadas áreas marítimas. Por favor, selecciona principalmente áreas terrestres.' });
  }

  const maxSize = 300; // km
  let maxDistance = 0;
  for (let i = 0; i < coordinates.length; i++) {
    for (let j = i + 1; j < coordinates.length; j++) {
      const distance = calculateDistance(
        coordinates[i][0], coordinates[i][1],
        coordinates[j][0], coordinates[j][1]
      );
      if (distance > maxDistance) {
        maxDistance = distance;
      }
    }
  }

  if (maxDistance > maxSize) {
    return res.status(400).json({ error: 'La zona seleccionada es demasiado grande. El tamaño máximo permitido es de 300km x 300km.' });
  }

  try {
    const userId = await getUserId(auth0Id);
    const zoneData = JSON.stringify(coordinates);
    const geojson = {
      type: "FeatureCollection",
      features: [{
        type: "Feature",
        properties: {},
        geometry: {
          type: "Polygon",
          coordinates: [
            coordinates.map(coord => [coord[1], coord[0]]).concat([coordinates[0].slice().reverse()])
          ]
        }
      }]
    };

    logger.debug('Saving user zone:', { auth0Id, name, zoneData, geojson });

    db.run('INSERT INTO zones (user_id, name, coordinates, geojson, microclimates_loading) VALUES (?, ?, ?, ?, 1)', 
           [userId, name, zoneData, JSON.stringify(geojson)], 
           function(err) {
      if (err) {
        logger.error('Error saving user zone:', err);
        return res.status(500).json({ success: false, error: 'Error interno del servidor al guardar la zona.' });
      }
      
      const zoneId = this.lastID;
      logger.info('User zone saved:', { auth0Id, name, zoneId });

      // Responder al cliente inmediatamente
      res.json({ success: true, zone: { id: zoneId, name, coordinates } });

      // Iniciar el proceso de obtención de microclimas en segundo plano
      logger.debug('geoJSON data to send', {geojson});
      console.log('Sending GeoJSON:', JSON.stringify({ geojson: geojson }, null, 2));
      
      fetchMicroclimateData(geojson)
        .then(microclimates => {
          db.run('UPDATE zones SET microclimates = ?, microclimates_loading = 0 WHERE id = ?', 
                 [JSON.stringify(microclimates), zoneId], 
                 (updateErr) => {
            if (updateErr) {
              logger.error('Error updating microclimate data:', updateErr);
            } else {
              logger.info('Microclimate data updated successfully for zone:', zoneId);
            }
          });
        })
        .catch(error => {
          logger.error('Error fetching microclimate data:', error);
          db.run('UPDATE zones SET microclimates_loading = 0 WHERE id = ?', [zoneId], (updateErr) => {
            if (updateErr) {
              logger.error('Error updating microclimates_loading status:', updateErr);
            }
          });
        });
    });
  } catch (error) {
    logger.error('Error getting user ID:', error);
    res.status(500).json({ success: false, error: 'Error interno del servidor al procesar la solicitud.' });
  }
});

//New endpoint to fetch all zones for a user
app.get('/api/user/zones', requiresAuth(), async (req, res) => {
  const auth0Id = req.oidc.user.sub;

  try {
    const userId = await getUserId(auth0Id);
    db.all('SELECT id, name, coordinates, microclimates, microclimates_loading FROM zones WHERE user_id = ?', [userId], (err, rows) => {
      if (err) {
        logger.error('Error fetching user zones:', err);
        return res.status(500).json({ success: false, error: 'Error interno del servidor al obtener las zonas.' });
      }
      const zones = rows.map(row => ({
        id: row.id,
        name: row.name,
        coordinates: JSON.parse(row.coordinates),
        microclimates: row.microclimates ? JSON.parse(row.microclimates) : null,
        microclimates_loading: row.microclimates_loading
      }));
      res.json({ success: true, zones });
    });
  } catch (error) {
    logger.error('Error getting user ID:', error);
    res.status(500).json({ success: false, error: 'Error interno del servidor al procesar la solicitud.' });
  }
});


// Edit zone endpoint
app.put('/api/user/zone/:id', requiresAuth(), async (req, res) => {
  const auth0Id = req.oidc.user.sub;
  const { id } = req.params;
  const { name, coordinates } = req.body;

  try {
    const userId = await getUserId(auth0Id);
    const zoneData = JSON.stringify(coordinates);
    const geojson = {
      type: "FeatureCollection",
      features: [{
        type: "Feature",
        properties: {},
        geometry: {
          type: "Polygon",
          coordinates: [
            coordinates.map(coord => [coord[1], coord[0]]).concat([coordinates[0].slice().reverse()])
          ]
        }
      }]
    };
    db.run('UPDATE zones SET name = ?, coordinates = ?, geojson = ?, microclimates_loading = 1 WHERE id = ? AND user_id = ?', 
           [name, zoneData, JSON.stringify(geojson), id, userId], 
           function(err) {
      if (err) {
        logger.error('Error updating user zone:', err);
        return res.status(500).json({ success: false, error: 'Error interno del servidor al actualizar la zona.' });
      }
      
      if (this.changes === 0) {
        return res.status(404).json({ success: false, error: 'Zona no encontrada o no pertenece al usuario.' });
      }

      // Responder al cliente inmediatamente
      res.json({ success: true, zone: { id, name, coordinates} });

      // Iniciar el proceso de obtención de microclimas en segundo plano
      fetchMicroclimateData(geojson)
        .then(microclimates => {
          db.run('UPDATE zones SET microclimates = ?, microclimates_loading = 0 WHERE id = ?', 
                 [JSON.stringify(microclimates), id], 
                 (updateErr) => {
            if (updateErr) {
              logger.error('Error updating microclimate data:', updateErr);
            }
          });
        })
        .catch(error => {
          logger.error('Error fetching microclimate data:', error);
        });
    });
  } catch (error) {
    logger.error('Error getting user ID:', error);
    res.status(500).json({ success: false, error: 'Error interno del servidor al procesar la solicitud.' });
  }
});

async function fetchMicroclimateData(geojson) {
  try {
    const response = await axios.post('https://api-i6e7.onrender.com/microclimate/divider', {
      geojson: geojson
    }, {
      headers: {
        'Content-Type': 'application/json'
      }
    });
    return response.data.microclimate_centroids;
  } catch (error) {
    console.error('Error fetching microclimate data:', error);
    throw error;
  }
}


// Delete zone endpoint
app.delete('/api/user/zone/:id', requiresAuth(), async (req, res) => {
  const auth0Id = req.oidc.user.sub;
  const zoneId = req.params.id;

  try {
    const userId = await getUserId(auth0Id);

    // Primero, verifica si la zona existe y si está en proceso de carga
    db.get('SELECT microclimates_loading FROM zones WHERE id = ? AND user_id = ?', [zoneId, userId], (err, row) => {
      if (err) {
        logger.error('Error checking zone status:', err);
        return res.status(500).json({ success: false, error: 'Error interno del servidor al verificar el estado de la zona.' });
      }

      if (!row) {
        return res.status(404).json({ success: false, error: 'Zona no encontrada o no pertenece al usuario.' });
      }

      // Si la zona está en proceso de carga, cancela la solicitud
      if (row.microclimates_loading === 1) {
        const controller = abortControllers.get(zoneId);
        if (controller) {
          controller.abort();
          abortControllers.delete(zoneId);
          logger.info('Cancelled ongoing microclimate data fetch for zone:', zoneId);
        }
      }

      // Procede con la eliminación de la zona
      db.run('DELETE FROM zones WHERE id = ? AND user_id = ?', [zoneId, userId], function(err) {
        if (err) {
          logger.error('Error deleting user zone:', err);
          return res.status(500).json({ success: false, error: 'Error interno del servidor al eliminar la zona.' });
        }
        if (this.changes === 0) {
          return res.status(404).json({ success: false, error: 'Zona no encontrada o no pertenece al usuario.' });
        }
        logger.info('User zone deleted:', { auth0Id, zoneId });
        res.json({ success: true, message: 'Zona eliminada exitosamente.' });
      });
    });
  } catch (error) {
    logger.error('Error getting user ID:', error);
    res.status(500).json({ success: false, error: 'Error interno del servidor al procesar la solicitud.' });
  }
});

app.get('/api/notifications', requiresAuth(), (req, res) => {
  const auth0Id = req.oidc.user.sub;

  db.get('SELECT id FROM users WHERE auth0_id = ?', [auth0Id], (err, row) => {
      if (err) {
          logger.error('Error fetching user id:', err);
          return res.status(500).json({ error: 'Internal server error' });
      }
      if (!row) {
          return res.status(404).json({ error: 'User not found' });
      }

      db.all('SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT 10', [row.id], (err, rows) => {
          if (err) {
              logger.error('Error fetching notifications:', err);
              return res.status(500).json({ error: 'Internal server error' });
          }
          res.json(rows);
      });
  });
});

app.post('/api/notifications', requiresAuth(), (req, res) => {
  const auth0Id = req.oidc.user.sub;
  const { type, title, message } = req.body;

  if (!type || !title || !message) {
      return res.status(400).json({ error: 'Missing required fields' });
  }

  db.get('SELECT id FROM users WHERE auth0_id = ?', [auth0Id], (err, row) => {
      if (err) {
          logger.error('Error fetching user id:', err);
          return res.status(500).json({ error: 'Internal server error' });
      }
      if (!row) {
          return res.status(404).json({ error: 'User not found' });
      }

      db.run('INSERT INTO notifications (user_id, message, type) VALUES (?, ?, ?)', 
          [row.id, `${title}: ${message}`, type], 
          function(err) {
              if (err) {
                  logger.error('Error saving notification:', err);
                  return res.status(500).json({ error: 'Internal server error' });
              }
              res.json({ success: true, id: this.lastID });
          }
      );
  });
});

app.post('/api/notifications/:id/read', requiresAuth(), (req, res) => {
  const auth0Id = req.oidc.user.sub;
  const notificationId = req.params.id;

  db.get('SELECT id FROM users WHERE auth0_id = ?', [auth0Id], (err, row) => {
      if (err) {
          logger.error('Error fetching user id:', err);
          return res.status(500).json({ error: 'Internal server error' });
      }
      if (!row) {
          return res.status(404).json({ error: 'User not found' });
      }

      db.run('UPDATE notifications SET read = 1 WHERE id = ? AND user_id = ?', [notificationId, row.id], function(err) {
          if (err) {
              logger.error('Error marking notification as read:', err);
              return res.status(500).json({ error: 'Internal server error' });
          }
          res.json({ success: true });
      });
  });
});

// Error handling
app.use(notFound);
app.use(errorHandler);

// Start server
app.listen(config.port, () => {
  logger.info(`🚀 Server running on http://localhost:${config.port}`);
});