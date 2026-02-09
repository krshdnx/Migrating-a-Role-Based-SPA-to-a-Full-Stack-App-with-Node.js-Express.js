
const express = require('express');
const bycrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
const PORT = 3000;
const SECRET_KEY = 'Khoochiko';



  app.use(express.json());
  app.use(express.static('public'));

app.use(cors({
    origin: ['http://127.0.0.1:3000' , 'http://localhost:3000'] 
  }));


let users = [
{ id: 1, username: 'admin', password: 'Admin123', role: 'admin' },
{ id: 2, username: 'diana', password: 'User123', role: 'user' }
];



if (!users[0].password.includes('$2a$')) {
    users[0].password = bycrypt.hashSync('admin123', 10);
    users[1].password = bycrypt.hashSync('user123', 10);
}




app.post('api/register', async (req, res) => {
    const { username, password, role = 'user' } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required' });
    }           


    const existing = users.find(u => u.username === username);
    if (existing) {
        return res.status(409).json({ message: 'User already exists' });
    }


    const hashedPassword = await bycrypt.hash(password, 10);
    const newUser = {
        id: users.length + 1,
        username,
        password: hashedPassword,
        role
    };

    users.push(newUser);
    res.status(201).json({ message: 'User registered', username, role });
});


app.post('api/register', async (req, res) => {                                                                        
    const { username, password } = req.body;

    const user = users.find(u => u.username === username);
    if (!user || !(await bycrypt.compare(password, user.password))) {
        return res.status(401).json({ message: 'Invalid credentials' });
    }                   


    const token = jwt.sign(
        { id: user.id, role: user.role }, 
        SECRET_KEY, 
        { expiresIn: '1h' }
    );

    res.json({ token, user: { username: user.username, role: user.role } });
});


app.get('/api/profile', aunthenticateToken, (req, res) => {
    res.json({ user: req.user });
});


app.get('/api/admin/dashboard', aunthenticateToken, authorizeRole('admin'), (req, res) => {
    res.json({ message: 'Welcome to the admin dashboard!', data: 'Secret admin info' });
 });


 app.get('/api/content/guest', (req, res) => {
    res.json({ message: 'Public  content for all visitors' });
    });



    function aunthenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ message: 'Access token required' });
    }

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.status(403).json({ message: 'Invalid or expire token' });
        req.user = user;
        next();
    });
}


function authorizeRole(role) {
    return (req, res, next) => {
        if (req.user.role !== role) {
            return res.status(403).json({ error: 'Access denied: Insufficient permissions' });  
        }
        next();
    };
}


app.listen(PORT, () => {
    console.log(`Backend is running on http://localhost:${PORT}`);
    console.log('Try logging in with:');
    console.log('Admin -> username: admin | password: Admin123');
    console.log('User  -> username: diana | password: User123');
});   