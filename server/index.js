const express = require('express');
const { Pool } = require('pg');
require('dotenv').config();
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken'); // Библиотека для токенов

const app = express();
const PORT = 5000;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});
const crypto = require('crypto');
const algorithm = 'aes-256-cbc';
// Ключ ровно 32 символа. Обязательно сохрани его, иначе сообщения не прочитать!
const secretKey = Buffer.from('12345678901234567890123456789012', 'utf-8'); 

function encrypt(text) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(algorithm, secretKey, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return iv.toString('hex') + ':' + encrypted;
}

function decrypt(text) {
    try {
        const parts = text.split(':');
        const iv = Buffer.from(parts.shift(), 'hex');
        const encryptedText = Buffer.from(parts.join(':'), 'hex');
        const decipher = crypto.createDecipheriv(algorithm, secretKey, iv);
        let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    } catch (e) {
        return "[Старое или нечитаемое сообщение]"; 
    }
}
app.use(cors());
app.use(express.json());
// Функция-фильтр для проверки токена
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ error: 'Доступ запрещен (нет токена)' });

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Токен недействителен' });
        req.user = user; // Сохраняем данные юзера в запрос
        next(); // Идем дальше к обработке поста
    });
};
// 1. ПРОВЕРКА БАЗЫ
app.get('/test-db', async (req, res) => {
    try {
        const result = await pool.query('SELECT NOW()');
        res.json({ success: true, db_time: result.rows[0].now });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

// 2. РЕГИСТРАЦИЯ
app.post('/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        const newUser = await pool.query(
            'INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3) RETURNING id, username',
            [username, email, hashedPassword]
        );

        res.status(201).json({ success: true, user: newUser.rows[0] });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: 'Ошибка регистрации' });
    }
});

// 3. ЛОГИН (АВТОРИЗАЦИЯ) — НОВЫЙ БЛОК
app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Ищем юзера
        const user = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        
        if (user.rows.length === 0) {
            return res.status(401).json({ success: false, error: 'Пользователь не найден' });
        }

        // Проверяем пароль
        const validPassword = await bcrypt.compare(password, user.rows[0].password_hash);
        
        if (!validPassword) {
            return res.status(401).json({ success: false, error: 'Неверный пароль' });
        }

        // Создаем токен (паспорт)
        const token = jwt.sign(
            { id: user.rows[0].id, username: user.rows[0].username },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({ success: true, token, username: user.rows[0].username, userId: user.rows[0].id });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: 'Ошибка сервера при входе' });
    }
});

// 4. ПОЛУЧИТЬ ВСЕХ ЮЗЕРОВ
app.get('/users', async (req, res) => {
    try {
        const result = await pool.query('SELECT id, username, email FROM users');
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});
// ДОБАВИТЬ ЭТОТ РОУТ ДЛЯ СОЗДАНИЯ ПОСТОВ
app.post('/posts', authenticateToken, async (req, res) => {
    try {
        const { content } = req.body;
        const userId = req.user.id; // Берем ID из токена

        const result = await pool.query(
            'INSERT INTO posts (user_id, content) VALUES ($1, $2) RETURNING *',
            [userId, content]
        );

        res.status(201).json(result.rows[0]);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Ошибка при создании поста' });
    }
});
// 5. СОЗДАТЬ ПОСТ
// Теперь создать пост можно ТОЛЬКО с токеном
app.get('/posts', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT p.*, u.username, 
            (SELECT COUNT(*)::int FROM likes WHERE post_id = p.id) as likes_count,
            (SELECT COUNT(*)::int FROM comments WHERE post_id = p.id) as comments_count
            FROM posts p 
            JOIN users u ON p.user_id = u.id 
            ORDER BY p.created_at DESC
        `);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});
app.post('/posts/:id/like', authenticateToken, async (req, res) => {
    const postId = req.params.id;
    const userId = req.user.id;
    try {
        const existingLike = await pool.query(
            'SELECT * FROM likes WHERE user_id = $1 AND post_id = $2',
            [userId, postId]
        );

        if (existingLike.rows.length > 0) {
            await pool.query('DELETE FROM likes WHERE user_id = $1 AND post_id = $2', [userId, postId]);
            res.json({ liked: false });
        } else {
            await pool.query('INSERT INTO likes (user_id, post_id) VALUES ($1, $2)', [userId, postId]);
            res.json({ liked: true });
        }
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});
app.get('/posts/:id/comments', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT c.*, u.username 
            FROM comments c 
            JOIN users u ON c.user_id = u.id 
            WHERE c.post_id = $1 
            ORDER BY c.created_at ASC`, [req.params.id]);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});
app.post('/posts/:id/comments', authenticateToken, async (req, res) => {
    try {
        const { content } = req.body;
        const postId = req.params.id;
        const userId = req.user.id;

        const result = await pool.query(
            'INSERT INTO comments (post_id, user_id, content) VALUES ($1, $2, $3) RETURNING *',
            [postId, userId, content]
        );
        res.json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});
app.delete('/posts/:id', authenticateToken, async (req, res) => {
    try {
        const postId = req.params.id;
        const userId = req.user.id; // Извлекаем из токена

        // Пытаемся удалить пост, только если он принадлежит этому пользователю
        const result = await pool.query(
            'DELETE FROM posts WHERE id = $1 AND user_id = $2',
            [postId, userId]
        );

        if (result.rowCount === 0) {
            return res.status(403).json({ error: "Удалять можно только свои посты" });
        }

        res.json({ success: true, message: "Пост удален" });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});
// ОТПРАВИТЬ СООБЩЕНИЕ
app.post('/messages', authenticateToken, async (req, res) => {
    const { receiver_name, content } = req.body;
    const sender_id = req.user.id;
    try {
        const receiver = await pool.query('SELECT id FROM users WHERE username = $1', [receiver_name]);
        if (receiver.rows.length === 0) return res.status(404).json({ error: 'Юзер не найден' });

        const encryptedContent = encrypt(content); // Шифруем

        await pool.query(
            'INSERT INTO messages (sender_id, receiver_id, content) VALUES ($1, $2, $3)',
            [sender_id, receiver.rows[0].id, encryptedContent]
        );
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});
app.get('/messages/:username', authenticateToken, async (req, res) => {
    const myId = req.user.id;
    const otherUser = req.params.username;
    try {
        const result = await pool.query(`
            SELECT m.*, u.username as sender_name 
            FROM messages m
            JOIN users u ON m.sender_id = u.id
            WHERE (m.sender_id = $1 AND m.receiver_id = (SELECT id FROM users WHERE username = $2))
               OR (m.sender_id = (SELECT id FROM users WHERE username = $2) AND m.receiver_id = $1)
            ORDER BY m.created_at ASC`, [myId, otherUser]);

        const decryptedMessages = result.rows.map(m => ({
            ...m,
            content: decrypt(m.content) // Расшифровываем
        }));

        await pool.query(`
            UPDATE messages SET is_read = TRUE 
            WHERE receiver_id = $1 AND sender_id = (SELECT id FROM users WHERE username = $2)`, 
            [myId, otherUser]);

        res.json(decryptedMessages);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});
app.get('/unread-count', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT COUNT(*) FROM messages WHERE receiver_id = $1 AND is_read = FALSE',
            [req.user.id]
        );
        res.json({ count: parseInt(result.rows[0].count) });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});
// ПОЛУЧИТЬ СПИСОК ВСЕХ ДИАЛОГОВ
app.get('/chats', authenticateToken, async (req, res) => {
    try {
        const myId = req.user.id;
        
        // Сложный запрос: берем всех собеседников и считаем непрочитанные от них
        const chats = await pool.query(
            `SELECT 
                u.username, 
                COUNT(m.id) FILTER (WHERE m.receiver_id = $1 AND m.is_read = FALSE) as unread_count
             FROM users u
             JOIN messages m ON (u.id = m.sender_id OR u.id = m.receiver_id)
             WHERE (m.sender_id = $1 OR m.receiver_id = $1) AND u.id != $1
             GROUP BY u.username`, 
            [myId]
        );
        
        res.json(chats.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});
app.listen(PORT, () => {
    console.log('Сервер запущен: http://localhost:5000');
});