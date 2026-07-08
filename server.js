const express = require('express');
const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();

// ===== ПРАВИЛЬНЫЙ CORS =====
app.use(cors({
    origin: '*', // Разрешаем все источники для теста
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true
}));

app.use(express.json());

// ===== ПОДКЛЮЧЕНИЕ К SUPABASE =====
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_KEY;

if (!supabaseUrl || !supabaseKey) {
    console.error('❌ Ошибка: SUPABASE_URL или SUPABASE_KEY не заданы!');
    process.exit(1);
}

const supabase = createClient(supabaseUrl, supabaseKey);

const JWT_SECRET = process.env.JWT_SECRET || 'cybermode_super_secret_2026';
const SUPER_ADMIN_EMAIL = 'cyber@mail.ru';

// ===== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ =====
function generateToken(userId) {
    return jwt.sign({ userId }, JWT_SECRET, { expiresIn: '7d' });
}

function verifyToken(token) {
    try {
        return jwt.verify(token, JWT_SECRET);
    } catch {
        return null;
    }
}

async function isAdmin(userId) {
    const { data, error } = await supabase
        .from('users')
        .select('is_admin, email')
        .eq('id', userId)
        .single();
    if (error || !data) return false;
    return data.is_admin === true;
}

async function isSuperAdmin(userId) {
    const { data, error } = await supabase
        .from('users')
        .select('email')
        .eq('id', userId)
        .single();
    if (error || !data) return false;
    return data.email === SUPER_ADMIN_EMAIL;
}

// ===== ТЕСТОВЫЙ ЭНДПОИНТ (ПРОВЕРКА РАБОТЫ) =====
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        timestamp: new Date().toISOString(),
        supabase: supabaseUrl ? 'connected' : 'no url'
    });
});

// ===== АУТЕНТИФИКАЦИЯ =====
app.post('/api/auth/register', async (req, res) => {
    try {
        console.log('📝 Register request:', req.body);
        const { username, email, password } = req.body;

        if (!username || !email || !password) {
            return res.status(400).json({ error: 'Все поля обязательны для заполнения' });
        }
        if (password.length < 8) {
            return res.status(400).json({ error: 'Пароль должен содержать минимум 8 символов' });
        }

        const { data: existing } = await supabase
            .from('users')
            .select('email')
            .or(`email.eq.${email},username.eq.${username}`)
            .maybeSingle();

        if (existing) {
            return res.status(400).json({ error: 'Пользователь уже существует' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const isAdmin = email === SUPER_ADMIN_EMAIL;

        const { data: user, error } = await supabase
            .from('users')
            .insert({
                username,
                email,
                password: hashedPassword,
                is_admin: isAdmin,
                wins: 0,
                losses: 0,
                matches: 0,
                elo: 1000,
                calibration_matches: 0,
                is_calibrated: false,
                history: []
            })
            .select()
            .single();

        if (error) {
            console.error('❌ Supabase insert error:', error);
            return res.status(500).json({ error: 'Ошибка базы данных' });
        }

        const token = generateToken(user.id);

        res.json({
            success: true,
            token,
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                isAdmin: user.is_admin
            }
        });
    } catch (error) {
        console.error('❌ Register error:', error);
        res.status(500).json({ error: 'Внутренняя ошибка сервера' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        console.log('🔑 Login request:', req.body.email);
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ error: 'Email и пароль обязательны' });
        }

        const { data: user, error } = await supabase
            .from('users')
            .select('*')
            .eq('email', email)
            .single();

        if (error || !user) {
            return res.status(400).json({ error: 'Пользователь не найден' });
        }

        const valid = await bcrypt.compare(password, user.password);
        if (!valid) {
            return res.status(400).json({ error: 'Неверный пароль' });
        }

        const token = generateToken(user.id);

        res.json({
            success: true,
            token,
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                isAdmin: user.is_admin || false,
                wins: user.wins || 0,
                losses: user.losses || 0,
                matches: user.matches || 0,
                elo: user.elo || 1000,
                isCalibrated: user.is_calibrated || false,
                calibrationMatches: user.calibration_matches || 0,
                history: user.history || []
            }
        });
    } catch (error) {
        console.error('❌ Login error:', error);
        res.status(500).json({ error: 'Внутренняя ошибка сервера' });
    }
});

app.get('/api/auth/me', async (req, res) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader) {
            return res.status(401).json({ error: 'Не авторизован' });
        }

        const token = authHeader.split(' ')[1];
        const decoded = verifyToken(token);
        if (!decoded) {
            return res.status(401).json({ error: 'Неверный токен' });
        }

        const { data: user, error } = await supabase
            .from('users')
            .select('*')
            .eq('id', decoded.userId)
            .single();

        if (error || !user) {
            return res.status(404).json({ error: 'Пользователь не найден' });
        }

        res.json({
            id: user.id,
            username: user.username,
            email: user.email,
            isAdmin: user.is_admin || false,
            wins: user.wins || 0,
            losses: user.losses || 0,
            matches: user.matches || 0,
            elo: user.elo || 1000,
            isCalibrated: user.is_calibrated || false,
            calibrationMatches: user.calibration_matches || 0,
            history: user.history || []
        });
    } catch (error) {
        console.error('❌ Me error:', error);
        res.status(500).json({ error: 'Внутренняя ошибка сервера' });
    }
});

// ===== ПРОФИЛЬ =====
app.put('/api/profile/update', async (req, res) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader) {
            return res.status(401).json({ error: 'Не авторизован' });
        }

        const token = authHeader.split(' ')[1];
        const decoded = verifyToken(token);
        if (!decoded) {
            return res.status(401).json({ error: 'Неверный токен' });
        }

        const { username } = req.body;

        if (!username) {
            return res.status(400).json({ error: 'Укажите никнейм' });
        }

        const { data: user, error } = await supabase
            .from('users')
            .update({
                username: username
            })
            .eq('id', decoded.userId)
            .select()
            .single();

        if (error) throw error;

        res.json({
            success: true,
            user: {
                username: user.username
            }
        });
    } catch (error) {
        console.error('Update profile error:', error);
        res.status(500).json({ error: error.message });
    }
});

// ===== ПУБЛИЧНЫЙ СПИСОК ПОЛЬЗОВАТЕЛЕЙ =====
app.get('/api/users/public', async (req, res) => {
    try {
        const { data: users, error } = await supabase
            .from('users')
            .select('id, username, wins, losses, matches, elo, is_calibrated, calibration_matches')
            .order('elo', { ascending: false });

        if (error) {
            console.error('Supabase error:', error);
            return res.status(500).json({ error: error.message });
        }

        const formattedUsers = (users || []).map(u => ({
            id: u.id,
            username: u.username,
            wins: u.wins || 0,
            losses: u.losses || 0,
            matches: u.matches || 0,
            elo: u.elo || 1000,
            is_calibrated: u.is_calibrated || false,
            calibration_matches: u.calibration_matches || 0
        }));

        res.json({ users: formattedUsers });
    } catch (error) {
        console.error('Public users error:', error);
        res.status(500).json({ error: error.message });
    }
});

// ===== АДМИН - ПРОВЕРКА =====
app.get('/api/admin/check', async (req, res) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader) {
            return res.status(401).json({ error: 'Не авторизован' });
        }

        const token = authHeader.split(' ')[1];
        const decoded = verifyToken(token);
        if (!decoded) {
            return res.status(401).json({ error: 'Неверный токен' });
        }

        const isAdminUser = await isAdmin(decoded.userId);
        const isSuperAdminUser = await isSuperAdmin(decoded.userId);

        res.json({
            isAdmin: isAdminUser,
            isSuperAdmin: isSuperAdminUser
        });
    } catch (error) {
        console.error('Admin check error:', error);
        res.status(500).json({ error: error.message });
    }
});

// ===== АДМИН - УПРАВЛЕНИЕ ПОЛЬЗОВАТЕЛЯМИ =====
app.get('/api/admin/users', async (req, res) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader) {
            return res.status(401).json({ error: 'Не авторизован' });
        }

        const token = authHeader.split(' ')[1];
        const decoded = verifyToken(token);
        if (!decoded) {
            return res.status(401).json({ error: 'Неверный токен' });
        }

        const isAdminUser = await isAdmin(decoded.userId);
        if (!isAdminUser) {
            return res.status(403).json({ error: 'Доступ запрещен' });
        }

        const { data: users, error } = await supabase
            .from('users')
            .select('id, username, email, is_admin, created_at')
            .order('created_at', { ascending: false });

        if (error) throw error;

        const usersWithFlag = users.map(u => ({
            ...u,
            isSuperAdmin: u.email === SUPER_ADMIN_EMAIL
        }));

        res.json({ users: usersWithFlag });
    } catch (error) {
        console.error('Admin users error:', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/admin/users/toggle', async (req, res) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader) {
            return res.status(401).json({ error: 'Не авторизован' });
        }

        const token = authHeader.split(' ')[1];
        const decoded = verifyToken(token);
        if (!decoded) {
            return res.status(401).json({ error: 'Неверный токен' });
        }

        const isSuperAdminUser = await isSuperAdmin(decoded.userId);
        if (!isSuperAdminUser) {
            return res.status(403).json({ error: 'Только главный администратор может управлять админами' });
        }

        const { userId, makeAdmin } = req.body;

        if (!userId) {
            return res.status(400).json({ error: 'ID пользователя обязателен' });
        }

        const { data: targetUser } = await supabase
            .from('users')
            .select('email')
            .eq('id', userId)
            .single();

        if (targetUser?.email === SUPER_ADMIN_EMAIL) {
            return res.status(403).json({ error: 'Нельзя изменять статус главного администратора' });
        }

        const { data: user, error } = await supabase
            .from('users')
            .update({ is_admin: makeAdmin })
            .eq('id', userId)
            .select()
            .single();

        if (error) throw error;

        res.json({
            success: true,
            user: {
                id: user.id,
                username: user.username,
                isAdmin: user.is_admin
            }
        });
    } catch (error) {
        console.error('Toggle admin error:', error);
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/admin/users/:userId', async (req, res) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader) {
            return res.status(401).json({ error: 'Не авторизован' });
        }

        const token = authHeader.split(' ')[1];
        const decoded = verifyToken(token);
        if (!decoded) {
            return res.status(401).json({ error: 'Неверный токен' });
        }

        const isSuperAdminUser = await isSuperAdmin(decoded.userId);
        if (!isSuperAdminUser) {
            return res.status(403).json({ error: 'Только главный администратор может удалять пользователей' });
        }

        const { userId } = req.params;

        const { data: targetUser } = await supabase
            .from('users')
            .select('email')
            .eq('id', userId)
            .single();

        if (targetUser?.email === SUPER_ADMIN_EMAIL) {
            return res.status(403).json({ error: 'Нельзя удалять главного администратора' });
        }

        const { error } = await supabase
            .from('users')
            .delete()
            .eq('id', userId);

        if (error) throw error;

        res.json({ success: true });
    } catch (error) {
        console.error('Delete user error:', error);
        res.status(500).json({ error: error.message });
    }
});

// ===== ОЧЕРЕДЬ =====
app.get('/api/queue', async (req, res) => {
    try {
        const { data: queue, error } = await supabase
            .from('queue')
            .select('players')
            .order('created_at', { ascending: false })
            .limit(1)
            .maybeSingle();

        if (error) throw error;

        res.json({ players: queue?.players || [] });
    } catch (error) {
        console.error('Queue error:', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/queue/join', async (req, res) => {
    try {
        const { username } = req.body;

        if (!username) {
            return res.status(400).json({ error: 'Имя пользователя не указано' });
        }

        const { data: existing } = await supabase
            .from('queue')
            .select('players')
            .order('created_at', { ascending: false })
            .limit(1)
            .maybeSingle();

        let players = existing?.players || [];

        if (!players.includes(username)) {
            players.push(username);
        } else {
            return res.json({ 
                players: players, 
                alreadyInQueue: true,
                message: 'Игрок уже в очереди'
            });
        }

        await supabase.from('queue').delete().neq('id', '0');

        const { data: queue, error } = await supabase
            .from('queue')
            .insert({ players })
            .select()
            .single();

        if (error) throw error;

        res.json({ 
            players: queue.players,
            alreadyInQueue: false,
            message: 'Игрок добавлен в очередь'
        });
    } catch (error) {
        console.error('Join queue error:', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/queue/leave', async (req, res) => {
    try {
        const { username } = req.body;

        if (!username) {
            return res.status(400).json({ error: 'Имя пользователя не указано' });
        }

        const { data: existing } = await supabase
            .from('queue')
            .select('players')
            .order('created_at', { ascending: false })
            .limit(1)
            .maybeSingle();

        let players = existing?.players || [];
        const wasInQueue = players.includes(username);
        players = players.filter(p => p !== username);

        await supabase.from('queue').delete().neq('id', '0');

        const { data: queue, error } = await supabase
            .from('queue')
            .insert({ players })
            .select()
            .single();

        if (error) throw error;

        res.json({ 
            players: queue.players,
            wasInQueue: wasInQueue,
            message: wasInQueue ? 'Игрок удалён из очереди' : 'Игрок не находился в очереди'
        });
    } catch (error) {
        console.error('Leave queue error:', error);
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/queue/clear', async (req, res) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader) {
            return res.status(401).json({ error: 'Не авторизован' });
        }

        const token = authHeader.split(' ')[1];
        const decoded = verifyToken(token);
        if (!decoded) {
            return res.status(401).json({ error: 'Неверный токен' });
        }

        const isAdminUser = await isAdmin(decoded.userId);
        if (!isAdminUser) {
            return res.status(403).json({ error: 'Доступ запрещен' });
        }

        await supabase.from('queue').delete().neq('id', '0');
        await supabase.from('queue').insert({ players: [] });

        res.json({ success: true });
    } catch (error) {
        console.error('Clear queue error:', error);
        res.status(500).json({ error: error.message });
    }
});

// ===== МАТЧИ =====
app.post('/api/match/create', async (req, res) => {
    try {
        const { matchId, teamA, teamB, banned, finalMap, players } = req.body;

        if (!matchId || !teamA || !teamB) {
            return res.status(400).json({ error: 'Недостаточно данных для создания матча' });
        }

        const { data: match, error } = await supabase
            .from('matches')
            .insert({
                match_id: matchId,
                team_a: teamA || [],
                team_b: teamB || [],
                banned: banned || [],
                final_map: finalMap || '💎 Gem Grab',
                players: players || [],
                status: 'ban_phase'
            })
            .select()
            .single();

        if (error) throw error;

        await supabase.from('queue').delete().neq('id', '0');
        await supabase.from('queue').insert({ players: [] });

        res.json({ success: true, match });
    } catch (error) {
        console.error('Create match error:', error);
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/match/:matchId', async (req, res) => {
    try {
        const { matchId } = req.params;

        const { data: match, error } = await supabase
            .from('matches')
            .select('*')
            .eq('match_id', matchId)
            .single();

        if (error || !match) {
            return res.status(404).json({ error: 'Матч не найден' });
        }

        res.json(match);
    } catch (error) {
        console.error('Get match error:', error);
        res.status(500).json({ error: error.message });
    }
});

app.put('/api/match/update', async (req, res) => {
    try {
        const { matchId, banned, finalMap, status } = req.body;

        if (!matchId) {
            return res.status(400).json({ error: 'ID матча обязателен' });
        }

        const updateData = {};
        if (banned !== undefined) updateData.banned = banned;
        if (finalMap !== undefined) updateData.final_map = finalMap;
        if (status !== undefined) updateData.status = status;

        const { data: match, error } = await supabase
            .from('matches')
            .update(updateData)
            .eq('match_id', matchId)
            .select()
            .single();

        if (error) throw error;

        res.json({ success: true, match });
    } catch (error) {
        console.error('Update match error:', error);
        res.status(500).json({ error: error.message });
    }
});

// ===== ОТМЕНА МАТЧА =====
app.delete('/api/match/:matchId/cancel', async (req, res) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader) {
            return res.status(401).json({ error: 'Не авторизован' });
        }

        const token = authHeader.split(' ')[1];
        const decoded = verifyToken(token);
        if (!decoded) {
            return res.status(401).json({ error: 'Неверный токен' });
        }

        const isAdminUser = await isAdmin(decoded.userId);
        if (!isAdminUser) {
            return res.status(403).json({ error: 'Доступ запрещен. Только администраторы могут отменять матчи.' });
        }

        const { matchId } = req.params;

        const { error } = await supabase
            .from('matches')
            .delete()
            .eq('match_id', matchId);

        if (error) throw error;

        res.json({ success: true, message: 'Матч отменён' });
    } catch (error) {
        console.error('Cancel match error:', error);
        res.status(500).json({ error: error.message });
    }
});

// ===== ЗАВЕРШЕНИЕ МАТЧА =====
app.post('/api/match/finish', async (req, res) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader) {
            return res.status(401).json({ error: 'Не авторизован' });
        }

        const token = authHeader.split(' ')[1];
        const decoded = verifyToken(token);
        if (!decoded) {
            return res.status(401).json({ error: 'Неверный токен' });
        }

        const isAdminUser = await isAdmin(decoded.userId);
        if (!isAdminUser) {
            return res.status(403).json({ 
                error: 'Доступ запрещен. Только администраторы могут завершать матчи.' 
            });
        }

        const { matchId, winner, playerUsername, isWin, screenshot, finalMap } = req.body;

        if (!matchId || !playerUsername) {
            return res.status(400).json({ error: 'Недостаточно данных для завершения матча' });
        }

        await supabase
            .from('matches')
            .update({
                winner: winner,
                status: 'finished',
                screenshot: screenshot || '',
                final_map: finalMap || '💎 Gem Grab'
            })
            .eq('match_id', matchId);

        const { data: user, error: userError } = await supabase
            .from('users')
            .select('*')
            .eq('username', playerUsername)
            .single();

        if (userError || !user) {
            return res.status(404).json({ error: 'Пользователь не найден' });
        }

        let newWins = user.wins || 0;
        let newLosses = user.losses || 0;
        let newMatches = (user.matches || 0) + 1;
        let newElo = user.elo || 1000;
        let newCalibrationMatches = user.calibration_matches || 0;
        let isCalibrated = user.is_calibrated || false;
        let history = user.history || [];

        const isCalibration = !isCalibrated && newCalibrationMatches < 10;
        let eloChange = 0;

        if (isCalibration) {
            newCalibrationMatches++;
            if (isWin) {
                newWins++;
                eloChange = 95;
            } else {
                newLosses++;
                eloChange = -35;
            }
        } else {
            if (isWin) {
                newWins++;
                eloChange = 25;
            } else {
                newLosses++;
                eloChange = -25;
            }
        }

        newElo = Math.max(0, newElo + eloChange);

        history.push({
            matchId: matchId,
            map: finalMap || '💎 Gem Grab',
            result: isWin ? 'win' : 'lose',
            date: new Date().toLocaleDateString('ru-RU'),
            isCalibration: isCalibration,
            eloChange: eloChange
        });

        if (isCalibration && newCalibrationMatches >= 10) {
            isCalibrated = true;
        }

        await supabase
            .from('users')
            .update({
                wins: newWins,
                losses: newLosses,
                matches: newMatches,
                elo: newElo,
                calibration_matches: newCalibrationMatches,
                is_calibrated: isCalibrated,
                history: history
            })
            .eq('id', user.id);

        res.json({
            success: true,
            user: {
                username: user.username,
                wins: newWins,
                losses: newLosses,
                matches: newMatches,
                elo: newElo,
                isCalibrated: isCalibrated
            }
        });
    } catch (error) {
        console.error('Finish match error:', error);
        res.status(500).json({ error: error.message });
    }
});

// ===== СТАТИСТИКА =====
app.get('/api/stats', async (req, res) => {
    try {
        const { count: usersCount } = await supabase
            .from('users')
            .select('*', { count: 'exact', head: true });

        const { count: matchesCount } = await supabase
            .from('matches')
            .select('*', { count: 'exact', head: true });

        const { data: queue } = await supabase
            .from('queue')
            .select('players')
            .order('created_at', { ascending: false })
            .limit(1)
            .maybeSingle();

        res.json({
            totalUsers: usersCount || 0,
            tournaments: matchesCount || 0,
            servers: 0,
            pending: queue?.players?.length || 0
        });
    } catch (error) {
        console.error('Stats error:', error);
        res.status(500).json({ error: error.message });
    }
});

// ===== ЗАПУСК =====
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Сервер запущен на порту ${PORT}`);
    console.log(`👑 Главный администратор: ${SUPER_ADMIN_EMAIL}`);
    console.log(`📡 Supabase URL: ${supabaseUrl}`);
});
