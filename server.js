const express = require('express');
const oracledb = require('oracledb');
const bodyParser = require('body-parser');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = 3000;

// Cấu hình Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public'))); // Cho phép truy cập thư mục public

// CẤU HÌNH KẾT NỐI ORACLE
const dbConfig = {
    user: "ADMIN_HUIT",
    password: "123",
    connectString: "localhost:1521/orcl" // Dùng SID orcl
};

// Chế độ Auto Commit cho Oracle
oracledb.autoCommit = true;

// API: ĐĂNG NHẬP
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    let connection;

    try {
        connection = await oracledb.getConnection(dbConfig);

        // Gọi Stored Procedure PROC_KIEMTRA_DANGNHAP
        const result = await connection.execute(
            `BEGIN 
                PROC_KIEMTRA_DANGNHAP(:u, :p, :res, :role); 
             END;`,
            {
                u: username,
                p: password,
                res:  { dir: oracledb.BIND_OUT, type: oracledb.NUMBER }, // 1: Thành công, 0: Thất bại
                role: { dir: oracledb.BIND_OUT, type: oracledb.STRING }  // Tên vai trò (ADMIN, SINHVIEN...)
            }
        );

        const ketQua = result.outBinds.res;
        const vaiTro = result.outBinds.role;

        if (ketQua === 1) {
            res.json({ success: true, role: vaiTro, message: "Đăng nhập thành công!" });
        } else {
            res.status(401).json({ success: false, message: "Sai tên đăng nhập hoặc mật khẩu!" });
        }

    } catch (err) {
        console.error("Lỗi đăng nhập:", err);
        res.status(500).json({ success: false, message: "Lỗi Server: " + err.message });
    } finally {
        if (connection) {
            try { await connection.close(); } catch (e) { console.error(e); }
        }
    }
});

// Route mặc định: Vào trang login đầu tiên
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Khởi động server
app.listen(PORT, () => {
    console.log(`Server đang chạy tại: http://localhost:${PORT}`);
    console.log(`Đang kết nối Oracle User: ${dbConfig.user}...`);
});