from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from datetime import datetime, timedelta
from captcha.image import ImageCaptcha 
import pandas as pd
import qrcode
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import io
import random
import base64
import oracledb
from flask_caching import Cache
import time
from dotenv import load_dotenv
import os
import json
import secrets

load_dotenv()


app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'super_secret_key_huit')  

# --- CẤU HÌNH KẾT NỐI ORACLE ---
ORACLE_USER = os.getenv('ORACLE_USER')
ORACLE_PASS = os.getenv('ORACLE_PASS')
ORACLE_HOST = os.getenv('ORACLE_HOST', 'localhost')
ORACLE_PORT = os.getenv('ORACLE_PORT', '1521')
ORACLE_SID = os.getenv('ORACLE_SID', 'orcl')

app.config['SQLALCHEMY_DATABASE_URI'] = f'oracle+oracledb://{ORACLE_USER}:{ORACLE_PASS}@{ORACLE_HOST}:{ORACLE_PORT}/{ORACLE_SID}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# --- CẤU HÌNH EMAIL ---
MY_EMAIL = os.getenv('EMAIL_USER')
MY_PASSWORD = os.getenv('EMAIL_PASS')

# --- MODELS ---
class NguoiDung(db.Model):
    __tablename__ = 'NGUOI_DUNG'
    ma_nguoi_dung = db.Column(db.Integer, primary_key=True)
    ten_dang_nhap = db.Column(db.String(50), unique=True)
    ho_ten = db.Column(db.String(100))
    email = db.Column(db.String(100))
    ma_vai_tro = db.Column(db.Integer)

# --- UTILS ---
def generate_captcha():
    source = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
    text = ''.join(random.choice(source) for _ in range(5))
    session['captcha_result'] = text
    image = ImageCaptcha(width=280, height=80)
    data = image.generate(text)
    return base64.b64encode(data.read()).decode('utf-8')

def send_reset_email(user_email, reset_code):
    try:
        msg = MIMEMultipart()
        msg['From'] = MY_EMAIL
        msg['To'] = user_email
        msg['Subject'] = "Mã xác nhận khôi phục mật khẩu"
        msg.attach(MIMEText(f"Mã của bạn: {reset_code}", 'plain'))
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(MY_EMAIL, MY_PASSWORD)
        server.sendmail(MY_EMAIL, user_email, msg.as_string())
        server.quit()
        return True
    except Exception as e:
        print(f"Email error: {e}")
        return False

def send_credentials_email(user_email, username, fullname):
    try:
        msg = MIMEMultipart()
        msg['From'] = MY_EMAIL
        msg['To'] = user_email
        msg['Subject'] = "Thông tin tài khoản Hệ thống Điểm danh"
        
        body = f"""
        Xin chào {fullname},
        
        Tài khoản của bạn đã được tạo thành công.
        
        --------------------------------
        Tên đăng nhập: {username}
        Mật khẩu mặc định: 123
        --------------------------------
        
        Vui lòng đăng nhập và đổi mật khẩu ngay lập tức.
        """
        msg.attach(MIMEText(body, 'plain'))
        
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(MY_EMAIL, MY_PASSWORD)
        server.sendmail(MY_EMAIL, user_email, msg.as_string())
        server.quit()
        return True
    except Exception as e:
        print(f"Lỗi gửi email: {e}")
        return False

def validate_otp(code):
    """Validate OTP format"""
    if not code:
        return False
    # Loại bỏ khoảng trắng và kiểm tra
    code = str(code).strip()
    if not code.isdigit() or len(code) != 6:
        return False
    return True

def safe_str_date(value, format_str='%d/%m/%Y'):
    if value is None:
        return ""
    try:
        if hasattr(value, 'strftime'):
            return value.strftime(format_str)
        return str(value)
    except:
        return ""

# --- ROUTES ---

@app.route('/')
def index(): 
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        captcha = request.form['captcha']
        
        if captcha.upper() != session.get('captcha_result'):
            flash('Sai mã Captcha!', 'error')
            return redirect(url_for('login'))

        try:
            user_check = db.session.execute(text("SELECT MA_NGUOI_DUNG FROM NGUOI_DUNG WHERE TEN_DANG_NHAP=:u"), {'u': username}).fetchone()
            user_id_log = user_check[0] if user_check else None

            sql = text("SELECT FUNC_KIEMTRA_DANGNHAP(:u, :p) FROM DUAL")
            result = db.session.execute(sql, {'u': username, 'p': password}).scalar()
            
            if result and result > 0:
                user = NguoiDung.query.get(result)
                check_pass = db.session.execute(text("SELECT FORCE_CHANGE_PASS FROM NGUOI_DUNG WHERE MA_NGUOI_DUNG=:id"), {'id': user.ma_nguoi_dung}).scalar()

                session.permanent = True
                session['user_id'] = user.ma_nguoi_dung
                session['name'] = user.ho_ten
                session['username'] = user.ten_dang_nhap
                
                try:
                    db.session.execute(text("BEGIN PROC_THEM_AUDIT_LOG(:u, :a, :d, :ip, :ua, :s); END;"), {
                        'u': user.ma_nguoi_dung, 'a': 'Đăng nhập', 'd': 'Đăng nhập vào hệ thống',
                        'ip': request.remote_addr, 'ua': request.user_agent.string[:250], 's': 'Thành công'
                    })
                    db.session.commit()
                except: pass

                if check_pass == 1:
                    flash('Bạn cần đổi mật khẩu lần đầu đăng nhập!', 'warning')
                    return redirect(url_for('change_password_required'))
                
                role_map = {1: 'admin', 2: 'teacher', 3: 'student'}
                user_role = role_map.get(user.ma_vai_tro, 'student')
                session['role'] = user_role

                if user_role == 'admin': return redirect(url_for('admin_dashboard'))
                elif user_role == 'teacher': return redirect(url_for('teacher_dashboard'))
                else: return redirect(url_for('student_dashboard'))
            else:
                if user_id_log:
                    try:
                        db.session.execute(text("BEGIN PROC_THEM_AUDIT_LOG(:u, :a, :d, :ip, :ua, :s); END;"), {
                            'u': user_id_log, 'a': 'Đăng nhập', 'd': f'Sai mật khẩu (User: {username})',
                            'ip': request.remote_addr, 'ua': request.user_agent.string[:250], 's': 'Thất bại'
                        })
                        db.session.commit()
                    except Exception as e: print(e)

                if result == 0: flash('Sai mật khẩu!', 'error')
                else: flash('Tên đăng nhập không tồn tại!', 'error')     
        except Exception as e:
            flash(f'Lỗi hệ thống: {str(e)}', 'error')

    return render_template('login.html', captcha_image=generate_captcha())

@app.route('/change_password_required', methods=['GET', 'POST'])
def change_password_required():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    if request.method == 'POST':
        new_pass = request.form['new_password']
        confirm_pass = request.form['confirm_password']
        
        if new_pass != confirm_pass:
            flash('Mật khẩu xác nhận không khớp!', 'error')
        elif len(new_pass) < 1:
            flash('Mật khẩu không được để trống!', 'error')
        else:
            try:
                db.session.execute(text("""
                    DECLARE
                        v_salt VARCHAR2(100);
                        v_hash VARCHAR2(255);
                    BEGIN
                        v_salt := FUNC_GEN_SALT();
                        v_hash := FUNC_HASH_PASS(:p, v_salt);
                        
                        UPDATE NGUOI_DUNG 
                        SET MAT_KHAU_HASH = v_hash, 
                            SALT = v_salt, 
                            FORCE_CHANGE_PASS = 0 
                        WHERE MA_NGUOI_DUNG = :id;
                        COMMIT;
                    END;
                """), {'p': new_pass, 'id': session['user_id']})
                
                session.clear()
                flash('Đổi mật khẩu thành công! Vui lòng đăng nhập lại.', 'success')
                return redirect(url_for('login'))
            except Exception as e:
                flash(f'Lỗi đổi mật khẩu: {str(e)}', 'error')
                
    return render_template('change_password.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        fullname = request.form['fullname']
        email = request.form['email']
        
        try:
            check_exist = db.session.execute(text("SELECT 1 FROM NGUOI_DUNG WHERE EMAIL=:e"), {'e': email}).fetchone()
            if check_exist:
                flash('Email này đã được sử dụng!', 'error')
                return redirect(url_for('register'))

            check_pending = db.session.execute(text("SELECT 1 FROM DANG_KY_CHO WHERE EMAIL=:e"), {'e': email}).fetchone()
            if check_pending:
                flash('Bạn đã gửi yêu cầu rồi, vui lòng chờ Admin duyệt!', 'warning')
                return redirect(url_for('login'))

            db.session.execute(text("INSERT INTO DANG_KY_CHO (HO_TEN, EMAIL) VALUES (:n, :e)"), 
                               {'n': fullname, 'e': email})
            db.session.commit()
            
            flash('Đã gửi yêu cầu đăng ký! Vui lòng chờ Giảng viên/Admin phê duyệt qua Email.', 'success')
            return redirect(url_for('login'))

        except Exception as e:
            flash(f'Lỗi: {str(e)}', 'error')
            
    return render_template('register.html')

@app.route('/admin')
def admin_dashboard():
    if session.get('role') != 'admin':
        return redirect(url_for('login'))
    users = NguoiDung.query.all()
    try:
        stats = db.session.execute(text("""
            SELECT 
                (SELECT COUNT(*) FROM NGUOI_DUNG WHERE MA_VAI_TRO = 3) as total_students,
                (SELECT COUNT(*) FROM NGUOI_DUNG WHERE MA_VAI_TRO = 2) as total_teachers,
                (SELECT COUNT(*) FROM LICHSU_DIEMDANH 
                 WHERE TRUNC(THOI_GIAN_DIEM_DANH) = TRUNC(SYSDATE)) as today_attendance,
                (SELECT COUNT(*) FROM AUDIT_LOG 
                 WHERE TRUNC(THOI_GIAN) = TRUNC(SYSDATE)) as today_actions
            FROM DUAL
        """)).fetchone()
    except Exception as e:
        print(f"Stats error: {e}")
        stats = (0, 0, 0, 0)
    
    # Audit logs
    try:
        audit_logs = db.session.execute(text("""
            SELECT a.THOI_GIAN, u.HO_TEN, u.TEN_DANG_NHAP, a.HANH_DONG, 
                   a.CHI_TIET, a.IP_ADDRESS, a.TRANG_THAI
            FROM AUDIT_LOG a
            LEFT JOIN NGUOI_DUNG u ON a.MA_NGUOI_DUNG = u.MA_NGUOI_DUNG
            ORDER BY a.THOI_GIAN DESC 
            FETCH FIRST 100 ROWS ONLY
        """)).fetchall()
    except Exception as e:
        print(f"Audit log error: {e}")
        audit_logs = []
    
    # Trigger Logs 
    try:
        trigger_logs = db.session.execute(text("""
            SELECT ID_LOG, USER_DB, ACTION_TIME, ACTION_TYPE, TABLE_NAME, OLD_DATA, NEW_DATA 
            FROM LOG_DB_CHANGES 
            ORDER BY ID_LOG DESC 
            FETCH FIRST 50 ROWS ONLY
        """)).fetchall()
    except Exception as e:
        print(f"Trigger Log Error: {e}")
        trigger_logs = []

    # Lịch sử điểm danh 
    try:
        attendance_logs = db.session.execute(text("""
            SELECT l.THOI_GIAN_DIEM_DANH, u.HO_TEN, l.TRANG_THAI, l.PHUONG_THUC 
            FROM LICHSU_DIEMDANH l 
            JOIN NGUOI_DUNG u ON l.MA_SINH_VIEN = u.MA_NGUOI_DUNG
            ORDER BY l.THOI_GIAN_DIEM_DANH DESC 
            FETCH FIRST 50 ROWS ONLY
        """)).fetchall()
    except Exception as e:
        print(f"Attendance log error: {e}")
        attendance_logs = []
        
    try:
        pending_users = db.session.execute(text("""
            SELECT ID, HO_TEN, EMAIL, THOI_GIAN 
            FROM DANG_KY_CHO 
            ORDER BY THOI_GIAN DESC
        """)).fetchall()
    except Exception as e:
        print(f"Pending users error: {e}")
        pending_users = []

    return render_template('admin.html', 
                         all_users=users, 
                         audit_logs=audit_logs,
                         attendance_logs=attendance_logs, 
                         trigger_logs=trigger_logs,
                         stats=stats, 
                         pending_users=pending_users)

@app.route('/admin/create_user', methods=['POST'])
def admin_create_user():
    if session.get('role') != 'admin':
        return redirect(url_for('login'))
    role_map = {'student': 3, 'teacher': 2}
    role_id = role_map.get(request.form['role'], 3)
    fullname = request.form['fullname']
    email = request.form.get('email', '')
    try:
        db.session.execute(text("BEGIN PROC_THEM_NGUOI_DUNG_AUTO(:n, :e, :r); END;"), 
                           {'n': fullname, 'e': email, 'r': role_id})
        db.session.execute(text("BEGIN PROC_THEM_AUDIT_LOG(:u, :a, :d, :ip, :ua, :s); END;"), {
            'u': session['user_id'], 
            'a': 'Quản lý User', 
            'd': f'Đã tạo tài khoản mới cho: {fullname} ({request.form["role"]})',
            'ip': request.remote_addr, 
            'ua': request.user_agent.string[:250], 
            's': 'Thành công'
        })
        db.session.commit()

        new_user = db.session.execute(text("""
            SELECT TEN_DANG_NHAP FROM NGUOI_DUNG 
            WHERE EMAIL = :e ORDER BY MA_NGUOI_DUNG DESC FETCH FIRST 1 ROW ONLY
        """), {'e': email}).fetchone()

        if new_user and email:
            send_credentials_email(email, new_user[0], fullname)
            flash(f'Tạo thành công! Username: {new_user[0]}. Đã gửi email cho người dùng.', 'success')
        else:
            flash('Tạo thành công nhưng không gửi được email', 'warning')
    except Exception as e:
        flash(f'Lỗi: {str(e)}', 'error')
    return redirect(url_for('admin_dashboard'))

# Duyệt/ từ chối user đăng ký 
@app.route('/admin/approve/<int:req_id>')
def approve_user(req_id):
    if session.get('role') != 'admin': return redirect(url_for('login'))
    
    try:
        req = db.session.execute(text("SELECT HO_TEN, EMAIL FROM DANG_KY_CHO WHERE ID=:id"), {'id': req_id}).fetchone()
        if not req:
            flash('Yêu cầu không tồn tại!', 'error')
            return redirect(url_for('admin_dashboard'))
        fullname, email = req[0], req[1]        
        db.session.execute(text("BEGIN PROC_THEM_NGUOI_DUNG_AUTO(:n, :e, 3); END;"), {'n': fullname, 'e': email})       
        db.session.execute(text("DELETE FROM DANG_KY_CHO WHERE ID=:id"), {'id': req_id})
        
        # Ghi Log Audit
        db.session.execute(text("BEGIN PROC_THEM_AUDIT_LOG(:u, :a, :d, :ip, :ua, :s); END;"), {
            'u': session['user_id'], 'a': 'Duyệt tài khoản', 
            'd': f'Đã duyệt sinh viên: {fullname}',
            'ip': request.remote_addr, 'ua': request.user_agent.string[:250], 's': 'Thành công'
        })
        db.session.commit()
        
        # Gửi mail thông báo
        new_user = db.session.execute(text("SELECT TEN_DANG_NHAP FROM NGUOI_DUNG WHERE EMAIL=:e"), {'e': email}).fetchone()
        if new_user:
            send_credentials_email(email, new_user[0], fullname)
            flash(f'Đã duyệt {fullname}. Email kích hoạt đã được gửi!', 'success')
            
    except Exception as e:
        flash(f'Lỗi khi duyệt: {str(e)}', 'error')
        
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/reject/<int:req_id>')
def reject_user(req_id):
    if session.get('role') != 'admin': return redirect(url_for('login'))
    
    try:
        db.session.execute(text("DELETE FROM DANG_KY_CHO WHERE ID=:id"), {'id': req_id})
        db.session.commit()
        flash('Đã từ chối yêu cầu đăng ký.', 'success')
    except Exception as e:
        flash(f'Lỗi: {str(e)}', 'error')
        
    return redirect(url_for('admin_dashboard'))

# Admin thêm lớp học phần 
@app.route('/admin/assign_class', methods=['POST'])
def admin_assign_class():
    if session.get('role') != 'admin':
        return redirect(url_for('login'))
        
    mssv = request.form.get('mssv')     
    class_code = request.form.get('class_code') 
    
    try:
        user = db.session.execute(text("SELECT MA_NGUOI_DUNG FROM NGUOI_DUNG WHERE TEN_DANG_NHAP = :u"), {'u': mssv}).fetchone()
        if not user:
            flash(f'Không tìm thấy sinh viên {mssv}!', 'error')
            return redirect(url_for('admin_dashboard'))
            
        lhp = db.session.execute(text("SELECT MA_LOP_HP FROM LOP_HOC_PHAN WHERE MA_LOP_CODE = :c"), {'c': class_code}).fetchone()
        if not lhp:
            flash(f'Mã lớp {class_code} không tồn tại!', 'error')
            return redirect(url_for('admin_dashboard'))

        db.session.execute(text("""
            BEGIN
                INSERT INTO DANG_KY_LOP (MA_LOP_HP, MA_SINH_VIEN)
                SELECT :lhp, :sv FROM DUAL
                WHERE NOT EXISTS (SELECT 1 FROM DANG_KY_LOP WHERE MA_LOP_HP=:lhp AND MA_SINH_VIEN=:sv);
                
                IF SQL%ROWCOUNT = 0 THEN
                    RAISE_APPLICATION_ERROR(-20000, 'Sinh viên đã ở trong lớp này rồi');
                END IF;
                
                PROC_THEM_AUDIT_LOG(:admin, N'Quản lý Lớp', N'Thêm '||:u||' vào lớp '||:c, :ip, :ua, 'Thành công');
                COMMIT;
            END;
        """), {
            'lhp': lhp[0], 'sv': user[0], 'u': mssv, 'c': class_code,
            'admin': session['user_id'],
            'ip': request.remote_addr, 'ua': request.user_agent.string[:250]
        })
        
        flash(f'Đã thêm {mssv} vào lớp {class_code} thành công!', 'success')
        
    except Exception as e:
        if "Sinh viên đã ở trong lớp này rồi" in str(e):
            flash('Sinh viên này đã có trong lớp đó rồi!', 'warning')
        else:
            flash(f'Lỗi: {str(e)}', 'error')
            
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if session.get('role') != 'admin':
        return redirect(url_for('login'))
    try:
        target_user = db.session.execute(text("SELECT TEN_DANG_NHAP FROM NGUOI_DUNG WHERE MA_NGUOI_DUNG=:id"), {'id': user_id}).scalar()
        db.session.execute(text("BEGIN PROC_XOA_NGUOI_DUNG(:id); END;"), {'id': user_id})
        db.session.execute(text("BEGIN PROC_THEM_AUDIT_LOG(:u, :a, :d, :ip, :ua, :s); END;"), {
            'u': session['user_id'], 'a': 'Quản lý User', 
            'd': f'Đã xóa vĩnh viễn user: {target_user or user_id}',
            'ip': request.remote_addr, 'ua': request.user_agent.string[:250], 
            's': 'Cảnh báo' 
        })
        db.session.commit()
        flash('Đã xóa tài khoản và dữ liệu liên quan thành công!', 'success')
    except Exception as e:
        flash(f'Lỗi khi xóa: {str(e)}', 'error')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/security_report')
def security_report():
    if session.get('role') != 'admin':
        return redirect(url_for('login'))
    try:
        stats = db.session.execute(text("SELECT * FROM V_SECURITY_STATS")).fetchone()        
        db_changes = db.session.execute(text("""
            SELECT * FROM V_DB_AUDIT 
            ORDER BY ACTION_TIME DESC 
            FETCH FIRST 50 ROWS ONLY
        """)).fetchall()      

        activities = db.session.execute(text("""
            SELECT * FROM V_DIEMDANH_ACTIVITY
            FETCH FIRST 30 ROWS ONLY
        """)).fetchall()
        
        return render_template('security_report.html',
                             stats=stats,
                             db_changes=db_changes,
                             activities=activities)
    except Exception as e:
        flash(f'Lỗi: {str(e)}', 'error')
        return redirect(url_for('admin_dashboard'))

@app.route('/teacher')
def teacher_dashboard():
    if session.get('role') != 'teacher': 
        return redirect(url_for('login'))
    
    attendees = db.session.execute(text("""
        SELECT u.TEN_DANG_NHAP, u.HO_TEN, l.THOI_GIAN_DIEM_DANH, l.PHUONG_THUC
        FROM LICHSU_DIEMDANH l 
        JOIN NGUOI_DUNG u ON l.MA_SINH_VIEN = u.MA_NGUOI_DUNG
        JOIN LICH_HOC lh ON l.MA_BUOI_HOC = lh.MA_BUOI_HOC
        JOIN LOP_HOC_PHAN lhp ON lh.MA_LOP_HP = lhp.MA_LOP_HP
        WHERE lhp.MA_GIANG_VIEN = :uid
        ORDER BY l.THOI_GIAN_DIEM_DANH DESC
    """), {'uid': session['user_id']}).fetchall()
    
    schedules = db.session.execute(text("""
        SELECT lh.NGAY_HOC, lh.GIO_BAT_DAU, lh.GIO_KET_THUC, lh.PHONG_HOC, 
               mh.TEN_MON, lh.MA_OTP, lh.MA_BUOI_HOC 
        FROM LICH_HOC lh 
        JOIN LOP_HOC_PHAN lhp ON lh.MA_LOP_HP = lhp.MA_LOP_HP
        JOIN MON_HOC mh ON lhp.MA_MON = mh.MA_MON
        WHERE lhp.MA_GIANG_VIEN = :uid AND lh.NGAY_HOC >= TRUNC(SYSDATE, 'IW')
        ORDER BY lh.NGAY_HOC
    """), {'uid': session['user_id']}).fetchall()

    return render_template('teacher.html', attendees=attendees, schedules=schedules)

# Tạo QR/OTP theo tiết học (CẢI TIẾN BẢO MẬT)
@app.route('/teacher/generate_code/<int:schedule_id>', methods=['POST'])
def generate_code_for_schedule(schedule_id):
    if session.get('role') != 'teacher':
        return jsonify({'error': 'Unauthorized'}), 401
    try:
        # Kiểm tra quyền và lấy thông tin buổi học
        check = db.session.execute(text("""
            SELECT lh.MA_BUOI_HOC, lh.NGAY_HOC, lh.GIO_BAT_DAU, lh.GIO_KET_THUC
            FROM LICH_HOC lh
            JOIN LOP_HOC_PHAN lhp ON lh.MA_LOP_HP = lhp.MA_LOP_HP
            WHERE lh.MA_BUOI_HOC = :sid AND lhp.MA_GIANG_VIEN = :uid
        """), {'sid': schedule_id, 'uid': session['user_id']}).fetchone()
        
        if not check:
            return jsonify({'error': 'Bạn không có quyền tạo mã cho tiết này'}), 403
        
        ma_buoi_hoc, ngay_hoc, gio_bat_dau, gio_ket_thuc = check
        
        # BẢO MẬT: Kiểm tra thời gian - chỉ cho phép tạo mã trong ngày học và trước giờ kết thúc
        if ngay_hoc:
            if datetime.now().date() > ngay_hoc.date():
                return jsonify({'error': 'Không thể tạo mã cho buổi học đã qua!'}), 400
            if datetime.now().date() < ngay_hoc.date():
                return jsonify({'error': 'Chưa đến ngày học này!'}), 400
        
        # Tạo OTP an toàn hơn - sử dụng secrets module (cryptographically secure)
        otp_code = str(secrets.randbelow(900000) + 100000)  # 100000-999999
        
        # Cập nhật OTP vào database
        db.session.execute(text("""
            UPDATE LICH_HOC SET MA_OTP = :otp WHERE MA_BUOI_HOC = :sid
        """), {'otp': otp_code, 'sid': schedule_id})
        
        # Log audit
        db.session.execute(text("BEGIN PROC_THEM_AUDIT_LOG(:u, :a, :d, :ip, :ua, :s); END;"), {
            'u': session['user_id'], 
            'a': 'Tạo mã điểm danh', 
            'd': f'Đã tạo mã OTP cho tiết học ID: {schedule_id} (Mã: {otp_code})',
            'ip': request.remote_addr, 
            'ua': request.user_agent.string[:250] if request.user_agent else '', 
            's': 'Thành công'
        })
        db.session.commit()
        
        # Tạo QR code với timestamp để tăng bảo mật
        base_url = request.host_url.rstrip('/')
        timestamp = int(time.time())
        # QR code có timestamp để tự động hết hạn sau 5 phút
        qr_code_with_timestamp = f"{otp_code}_{timestamp}"
        link = f"{base_url}/student_attendance?code={qr_code_with_timestamp}"
        qr = qrcode.make(link)
        img_io = io.BytesIO()
        qr.save(img_io, 'PNG')
        img_io.seek(0)
        qr_img = base64.b64encode(img_io.getvalue()).decode()
        
        return jsonify({
            'success': True,
            'otp': otp_code,
            'qr_image': qr_img,
            'expires_in': 300,  # 5 phút
            'message': 'Mã OTP đã được tạo. QR code sẽ hết hạn sau 5 phút.'
        })
    except Exception as e:
        print(f"Error generating code: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

# Cho phép giảng viên xem danh sách lớp
@app.route('/api/class_details/<int:schedule_id>') 
def api_get_class_details(schedule_id):
    if session.get('role') != 'teacher':
        return jsonify({'error': 'Bạn không có quyền truy cập dữ liệu này'}), 403
        
    try:
        sql_class = text("""
            SELECT mh.TEN_MON, lh.PHONG_HOC, lh.GIO_BAT_DAU, lh.GIO_KET_THUC, 
                   lh.MA_OTP, lh.NGAY_HOC 
            FROM LICH_HOC lh
            JOIN LOP_HOC_PHAN lhp ON lh.MA_LOP_HP = lhp.MA_LOP_HP
            JOIN MON_HOC mh ON lhp.MA_MON = mh.MA_MON
            WHERE lh.MA_BUOI_HOC = :sid
        """)
        class_info = db.session.execute(sql_class, {'sid': schedule_id}).fetchone()

        if not class_info:
            return jsonify({'error': 'Không tìm thấy tiết học'}), 404

        ngay_hoc_str = safe_str_date(class_info[5])
        # Lấy danh sách sinh viên
        sql_students = text("""
            SELECT sv.TEN_DANG_NHAP, sv.HO_TEN, 
                   ls.TRANG_THAI, ls.PHUONG_THUC, ls.THOI_GIAN_DIEM_DANH
            FROM DANG_KY_LOP dk
            JOIN LICH_HOC lh ON dk.MA_LOP_HP = lh.MA_LOP_HP
            JOIN NGUOI_DUNG sv ON dk.MA_SINH_VIEN = sv.MA_NGUOI_DUNG
            LEFT JOIN LICHSU_DIEMDANH ls ON ls.MA_SINH_VIEN = sv.MA_NGUOI_DUNG 
                                         AND ls.MA_BUOI_HOC = lh.MA_BUOI_HOC
            WHERE lh.MA_BUOI_HOC = :sid
            ORDER BY sv.TEN_DANG_NHAP ASC
        """)
        students = db.session.execute(sql_students, {'sid': schedule_id}).fetchall()

        student_list = []
        for s in students:
            status = s[2] if s[2] else 'Chưa'
            method = s[3] if s[3] else '-'
            time_checkin = safe_str_date(s[4], '%H:%M:%S %d/%m/%Y')

            student_list.append({
                'mssv': s[0], 
                'ten': s[1], 
                'status': status, 
                'method': method, 
                'time_full': time_checkin
            })
            
        return jsonify({
            'success': True,
            'subject': class_info[0],
            'room': class_info[1],
            'time': f"{class_info[2]} - {class_info[3]}",
            'date': ngay_hoc_str,
            'otp': str(class_info[4]) if class_info[4] else None,
            'students': student_list,
            'is_teacher': True
        })
    except Exception as e:
        print(f"Lỗi API Class Details: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': 'Lỗi xử lý dữ liệu server'}), 500

@app.route('/student')
def student_dashboard():
    if session.get('role') != 'student': 
        return redirect(url_for('login'))

    schedules = db.session.execute(text("""
        SELECT lh.NGAY_HOC, lh.GIO_BAT_DAU, lh.GIO_KET_THUC, lh.PHONG_HOC, 
               mh.TEN_MON, gv.HO_TEN as GIANG_VIEN,
               CASE WHEN mh.MA_MON LIKE 'SEC%' THEN '#ffe0b2' 
                    WHEN mh.MA_MON LIKE 'PRG%' THEN '#cce5ff' 
                    ELSE '#d4edda' END as MAU_SAC,
                lh.MA_BUOI_HOC
        FROM LICH_HOC lh
        JOIN LOP_HOC_PHAN lhp ON lh.MA_LOP_HP = lhp.MA_LOP_HP
        JOIN MON_HOC mh ON lhp.MA_MON = mh.MA_MON
        JOIN NGUOI_DUNG gv ON lhp.MA_GIANG_VIEN = gv.MA_NGUOI_DUNG
        JOIN DANG_KY_LOP dk ON lhp.MA_LOP_HP = dk.MA_LOP_HP
        WHERE dk.MA_SINH_VIEN = :uid 
        AND lh.NGAY_HOC >= TRUNC(SYSDATE, 'IW')
        ORDER BY lh.NGAY_HOC
    """), {'uid': session['user_id']}).fetchall()

    history = db.session.execute(text("""
        SELECT mh.TEN_MON, ls.THOI_GIAN_DIEM_DANH, ls.PHUONG_THUC, ls.TRANG_THAI, lh.NGAY_HOC
        FROM LICHSU_DIEMDANH ls
        JOIN LICH_HOC lh ON ls.MA_BUOI_HOC = lh.MA_BUOI_HOC
        JOIN LOP_HOC_PHAN lhp ON lh.MA_LOP_HP = lhp.MA_LOP_HP
        JOIN MON_HOC mh ON lhp.MA_MON = mh.MA_MON
        WHERE ls.MA_SINH_VIEN = :uid ORDER BY ls.THOI_GIAN_DIEM_DANH DESC
    """), {'uid': session['user_id']}).fetchall()
    
    return render_template('student.html', schedules=schedules, history=history)

#XỬ LÝ ĐIỂM DANH
@app.route('/student_attendance')
def student_attendance_qr():
    if 'user_id' not in session:
        flash('Vui lòng đăng nhập!', 'warning')
        return redirect(url_for('login'))
    
    student_id = session['user_id']
    code = request.args.get('code')
    ip_address = request.remote_addr
    user_agent = request.user_agent.string[:250] if request.user_agent else ''
    
    # Rate limiting: Kiểm tra số lần thử điểm danh trong 5 phút gần đây
    try:
        recent_attempts = db.session.execute(text("""
            SELECT COUNT(*) FROM LICHSU_DIEMDANH 
            WHERE MA_SINH_VIEN = :sv 
            AND THOI_GIAN_DIEM_DANH >= SYSDATE - INTERVAL '5' MINUTE
        """), {'sv': student_id}).scalar()
        
        if recent_attempts >= 10:
            flash('Bạn đã thử điểm danh quá nhiều lần. Vui lòng đợi vài phút!', 'error')
            db.session.execute(text("BEGIN PROC_THEM_AUDIT_LOG(:u, :a, :d, :ip, :ua, :s); END;"), {
                'u': student_id, 'a': 'Điểm danh', 
                'd': 'Rate limit exceeded - quá nhiều lần thử',
                'ip': ip_address, 'ua': user_agent, 's': 'Cảnh báo'
            })
            db.session.commit()
            return redirect(url_for('student_dashboard'))
    except Exception as e:
        print(f"Rate limit check error: {e}")
    
    if not code:
        flash('Mã không hợp lệ!', 'error')
        return redirect(url_for('student_dashboard'))
    
    # Xử lý QR code với timestamp
    original_code = code
    if '_' in code:
        try:
            otp_part, timestamp = code.split('_')
            if int(time.time()) - int(timestamp) > 300:  # 5 phút
                flash('Mã QR đã hết hạn!', 'error')
                return redirect(url_for('student_dashboard'))
            code = otp_part  
        except ValueError:
            flash('Mã không đúng định dạng!', 'error')
            return redirect(url_for('student_dashboard'))
    
    # Loại bỏ khoảng trắng và chuẩn hóa OTP
    code = code.strip()
    
    if not validate_otp(code):
        flash('Mã OTP không hợp lệ!', 'error')
        return redirect(url_for('student_dashboard'))
    
    try:
        sql_find = text("""
            SELECT lh.MA_BUOI_HOC, lh.MA_LOP_HP, lh.GIO_BAT_DAU, lh.GIO_KET_THUC, lh.NGAY_HOC
            FROM LICH_HOC lh
            WHERE TRIM(lh.MA_OTP) = :otp 
            AND TRUNC(lh.NGAY_HOC) = TRUNC(SYSDATE)
        """)
        buoi_hoc_info = db.session.execute(sql_find, {'otp': code}).fetchone()
        
        if not buoi_hoc_info:
            flash('Mã không đúng hoặc không có lịch học hôm nay!', 'error')
            db.session.execute(text("BEGIN PROC_THEM_AUDIT_LOG(:u, :a, :d, :ip, :ua, :s); END;"), {
                'u': student_id, 'a': 'Điểm danh', 
                'd': f'Thử điểm danh với mã OTP không hợp lệ: {code}',
                'ip': ip_address, 'ua': user_agent, 's': 'Thất bại'
            })
            db.session.commit()
            return redirect(url_for('student_dashboard'))
        
        ma_buoi_hoc, ma_lop_hp, gio_bat_dau, gio_ket_thuc, ngay_hoc = buoi_hoc_info
        
        # BẢO MẬT 2: Kiểm tra sinh viên có trong lớp học phần không
        check_enrolled = db.session.execute(text("""
            SELECT 1 FROM DANG_KY_LOP 
            WHERE MA_LOP_HP = :lhp AND MA_SINH_VIEN = :sv
        """), {'lhp': ma_lop_hp, 'sv': student_id}).fetchone()
        
        if not check_enrolled:
            flash('Bạn không có trong lớp học phần này!', 'error')
            db.session.execute(text("BEGIN PROC_THEM_AUDIT_LOG(:u, :a, :d, :ip, :ua, :s); END;"), {
                'u': student_id, 'a': 'Điểm danh', 
                'd': f'Thử điểm danh lớp không đăng ký - Lớp HP: {ma_lop_hp}',
                'ip': ip_address, 'ua': user_agent, 's': 'Cảnh báo'
            })
            db.session.commit()
            return redirect(url_for('student_dashboard'))
        
        # Kiểm tra thời gian cụ thể (giờ học)
        current_time = datetime.now().time()
        if gio_bat_dau and gio_ket_thuc:
            try:
                if isinstance(gio_bat_dau, str):
                    t_bat_dau = datetime.strptime(gio_bat_dau, "%H:%M").time()
                else:
                    t_bat_dau = gio_bat_dau

                if isinstance(gio_ket_thuc, str):
                    t_ket_thuc = datetime.strptime(gio_ket_thuc, "%H:%M").time()
                else:
                    t_ket_thuc = gio_ket_thuc

                if current_time < t_bat_dau:
                    flash(f'Chưa đến giờ điểm danh! Giờ bắt đầu: {t_bat_dau.strftime("%H:%M")}', 'error')
                    return redirect(url_for('student_dashboard'))
                
                if current_time > t_ket_thuc:
                    flash(f'Đã hết giờ điểm danh! Giờ kết thúc: {t_ket_thuc.strftime("%H:%M")}', 'error')
                    return redirect(url_for('student_dashboard'))
            except ValueError:
                print("Lỗi format giờ trong DB")
                pass
        
        # Kiểm tra đã điểm danh chưa
        check_existing = db.session.execute(text("""
            SELECT 1 FROM LICHSU_DIEMDANH 
            WHERE MA_BUOI_HOC = :bh AND MA_SINH_VIEN = :sv
        """), {'bh': ma_buoi_hoc, 'sv': student_id}).fetchone()
        
        if check_existing:
            flash('Bạn đã điểm danh môn này rồi!', 'warning')
            return redirect(url_for('student_dashboard'))
        
        # Thực hiện điểm danh
        phuong_thuc = 'QR Code' if '_' in original_code else 'OTP'
        
        try:
            sql_proc = text("""
                BEGIN
                    PROC_DIEMDANH_HYBRID(:bh, :sv, :pt, :thietbi, :vitri, :tt);
                END;
            """)
            
            db.session.execute(sql_proc, {
                'bh': ma_buoi_hoc, 
                'sv': student_id,
                'pt': phuong_thuc,
                'thietbi': user_agent,  
                'vitri': ip_address,    
                'tt': 'Co Mat'         
            })
        
            # Ghi audit log thành công
            db.session.execute(text("BEGIN PROC_THEM_AUDIT_LOG(:u, :a, :d, :ip, :ua, :s); END;"), {
                'u': student_id, 'a': 'Điểm danh', 
                'd': f'Điểm danh thành công bằng {phuong_thuc} - Buổi học: {ma_buoi_hoc}',
                'ip': ip_address, 'ua': user_agent, 's': 'Thành công'
            })
            
            db.session.commit()
            flash(f'Điểm danh thành công bằng {phuong_thuc}!', 'success')
                
        except Exception as e:
            error_msg = str(e)
            if "ORA-00001" in error_msg: 
                flash('Bạn đã điểm danh môn này rồi!', 'warning')
            elif "ORA-20001" in error_msg: 
                flash('Lỗi: Không phải ngày học!', 'error')
            elif "ORA-20002" in error_msg: 
                flash('Lỗi: Chưa đến giờ hoặc đã hết giờ!', 'error')
            else: 
                flash(f'Lỗi hệ thống: {error_msg}', 'error')
                # Ghi log lỗi
                try:
                    db.session.execute(text("BEGIN PROC_THEM_AUDIT_LOG(:u, :a, :d, :ip, :ua, :s); END;"), {
                        'u': student_id, 'a': 'Điểm danh', 
                        'd': f'Lỗi điểm danh: {error_msg}',
                        'ip': ip_address, 'ua': user_agent, 's': 'Thất bại'
                    })
                    db.session.commit()
                except:
                    pass

        return redirect(url_for('student_dashboard'))
    except Exception as e:
        flash(f'Lỗi hệ thống khi xử lý điểm danh: {str(e)}', 'error')
        try:
            db.session.execute(text("BEGIN PROC_THEM_AUDIT_LOG(:u, :a, :d, :ip, :ua, :s); END;"), {
                'u': student_id, 'a': 'Điểm danh', 
                'd': f'Lỗi hệ thống: {str(e)}',
                'ip': ip_address, 'ua': user_agent, 's': 'Thất bại'
            })
            db.session.commit()
        except:
            pass
        return redirect(url_for('student_dashboard'))

@app.route('/submit_attendance', methods=['POST'])
def submit_attendance():
    code = request.form.get('otp_code')
    if not code:
        flash('Mã OTP không được để trống!', 'error')
        return redirect(url_for('student_dashboard'))
    
    # Loại bỏ khoảng trắng và chuẩn hóa OTP
    code = code.strip()
    
    if not code.isdigit() or len(code) != 6:
        flash('Mã OTP phải là 6 chữ số!', 'error')
        return redirect(url_for('student_dashboard'))
    
    return redirect(url_for('student_attendance_qr', code=code))

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        res = db.session.execute(text("SELECT * FROM NGUOI_DUNG WHERE EMAIL=:e"), {'e':email}).fetchone()
        
        if res:
            otp = str(random.randint(1000, 9999))
            
            if send_reset_email(email, otp):
                session['reset_otp'] = otp
                session['reset_email'] = email
                flash(f'Đã gửi mã xác nhận về {email}. Vui lòng kiểm tra mail!', 'success')
                return redirect(url_for('verify_code'))
            else:
                flash('Lỗi gửi email! Vui lòng thử lại.', 'error')
        else:
            flash('Email này chưa đăng ký trong hệ thống!', 'error')
            
    return render_template('forgot_password.html')

@app.route('/verify_code', methods=['GET', 'POST'])
def verify_code():
    """Bước 2: Nhập mã OTP"""
    if 'reset_email' not in session:
        return redirect(url_for('forgot_password'))
        
    if request.method == 'POST':
        user_code = request.form['otp']
        server_code = session.get('reset_otp')
        
        if user_code == server_code:
            flash('Xác thực thành công! Hãy đặt mật khẩu mới.', 'success')
            return redirect(url_for('reset_new_password'))
        else:
            flash('Mã xác nhận không đúng!', 'error')
            
    return render_template('verify_code.html')

@app.route('/reset_new_password', methods=['GET', 'POST'])
def reset_new_password():
    if 'reset_email' not in session or 'reset_otp' not in session:
        return redirect(url_for('login'))
        
    if request.method == 'POST':
        new_pass = request.form['new_password']
        confirm_pass = request.form['confirm_password']
        email = session['reset_email']
        
        if new_pass != confirm_pass:
            flash('Mật khẩu xác nhận không khớp!', 'error')
        else:
            try:
                user = db.session.execute(text("SELECT MA_NGUOI_DUNG, TEN_DANG_NHAP FROM NGUOI_DUNG WHERE EMAIL=:e"), {'e': email}).fetchone()
                if user:
                    db.session.execute(text("""
                        DECLARE
                            v_salt VARCHAR2(100);
                            v_hash VARCHAR2(255);
                        BEGIN
                            v_salt := FUNC_GEN_SALT();
                            v_hash := FUNC_HASH_PASS(:p, v_salt);
                            
                            UPDATE NGUOI_DUNG 
                            SET MAT_KHAU_HASH = v_hash, SALT = v_salt 
                            WHERE MA_NGUOI_DUNG = :id;
                            
                            -- 3. Ghi Audit Log trực tiếp tại đây
                            PROC_THEM_AUDIT_LOG(:id, N'Đổi mật khẩu', N'Khôi phục mật khẩu qua Email', :ip, :ua, 'Thành công');
                            COMMIT;
                        END;
                    """), {
                        'p': new_pass, 
                        'id': user[0],
                        'ip': request.remote_addr,
                        'ua': request.user_agent.string[:250]
                    })
                    
                    session.pop('reset_email', None)
                    session.pop('reset_otp', None)
                    flash('Khôi phục mật khẩu thành công! Hãy đăng nhập.', 'success')
                    return redirect(url_for('login'))
            except Exception as e:
                print(e)
                flash('Lỗi hệ thống khi đổi mật khẩu.', 'error')
    return render_template('reset_password.html')

@app.route('/export_excel')
def export_excel():
    if session.get('role') != 'teacher':
        return redirect(url_for('login'))
    
    data = db.session.execute(text("""
        SELECT u.TEN_DANG_NHAP, u.HO_TEN, u.EMAIL,
               l.THOI_GIAN_DIEM_DANH, l.PHUONG_THUC, mh.TEN_MON
        FROM LICHSU_DIEMDANH l
        JOIN NGUOI_DUNG u ON l.MA_SINH_VIEN = u.MA_NGUOI_DUNG
        JOIN LICH_HOC lh ON l.MA_BUOI_HOC = lh.MA_BUOI_HOC
        JOIN LOP_HOC_PHAN lhp ON lh.MA_LOP_HP = lhp.MA_LOP_HP
        JOIN MON_HOC mh ON lhp.MA_MON = mh.MA_MON
        WHERE lhp.MA_GIANG_VIEN = :uid
        ORDER BY l.THOI_GIAN_DIEM_DANH DESC
    """), {'uid': session['user_id']}).fetchall()
    
    if not data:
        flash('Chưa có dữ liệu điểm danh!', 'warning')
        return redirect(url_for('teacher_dashboard'))
    
    df = pd.DataFrame(data, columns=['MSSV', 'Họ Tên', 'Email', 'Thời gian', 'Phương thức', 'Môn học'])
    
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
        df.to_excel(writer, index=False, sheet_name='Điểm danh')
        workbook = writer.book
        worksheet = writer.sheets['Điểm danh']

        header_format = workbook.add_format({
            'bold': True,
            'bg_color': '#d9ead3',
            'align': 'center',
            'valign': 'vcenter',
            'border': 1
        })
        for col, header in enumerate(df.columns):
            worksheet.write(0, col, header, header_format)
        
        for i, col in enumerate(df.columns):
            max_len = max(
                df[col].astype(str).str.len().max(),
                len(col)
            )+2
            worksheet.set_column(i, i, max_len)
    
    output.seek(0)
    return send_file(
        output,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        as_attachment=True,
        download_name=f'diem_danh_{datetime.now().strftime("%Y%m%d_%H%M%S")}.xlsx'
    )    

# --- TÍNH NĂNG SAO LƯU & KHÔI PHỤC ---
@app.route('/admin/backup')
def admin_backup():
    if session.get('role') != 'admin': 
        return redirect(url_for('login'))
    
    try:
        sql_users = text("""
            SELECT MA_NGUOI_DUNG, TEN_DANG_NHAP, MAT_KHAU_HASH, HO_TEN, EMAIL, MA_VAI_TRO, SALT 
            FROM NGUOI_DUNG
        """)
        users = db.session.execute(sql_users).fetchall()
        
        users_data = []
        for u in users:
            users_data.append({
                'ma_nguoi_dung': u[0], 
                'ten_dang_nhap': u[1], 
                'mat_khau_hash': u[2] if u[2] else None,
                'ho_ten': u[3] if u[3] else None, 
                'email': u[4] if u[4] else None, 
                'ma_vai_tro': u[5] if u[5] else None, 
                'salt': u[6] if u[6] else None
            })

        sql_att = text("""
            SELECT MA_BUOI_HOC, MA_SINH_VIEN, THOI_GIAN_DIEM_DANH, TRANG_THAI, PHUONG_THUC 
            FROM LICHSU_DIEMDANH
        """)
        attendance = db.session.execute(sql_att).fetchall()
        
        att_data = []
        for a in attendance:
            time_str = a[2].strftime('%Y-%m-%d %H:%M:%S') if a[2] else None
            
            att_data.append({
                'ma_buoi_hoc': a[0] if a[0] else None, 
                'ma_sinh_vien': a[1] if a[1] else None, 
                'thoi_gian': time_str,
                'trang_thai': a[3] if a[3] else None, 
                'phuong_thuc': a[4] if a[4] else None
            })

        backup_data = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'users': users_data,
            'attendance': att_data
        }
        
        json_str = json.dumps(backup_data, indent=4, ensure_ascii=False)
        mem = io.BytesIO()
        mem.write(json_str.encode('utf-8'))
        mem.seek(0)
        
        filename = f"backup_huit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        response = send_file(
            mem, 
            mimetype='application/json',
            as_attachment=True,
            download_name=filename
        )
        
        # Đảm bảo file được tải xuống đúng cách
        response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
        response.headers['Content-Type'] = 'application/json; charset=utf-8'
        
        return response

    except Exception as e:
        print(f"Lỗi BACKUP: {e}")
        import traceback
        traceback.print_exc()
        flash(f'Lỗi sao lưu: {str(e)}', 'error')
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/restore', methods=['POST'])
def admin_restore():
    if session.get('role') != 'admin': return redirect(url_for('login'))
    
    file = request.files.get('backup_file')
    if not file: return redirect(url_for('admin_dashboard'))

    try:
        data = json.load(file)
        current_admin_id = session.get('user_id')

        # Xóa dữ liệu cũ
        db.session.execute(text("DELETE FROM LICHSU_DIEMDANH"))
        
        # Khôi phục users
        for u in data.get('users', []):
            if u.get('ma_nguoi_dung') == current_admin_id: continue 
            
            check = db.session.execute(text("SELECT 1 FROM NGUOI_DUNG WHERE TEN_DANG_NHAP=:u"), {'u': u['ten_dang_nhap']}).fetchone()
            if not check:
                sql = text("""
                    INSERT INTO NGUOI_DUNG (TEN_DANG_NHAP, MAT_KHAU_HASH, HO_TEN, EMAIL, MA_VAI_TRO, SALT)
                    VALUES (:user, :pass, :name, :email, :role, :salt)
                """)
                db.session.execute(sql, {
                    'user': u['ten_dang_nhap'], 'pass': u['mat_khau_hash'],
                    'name': u['ho_ten'], 'email': u['email'], 'role': u['ma_vai_tro'],
                    'salt': u['salt']
                })

        # Khôi phục dữ liệu điểm danh
        for att in data.get('attendance', []):
            if att.get('ma_buoi_hoc') and att.get('ma_sinh_vien'):
                try:
                    # Kiểm tra xem đã tồn tại chưa để tránh duplicate
                    check_att = db.session.execute(text("""
                        SELECT 1 FROM LICHSU_DIEMDANH 
                        WHERE MA_BUOI_HOC = :bh AND MA_SINH_VIEN = :sv
                    """), {
                        'bh': att['ma_buoi_hoc'], 
                        'sv': att['ma_sinh_vien']
                    }).fetchone()
                    
                    if not check_att:
                        thoi_gian = att.get('thoi_gian')
                        if thoi_gian:
                            sql_att = text("""
                                INSERT INTO LICHSU_DIEMDANH 
                                (MA_BUOI_HOC, MA_SINH_VIEN, THOI_GIAN_DIEM_DANH, TRANG_THAI, PHUONG_THUC)
                                VALUES (:bh, :sv, TO_TIMESTAMP(:tg, 'YYYY-MM-DD HH24:MI:SS'), :tt, :pt)
                            """)
                            db.session.execute(sql_att, {
                                'bh': att['ma_buoi_hoc'],
                                'sv': att['ma_sinh_vien'],
                                'tg': thoi_gian,
                                'tt': att.get('trang_thai'),
                                'pt': att.get('phuong_thuc')
                            })
                        else:
                            # Nếu không có thời gian, dùng SYSDATE
                            sql_att = text("""
                                INSERT INTO LICHSU_DIEMDANH 
                                (MA_BUOI_HOC, MA_SINH_VIEN, THOI_GIAN_DIEM_DANH, TRANG_THAI, PHUONG_THUC)
                                VALUES (:bh, :sv, SYSDATE, :tt, :pt)
                            """)
                            db.session.execute(sql_att, {
                                'bh': att['ma_buoi_hoc'],
                                'sv': att['ma_sinh_vien'],
                                'tt': att.get('trang_thai'),
                                'pt': att.get('phuong_thuc')
                            })
                except Exception as e:
                    print(f"Lỗi khi khôi phục attendance: {e}")
                    import traceback
                    traceback.print_exc()
                    # Tiếp tục với record tiếp theo nếu có lỗi
                    continue

        db.session.commit()
        flash('Khôi phục dữ liệu thành công!', 'success')

    except Exception as e:
        db.session.rollback()
        print(f"Lỗi restore: {e}")
        import traceback
        traceback.print_exc()
        flash(f'Lỗi khôi phục: {str(e)}', 'error')

    return redirect(url_for('admin_dashboard'))

@app.route('/logout')
def logout():
    """Đăng xuất"""
    session.clear()
    flash('Đã đăng xuất thành công!', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')




