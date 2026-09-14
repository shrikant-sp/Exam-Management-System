from flask import Flask, flash, g, redirect, render_template, request, session, url_for
from flask_mail import Mail, Message
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
import json, os, secrets, sqlite3
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'change-this-local-secret')
app.config['DATABASE'] = os.path.join(app.root_path, 'exam_portal.db')
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', '587'))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'true').lower() == 'true'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_FROM') or app.config['MAIL_USERNAME']
app.jinja_env.filters['fromjson'] = json.loads
mail = Mail(app)
otp_serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'], salt='exam-portal-login-otp')

def db():
    if 'db' not in g:
        g.db = sqlite3.connect(app.config['DATABASE'])
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(_error=None):
    connection = g.pop('db', None)
    if connection: connection.close()

def init_db():
    with app.app_context():
        c = db()
        c.executescript('''
        CREATE TABLE IF NOT EXISTS admins (id INTEGER PRIMARY KEY, name TEXT NOT NULL, erp TEXT UNIQUE NOT NULL, email TEXT UNIQUE NOT NULL, phone TEXT, password TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS students (id INTEGER PRIMARY KEY, name TEXT NOT NULL, current_year TEXT, admission_year TEXT, caste TEXT, erp TEXT UNIQUE NOT NULL, course TEXT, mobile TEXT, email TEXT, password TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS student_updates (id INTEGER PRIMARY KEY, student_id INTEGER NOT NULL, data TEXT NOT NULL, submitted_at TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'Pending');
        CREATE TABLE IF NOT EXISTS classrooms (id INTEGER PRIMARY KEY, floor_no INTEGER NOT NULL, room_no TEXT NOT NULL, capacity INTEGER NOT NULL DEFAULT 30);
        CREATE TABLE IF NOT EXISTS exams (id INTEGER PRIMARY KEY, exam_type TEXT NOT NULL, semester TEXT NOT NULL, year TEXT NOT NULL, branch TEXT NOT NULL, classes TEXT NOT NULL, enrollments TEXT NOT NULL, created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS marks (id INTEGER PRIMARY KEY, student_id INTEGER NOT NULL, subject TEXT NOT NULL, test_no TEXT NOT NULL, marks TEXT NOT NULL);
        ''')
        c.commit()

def admin_required(): return bool(session.get('admin_id'))
def student_required(): return bool(session.get('student_id'))

def send_otp_email(recipient, otp):
    """Send a login OTP through Flask-Mail."""
    if not all((app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'], app.config['MAIL_DEFAULT_SENDER'])):
        return False, 'Email is not configured. Set MAIL_SERVER, MAIL_USERNAME, MAIL_PASSWORD, and MAIL_FROM.'
    try:
        message = Message('Your Exam Portal login code', recipients=[recipient])
        message.body = f'Your Exam Portal verification code is: {otp}\n\nThis code expires in 10 minutes. Do not share it with anyone.'
        mail.send(message)
        return True, None
    except Exception as error:
        return False, f'Unable to send the OTP email: {error}'

def start_otp_login(user, role):
    otp = f'{secrets.randbelow(1_000_000):06d}'
    sent, error = send_otp_email(user['email'], otp)
    if not sent:
        flash(error, 'error')
        return False
    session.clear()
    session['otp_token'] = otp_serializer.dumps({'otp': otp, 'user_id': user['id'], 'role': role, 'name': user['name']})
    session['otp_email'] = user['email']
    return True

@app.route('/')
def index(): return render_template('index.html')

@app.route('/admin/login', methods=['GET','POST'])
def adminlogin():
    if request.method == 'POST':
        row = db().execute('SELECT * FROM admins WHERE erp=? AND password=?', (request.form['erp'], request.form['password'])).fetchone()
        if row:
            if start_otp_login(row, 'admin'):
                return redirect(url_for('verifyotp'))
            return render_template('adminlogin.html')
        flash('Invalid ERP number or password.', 'error')
    return render_template('adminlogin.html')

@app.route('/admin/signup', methods=['GET','POST'])
def adminsignup():
    if request.method == 'POST':
        try:
            db().execute('INSERT INTO admins(name,erp,email,phone,password) VALUES(?,?,?,?,?)', (request.form['name'],request.form['erp'],request.form['email'],request.form['phone'],request.form['password']))
            db().commit(); flash('Account created. Please log in.', 'success'); return redirect(url_for('adminlogin'))
        except sqlite3.IntegrityError: flash('That ERP number or email is already registered.', 'error')
    return render_template('adminsignup.html')

@app.route('/admin/forgot', methods=['GET','POST'])
def forgotpassword():
    if request.method == 'POST':
        found = db().execute('SELECT id FROM admins WHERE email=?', (request.form['email'],)).fetchone()
        if found: session['reset_admin_id'] = found['id']; flash('Reset link verified. Create your new password below.', 'success'); return redirect(url_for('adminreset'))
        flash('No admin account uses that email address.', 'error')
    return render_template('forgotpassword.html')

@app.route('/admin/reset', methods=['GET','POST'])
def adminreset():
    if not session.get('reset_admin_id'): return redirect(url_for('forgotpassword'))
    if request.method == 'POST':
        if request.form['password'] != request.form['confirm']: flash('Passwords do not match.', 'error')
        else:
            db().execute('UPDATE admins SET password=? WHERE id=?', (request.form['password'], session.pop('reset_admin_id'))); db().commit()
            flash('Password reset successfully. Please log in.', 'success'); return redirect(url_for('adminlogin'))
    return render_template('adminreset.html')

@app.route('/admin/dashboard', methods=['GET','POST'])
def adashboard():
    if not admin_required(): return redirect(url_for('adminlogin'))
    rooms = db().execute('SELECT * FROM classrooms ORDER BY floor_no, room_no').fetchall()
    if request.method == 'POST':
        enrollments = ','.join(x.strip() for x in request.form['enrollments'].replace('\n', ',').split(',') if x.strip())
        selected_classes = request.form.getlist('classes')
        classes = ', '.join(selected_classes)
        if not classes:
            flash('Select at least one classroom for this exam.', 'error')
            return render_template('adashboard.html', rooms=rooms)
        c = db()
        c.execute('INSERT INTO exams(exam_type,semester,year,branch,classes,enrollments,created_at) VALUES(?,?,?,?,?,?,?)', (request.form['exam_type'],request.form['semester'],request.form['year'],request.form['branch'],classes,enrollments,datetime.now().isoformat()))
        placeholders = ','.join('?' for _ in selected_classes)
        c.execute(f'DELETE FROM classrooms WHERE room_no IN ({placeholders})', selected_classes)
        c.commit(); flash('Exam created. The selected classrooms have been removed from Classroom Setup.', 'success'); return redirect(url_for('allocation'))
    return render_template('adashboard.html', rooms=rooms)

@app.route('/admin/allocation')
def allocation():
    if not admin_required(): return redirect(url_for('adminlogin'))
    return render_template('aAllocation.html', exams=db().execute('SELECT * FROM exams ORDER BY id DESC').fetchall())

@app.route('/admin/allocation/<int:exam_id>/delete', methods=['POST'])
def delete_exam(exam_id):
    if admin_required(): db().execute('DELETE FROM exams WHERE id=?',(exam_id,)); db().commit(); flash('Allocation deleted.', 'success')
    return redirect(url_for('allocation'))

@app.route('/admin/allocation/<int:exam_id>/edit', methods=['GET','POST'])
def edit_exam(exam_id):
    if not admin_required(): return redirect(url_for('adminlogin'))
    c = db(); exam = c.execute('SELECT * FROM exams WHERE id=?', (exam_id,)).fetchone()
    if not exam: return redirect(url_for('allocation'))
    if request.method == 'POST':
        enrollments = ','.join(x.strip() for x in request.form['enrollments'].replace('\n', ',').split(',') if x.strip())
        c.execute('UPDATE exams SET exam_type=?,semester=?,year=?,branch=?,enrollments=? WHERE id=?', (request.form['exam_type'],request.form['semester'],request.form['year'],request.form['branch'],enrollments,exam_id))
        c.commit(); flash('Allocation updated.', 'success'); return redirect(url_for('allocation'))
    return render_template('editexam.html', exam=exam)

@app.route('/admin/allocation/<int:exam_id>/view')
def view_exam(exam_id):
    if not admin_required(): return redirect(url_for('adminlogin'))
    exam=db().execute('SELECT * FROM exams WHERE id=?',(exam_id,)).fetchone()
    if not exam: return redirect(url_for('allocation'))
    students = exam['enrollments'].split(','); rooms = [room.strip() for room in exam['classes'].split(',') if room.strip()]
    seats=[]
    for i, erp in enumerate(students):
        room = rooms[i % len(rooms)] if rooms else 'TBA'; seats.append((erp, room, i//max(len(rooms), 1) + 1))
    return render_template('examview.html', exam=exam, seats=seats)

@app.route('/admin/classroom', methods=['GET','POST'])
def classroom():
    if not admin_required(): return redirect(url_for('adminlogin'))
    if request.method == 'POST':
        floor=int(request.form['floor']); count=int(request.form['count']); capacity=int(request.form['capacity'])
        c=db(); c.execute('DELETE FROM classrooms WHERE floor_no=?',(floor,))
        for room in range(1, count + 1):
            room_number = f'{floor}{room:02d}' if floor > 0 else f'G{room:02d}'
            c.execute('INSERT INTO classrooms(floor_no,room_no,capacity) VALUES(?,?,?)', (floor, room_number, capacity))
        c.commit(); flash('Classrooms saved.', 'success'); return redirect(url_for('classroom'))
    return render_template('aclassroom.html', rooms=db().execute('SELECT * FROM classrooms ORDER BY floor_no,room_no').fetchall())

@app.route('/admin/classroom/<int:classroom_id>/delete', methods=['POST'])
def delete_classroom(classroom_id):
    if not admin_required(): return redirect(url_for('adminlogin'))
    c = db()
    room = c.execute('SELECT room_no FROM classrooms WHERE id=?', (classroom_id,)).fetchone()
    if room:
        c.execute('DELETE FROM classrooms WHERE id=?', (classroom_id,))
        c.commit()
        flash(f"Classroom {room['room_no']} deleted.", 'success')
    return redirect(url_for('classroom'))

@app.route('/admin/students', methods=['GET','POST'])
def studentinfo():
    if not admin_required(): return redirect(url_for('adminlogin'))
    if request.method == 'POST':
        try:
            db().execute('INSERT INTO students(name,current_year,admission_year,caste,erp,course,mobile,email,password) VALUES(?,?,?,?,?,?,?,?,?)', tuple(request.form[k] for k in ['name','current_year','admission_year','caste','erp','course','mobile','email','password']))
            db().commit(); flash('Student added.', 'success')
        except sqlite3.IntegrityError: flash('That ERP number already exists.', 'error')
    query = request.args.get('q', '').strip()
    sql = 'SELECT * FROM students'
    params = []
    if query:
        sql += ' WHERE name LIKE ? OR erp LIKE ? OR course LIKE ? OR email LIKE ?'
        params = [f'%{query}%'] * 4
    students = db().execute(sql + ' ORDER BY name', params).fetchall()
    updates = db().execute('SELECT student_updates.*, students.name, students.erp FROM student_updates JOIN students ON students.id=student_updates.student_id WHERE student_updates.status="Pending" ORDER BY submitted_at DESC').fetchall()
    return render_template('studentinfo.html', students=students, updates=updates, query=query)

@app.route('/admin/students/<int:student_id>/edit', methods=['GET', 'POST'])
def edit_student(student_id):
    if not admin_required(): return redirect(url_for('adminlogin'))
    c = db(); student = c.execute('SELECT * FROM students WHERE id=?', (student_id,)).fetchone()
    if not student: return redirect(url_for('studentinfo'))
    if request.method == 'POST':
        fields = ['name','current_year','admission_year','caste','erp','course','mobile','email']
        try:
            c.execute('UPDATE students SET name=?,current_year=?,admission_year=?,caste=?,erp=?,course=?,mobile=?,email=? WHERE id=?', tuple(request.form[k] for k in fields) + (student_id,))
            c.commit(); flash('Student information updated.', 'success'); return redirect(url_for('studentinfo'))
        except sqlite3.IntegrityError: flash('That ERP number is already in use.', 'error')
    return render_template('editstudent.html', student=student)

@app.route('/admin/students/<int:student_id>/delete', methods=['POST'])
def delete_student(student_id):
    if not admin_required(): return redirect(url_for('adminlogin'))
    c = db(); c.execute('DELETE FROM marks WHERE student_id=?', (student_id,)); c.execute('DELETE FROM student_updates WHERE student_id=?', (student_id,)); c.execute('DELETE FROM students WHERE id=?', (student_id,)); c.commit()
    flash('Student record deleted.', 'success'); return redirect(url_for('studentinfo'))

@app.route('/admin/student-updates/<int:update_id>/<action>', methods=['POST'])
def handle_student_update(update_id, action):
    if not admin_required() or action not in ('approve', 'reject'): return redirect(url_for('studentinfo'))
    c = db(); update = c.execute('SELECT * FROM student_updates WHERE id=? AND status="Pending"', (update_id,)).fetchone()
    if update:
        if action == 'approve':
            values = json.loads(update['data']); fields = ['name','current_year','admission_year','caste','course','mobile','email']
            c.execute('UPDATE students SET name=?,current_year=?,admission_year=?,caste=?,course=?,mobile=?,email=? WHERE id=?', tuple(values[k] for k in fields) + (update['student_id'],))
        c.execute('UPDATE student_updates SET status=? WHERE id=?', ('Approved' if action == 'approve' else 'Rejected', update_id)); c.commit()
        flash(f'Student update {"approved" if action == "approve" else "rejected"}.', 'success')
    return redirect(url_for('studentinfo'))

@app.route('/admin/marks')
def adminmarks():
    if not admin_required(): return redirect(url_for('adminlogin'))
    return render_template('adminmarks.html', students=db().execute('SELECT * FROM students ORDER BY name').fetchall())

@app.route('/admin/marks/<int:student_id>', methods=['GET','POST'])
def addmarks(student_id):
    if not admin_required(): return redirect(url_for('adminlogin'))
    if request.method == 'POST':
        db().execute('INSERT INTO marks(student_id,subject,test_no,marks) VALUES(?,?,?,?)',(student_id,request.form['subject'],request.form['test_no'],request.form['marks'])); db().commit(); flash('Marks saved.', 'success'); return redirect(url_for('adminmarks'))
    return render_template('addmarks.html', student=db().execute('SELECT * FROM students WHERE id=?',(student_id,)).fetchone())

@app.route('/admin/marks/<int:student_id>/view')
def view_student_marks(student_id):
    if not admin_required(): return redirect(url_for('adminlogin'))
    c = db()
    student = c.execute('SELECT * FROM students WHERE id=?', (student_id,)).fetchone()
    if not student: return redirect(url_for('adminmarks'))
    marks = c.execute('SELECT * FROM marks WHERE student_id=? ORDER BY id DESC', (student_id,)).fetchall()
    return render_template('studentmarks_admin.html', student=student, marks=marks)

@app.route('/admin/marks/edit/<int:mark_id>', methods=['GET', 'POST'])
def editmarks(mark_id):
    if not admin_required(): return redirect(url_for('adminlogin'))
    c = db(); mark = c.execute('SELECT * FROM marks WHERE id=?', (mark_id,)).fetchone()
    if not mark: return redirect(url_for('adminmarks'))
    if request.method == 'POST':
        c.execute('UPDATE marks SET subject=?, test_no=?, marks=? WHERE id=?', (request.form['subject'], request.form['test_no'], request.form['marks'], mark_id))
        c.commit(); flash('Marks updated.', 'success'); return redirect(url_for('view_student_marks', student_id=mark['student_id']))
    return render_template('editmarks.html', mark=mark)

@app.route('/student/login', methods=['GET','POST'])
def studlogin():
    if request.method == 'POST':
        row=db().execute('SELECT * FROM students WHERE erp=? AND password=?',(request.form['erp'],request.form['password'])).fetchone()
        if row:
            if start_otp_login(row, 'student'): return redirect(url_for('verifyotp'))
            return render_template('studlogin.html')
        flash('Invalid ERP number or password. Ask your admin to add your student record.', 'error')
    return render_template('studlogin.html')

@app.route('/verify-otp', methods=['GET', 'POST'])
def verifyotp():
    if not session.get('otp_token'):
        flash('Please log in to receive a verification code.', 'error')
        return redirect(url_for('index'))
    if request.method == 'POST':
        try:
            otp_data = otp_serializer.loads(session['otp_token'], max_age=600)
        except SignatureExpired:
            session.clear(); flash('Your verification code has expired. Please log in again.', 'error'); return redirect(url_for('index'))
        except BadSignature:
            session.clear(); flash('Your verification session is invalid. Please log in again.', 'error'); return redirect(url_for('index'))
        if secrets.compare_digest(request.form.get('otp', ''), otp_data['otp']):
            role = otp_data['role']; user_id = otp_data['user_id']; name = otp_data['name']
            session.clear()
            session[f'{role}_id'] = user_id
            if role == 'admin': session['admin_name'] = name
            return redirect(url_for('adashboard' if role == 'admin' else 'studdashboard'))
        flash('Incorrect verification code.', 'error')
    return render_template('verifyotp.html', email=session['otp_email'])

@app.route('/student/dashboard')
def studdashboard():
    if not student_required(): return redirect(url_for('studlogin'))
    return render_template('studdashboard.html', student=db().execute('SELECT * FROM students WHERE id=?',(session['student_id'],)).fetchone())

@app.route('/student/exam', methods=['GET','POST'])
def studexam():
    if not student_required(): return redirect(url_for('studlogin'))
    result=None
    if request.method == 'POST':
        exam=db().execute('SELECT * FROM exams WHERE exam_type=? AND semester=? AND year=? AND branch=? AND instr(enrollments,?)>0 ORDER BY id DESC LIMIT 1',(request.form['exam_type'],request.form['semester'],request.form['year'],request.form['branch'],request.form['erp'])).fetchone()
        if exam:
            enrolled = exam['enrollments'].split(','); position = enrolled.index(request.form['erp']); rooms = [room.strip() for room in exam['classes'].split(',') if room.strip()]; room = rooms[position % len(rooms)] if rooms else 'TBA'
            result={'found':True,'exam':exam,'erp':request.form['erp'],'bench':position//max(len(rooms),1)+1,'room':room}
        else: result={'found':False}
    return render_template('studexam.html', result=result)

@app.route('/student/marks')
def studmarks():
    if not student_required(): return redirect(url_for('studlogin'))
    return render_template('studmarks.html', marks=db().execute('SELECT * FROM marks WHERE student_id=?',(session['student_id'],)).fetchall())

@app.route('/logout')
def logout(): session.clear(); return redirect(url_for('index'))

if __name__ == '__main__':
    init_db(); app.run(debug=True)
