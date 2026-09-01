import os
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from tinydb import TinyDB, Query
from datetime import datetime
from railfence import encrypt_file_content, decrypt_file_content, rail_encrypt, rail_decrypt
import io

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET","secret")


db = TinyDB('insurance_db.json')
users_table = db.table('users')
claims_table = db.table('claims')
messages_table = db.table('messages')
files_table = db.table('files')
settings_table = db.table('settings')

UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'doc', 'docx'}
RAILS = 3

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_user_by_username(username):
    User = Query()
    return users_table.get(User.username == username)

def get_user_by_id(user_id):
    User = Query()
    return users_table.get(User.id == user_id)

def generate_id():
    return datetime.now().strftime('%Y%m%d%H%M%S%f')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        email = request.form['email']
        full_name = request.form['full_name']
        phone = request.form['phone']
        address = request.form['address']
        role = request.form['role']
        
        if password != confirm_password:
            flash('Passwords do not match!', 'error')
            return redirect(url_for('signup'))
        
        if get_user_by_username(username):
            flash('Username already exists!', 'error')
            return redirect(url_for('signup'))
        
        user_data = {
            'id': generate_id(),
            'username': username,
            'password': generate_password_hash(password),
            'email': email,
            'full_name': full_name,
            'phone': phone,
            'address': address,
            'role': role,
            'created_at': datetime.now().isoformat(),
            'status': 'active'
        }
        users_table.insert(user_data)
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = get_user_by_username(username)
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            session['full_name'] = user['full_name']
            
            if user['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif user['role'] == 'authority':
                return redirect(url_for('authority_dashboard'))
            else:
                return redirect(url_for('client_dashboard'))
        else:
            flash('Invalid username or password!', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))

@app.route('/admin/dashboard')
def admin_dashboard():
    if session.get('role') != 'admin':
        flash('Access denied!', 'error')
        return redirect(url_for('login'))
    
    total_users = len(users_table.all())
    total_claims = len(claims_table.all())
    Claim = Query()
    pending_claims = len(claims_table.search(Claim.status == 'pending'))
    approved_claims = len(claims_table.search(Claim.status == 'approved'))
    
    return render_template('admin/dashboard.html', 
                         total_users=total_users,
                         total_claims=total_claims,
                         pending_claims=pending_claims,
                         approved_claims=approved_claims)

@app.route('/admin/users')
def admin_users():
    if session.get('role') != 'admin':
        flash('Access denied!', 'error')
        return redirect(url_for('login'))
    
    users = users_table.all()
    return render_template('admin/users.html', users=users)

@app.route('/admin/users/edit/<user_id>', methods=['GET', 'POST'])
def admin_edit_user(user_id):
    if session.get('role') != 'admin':
        flash('Access denied!', 'error')
        return redirect(url_for('login'))
    
    User = Query()
    user = users_table.get(User.id == user_id)
    
    if request.method == 'POST':
        users_table.update({
            'full_name': request.form['full_name'],
            'email': request.form['email'],
            'phone': request.form['phone'],
            'status': request.form['status']
        }, User.id == user_id)
        flash('User updated successfully!', 'success')
        return redirect(url_for('admin_users'))
    
    return render_template('admin/edit_user.html', user=user)

@app.route('/admin/users/delete/<user_id>')
def admin_delete_user(user_id):
    if session.get('role') != 'admin':
        flash('Access denied!', 'error')
        return redirect(url_for('login'))
    
    User = Query()
    users_table.remove(User.id == user_id)
    flash('User deleted successfully!', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/claims')
def admin_claims():
    if session.get('role') != 'admin':
        flash('Access denied!', 'error')
        return redirect(url_for('login'))
    
    claims = claims_table.all()
    for claim in claims:
        User = Query()
        user = users_table.get(User.id == claim.get('client_id'))
        claim['client_name'] = user['full_name'] if user else 'Unknown'
    
    return render_template('admin/claims.html', claims=claims)

@app.route('/admin/reports')
def admin_reports():
    if session.get('role') != 'admin':
        flash('Access denied!', 'error')
        return redirect(url_for('login'))
    
    Claim = Query()
    User = Query()
    
    total_claims = len(claims_table.all())
    pending = len(claims_table.search(Claim.status == 'pending'))
    approved = len(claims_table.search(Claim.status == 'approved'))
    rejected = len(claims_table.search(Claim.status == 'rejected'))
    settled = len(claims_table.search(Claim.status == 'settled'))
    
    total_admins = len(users_table.search(User.role == 'admin'))
    total_authorities = len(users_table.search(User.role == 'authority'))
    total_clients = len(users_table.search(User.role == 'client'))
    
    return render_template('admin/reports.html',
                         total_claims=total_claims,
                         pending=pending,
                         approved=approved,
                         rejected=rejected,
                         settled=settled,
                         total_admins=total_admins,
                         total_authorities=total_authorities,
                         total_clients=total_clients)

@app.route('/admin/analytics')
def admin_analytics():
    if session.get('role') != 'admin':
        flash('Access denied!', 'error')
        return redirect(url_for('login'))
    
    claims = claims_table.all()
    Claim = Query()
    
    claim_types = {}
    for claim in claims:
        ctype = claim.get('claim_type', 'Other')
        claim_types[ctype] = claim_types.get(ctype, 0) + 1
    
    monthly_claims = {}
    for claim in claims:
        month = claim.get('created_at', '')[:7]
        monthly_claims[month] = monthly_claims.get(month, 0) + 1
    
    return render_template('admin/analytics.html',
                         claim_types=claim_types,
                         monthly_claims=monthly_claims)

@app.route('/admin/settings', methods=['GET', 'POST'])
def admin_settings():
    if session.get('role') != 'admin':
        flash('Access denied!', 'error')
        return redirect(url_for('login'))
    
    Setting = Query()
    settings = settings_table.get(Setting.id == 'system_settings')
    
    if request.method == 'POST':
        new_settings = {
            'id': 'system_settings',
            'company_name': request.form['company_name'],
            'contact_email': request.form['contact_email'],
            'max_claim_amount': request.form['max_claim_amount'],
            'auto_approve_threshold': request.form['auto_approve_threshold'],
            'updated_at': datetime.now().isoformat()
        }
        
        if settings:
            settings_table.update(new_settings, Setting.id == 'system_settings')
        else:
            settings_table.insert(new_settings)
        
        flash('Settings updated successfully!', 'success')
        return redirect(url_for('admin_settings'))
    
    return render_template('admin/settings.html', settings=settings)

@app.route('/authority/dashboard')
def authority_dashboard():
    if session.get('role') != 'authority':
        flash('Access denied!', 'error')
        return redirect(url_for('login'))
    
    Claim = Query()
    pending_claims = len(claims_table.search(Claim.status == 'pending'))
    under_review = len(claims_table.search(Claim.status == 'under_review'))
    approved = len(claims_table.search(Claim.status == 'approved'))
    total_files = len(files_table.all())
    
    return render_template('authority/dashboard.html',
                         pending_claims=pending_claims,
                         under_review=under_review,
                         approved=approved,
                         total_files=total_files)

@app.route('/authority/verification')
def authority_verification():
    if session.get('role') != 'authority':
        flash('Access denied!', 'error')
        return redirect(url_for('login'))
    
    Claim = Query()
    claims = claims_table.search((Claim.status == 'pending') | (Claim.status == 'under_review'))
    
    for claim in claims:
        User = Query()
        user = users_table.get(User.id == claim.get('client_id'))
        claim['client_name'] = user['full_name'] if user else 'Unknown'
    
    return render_template('authority/verification.html', claims=claims)

@app.route('/authority/verify/<claim_id>', methods=['POST'])
def authority_verify_claim(claim_id):
    if session.get('role') != 'authority':
        flash('Access denied!', 'error')
        return redirect(url_for('login'))
    
    Claim = Query()
    action = request.form.get('action')
    remarks = request.form.get('remarks', '')
    
    if action == 'approve':
        claims_table.update({
            'status': 'approved',
            'verified_by': session.get('user_id'),
            'verified_at': datetime.now().isoformat(),
            'remarks': remarks
        }, Claim.id == claim_id)
        flash('Claim approved successfully!', 'success')
    elif action == 'reject':
        claims_table.update({
            'status': 'rejected',
            'verified_by': session.get('user_id'),
            'verified_at': datetime.now().isoformat(),
            'remarks': remarks
        }, Claim.id == claim_id)
        flash('Claim rejected!', 'warning')
    elif action == 'review':
        claims_table.update({
            'status': 'under_review',
            'reviewed_by': session.get('user_id'),
            'reviewed_at': datetime.now().isoformat()
        }, Claim.id == claim_id)
        flash('Claim marked for review!', 'info')
    
    return redirect(url_for('authority_verification'))

@app.route('/authority/documents')
def authority_documents():
    if session.get('role') != 'authority':
        flash('Access denied!', 'error')
        return redirect(url_for('login'))
    
    File = Query()
    files = files_table.all()
    
    for file in files:
        User = Query()
        uploader = users_table.get(User.id == file.get('uploaded_by'))
        file['uploader_name'] = uploader['full_name'] if uploader else 'Unknown'
    
    return render_template('authority/documents.html', files=files)

@app.route('/authority/approval')
def authority_approval():
    if session.get('role') != 'authority':
        flash('Access denied!', 'error')
        return redirect(url_for('login'))
    
    Claim = Query()
    approved_claims = claims_table.search(Claim.status == 'approved')
    rejected_claims = claims_table.search(Claim.status == 'rejected')
    
    for claim in approved_claims + rejected_claims:
        User = Query()
        user = users_table.get(User.id == claim.get('client_id'))
        claim['client_name'] = user['full_name'] if user else 'Unknown'
    
    return render_template('authority/approval.html', 
                         approved_claims=approved_claims,
                         rejected_claims=rejected_claims)

@app.route('/authority/settle/<claim_id>', methods=['POST'])
def authority_settle_claim(claim_id):
    if session.get('role') != 'authority':
        flash('Access denied!', 'error')
        return redirect(url_for('login'))
    
    Claim = Query()
    settlement_amount = request.form.get('settlement_amount')
    
    claims_table.update({
        'status': 'settled',
        'settlement_amount': settlement_amount,
        'settled_by': session.get('user_id'),
        'settled_at': datetime.now().isoformat()
    }, Claim.id == claim_id)
    
    flash('Claim settled successfully!', 'success')
    return redirect(url_for('authority_approval'))

@app.route('/authority/files', methods=['GET', 'POST'])
def authority_files():
    if session.get('role') != 'authority':
        flash('Access denied!', 'error')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file selected!', 'error')
            return redirect(url_for('authority_files'))
        
        file = request.files['file']
        recipient_id = request.form.get('recipient_id')
        description = request.form.get('description', '')
        
        if file.filename == '':
            flash('No file selected!', 'error')
            return redirect(url_for('authority_files'))
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_content = file.read()
            
            original_path = os.path.join(UPLOAD_FOLDER, 'original', filename)
            with open(original_path, 'wb') as f:
                f.write(file_content)
            
            encrypted_content = encrypt_file_content(file_content, RAILS)
            encrypted_filename = f"encrypted_{filename}.enc"
            encrypted_path = os.path.join(UPLOAD_FOLDER, 'encrypted', encrypted_filename)
            with open(encrypted_path, 'w') as f:
                f.write(encrypted_content)
            
            file_data = {
                'id': generate_id(),
                'original_filename': filename,
                'encrypted_filename': encrypted_filename,
                'uploaded_by': session.get('user_id'),
                'recipient_id': recipient_id,
                'description': description,
                'created_at': datetime.now().isoformat(),
                'rails': RAILS
            }
            files_table.insert(file_data)
            
            flash('File uploaded and encrypted successfully!', 'success')
        else:
            flash('Invalid file type!', 'error')
    
    User = Query()
    clients = users_table.search(User.role == 'client')
    
    File = Query()
    uploaded_files = files_table.search(File.uploaded_by == session.get('user_id'))
    
    return render_template('authority/files.html', clients=clients, files=uploaded_files)

@app.route('/authority/download/encrypted/<file_id>')
def authority_download_encrypted(file_id):
    if session.get('role') != 'authority':
        flash('Access denied!', 'error')
        return redirect(url_for('login'))
    
    File = Query()
    file_record = files_table.get(File.id == file_id)
    
    if file_record:
        encrypted_path = os.path.join(UPLOAD_FOLDER, 'encrypted', file_record['encrypted_filename'])
        return send_file(encrypted_path, as_attachment=True)
    
    flash('File not found!', 'error')
    return redirect(url_for('authority_files'))

@app.route('/authority/communication', methods=['GET', 'POST'])
def authority_communication():
    if session.get('role') != 'authority':
        flash('Access denied!', 'error')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        recipient_id = request.form.get('recipient_id')
        subject = request.form.get('subject')
        message_content = request.form.get('message')
        is_encrypted = request.form.get('encrypt') == 'on'
        
        if is_encrypted:
            message_content = rail_encrypt(message_content, RAILS)
        
        message_data = {
            'id': generate_id(),
            'sender_id': session.get('user_id'),
            'recipient_id': recipient_id,
            'subject': subject,
            'message': message_content,
            'is_encrypted': is_encrypted,
            'created_at': datetime.now().isoformat(),
            'read': False
        }
        messages_table.insert(message_data)
        flash('Message sent successfully!', 'success')
    
    User = Query()
    Message = Query()
    
    users = users_table.all()
    sent_messages = messages_table.search(Message.sender_id == session.get('user_id'))
    received_messages = messages_table.search(Message.recipient_id == session.get('user_id'))
    
    for msg in sent_messages + received_messages:
        sender = users_table.get(User.id == msg.get('sender_id'))
        recipient = users_table.get(User.id == msg.get('recipient_id'))
        msg['sender_name'] = sender['full_name'] if sender else 'Unknown'
        msg['recipient_name'] = recipient['full_name'] if recipient else 'Unknown'
    
    return render_template('authority/communication.html',
                         users=users,
                         sent_messages=sent_messages,
                         received_messages=received_messages)

@app.route('/client/dashboard')
def client_dashboard():
    if session.get('role') != 'client':
        flash('Access denied!', 'error')
        return redirect(url_for('login'))
    
    Claim = Query()
    File = Query()
    Message = Query()
    
    my_claims = claims_table.search(Claim.client_id == session.get('user_id'))
    my_files = files_table.search(File.recipient_id == session.get('user_id'))
    unread_messages = len(messages_table.search(
        (Message.recipient_id == session.get('user_id')) & (Message.read == False)
    ))
    
    pending = len([c for c in my_claims if c.get('status') == 'pending'])
    approved = len([c for c in my_claims if c.get('status') == 'approved'])
    
    return render_template('client/dashboard.html',
                         total_claims=len(my_claims),
                         pending=pending,
                         approved=approved,
                         files_count=len(my_files),
                         unread_messages=unread_messages)

@app.route('/client/submit', methods=['GET', 'POST'])
def client_submit():
    if session.get('role') != 'client':
        flash('Access denied!', 'error')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        claim_data = {
            'id': generate_id(),
            'client_id': session.get('user_id'),
            'claim_type': request.form['claim_type'],
            'policy_number': request.form['policy_number'],
            'incident_date': request.form['incident_date'],
            'claim_amount': request.form['claim_amount'],
            'description': request.form['description'],
            'status': 'pending',
            'created_at': datetime.now().isoformat()
        }
        claims_table.insert(claim_data)
        flash('Claim submitted successfully!', 'success')
        return redirect(url_for('client_tracking'))
    
    return render_template('client/submit.html')

@app.route('/client/documents', methods=['GET', 'POST'])
def client_documents():
    if session.get('role') != 'client':
        flash('Access denied!', 'error')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file selected!', 'error')
            return redirect(url_for('client_documents'))
        
        file = request.files['file']
        claim_id = request.form.get('claim_id')
        description = request.form.get('description', '')
        
        if file.filename == '' :
            flash('No file selected!', 'error')
            return redirect(url_for('client_documents'))
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_content = file.read()
            
            original_path = os.path.join(UPLOAD_FOLDER, 'original', filename)
            with open(original_path, 'wb') as f:
                f.write(file_content)
            
            file_data = {
                'id': generate_id(),
                'original_filename': filename,
                'uploaded_by': session.get('user_id'),
                'claim_id': claim_id,
                'description': description,
                'created_at': datetime.now().isoformat()
            }
            files_table.insert(file_data)
            
            flash('Document uploaded successfully!', 'success')
    
    Claim = Query()
    File = Query()
    my_claims = claims_table.search(Claim.client_id == session.get('user_id'))
    my_documents = files_table.search(File.uploaded_by == session.get('user_id'))
    
    return render_template('client/documents.html', claims=my_claims, documents=my_documents)

@app.route('/client/tracking')
def client_tracking():
    if session.get('role') != 'client':
        flash('Access denied!', 'error')
        return redirect(url_for('login'))
    
    Claim = Query()
    my_claims = claims_table.search(Claim.client_id == session.get('user_id'))
    
    return render_template('client/tracking.html', claims=my_claims)

@app.route('/client/files')
def client_files():
    if session.get('role') != 'client':
        flash('Access denied!', 'error')
        return redirect(url_for('login'))
    
    File = Query()
    my_files = files_table.search(File.recipient_id == session.get('user_id'))
    
    for file in my_files:
        User = Query()
        uploader = users_table.get(User.id == file.get('uploaded_by'))
        file['uploader_name'] = uploader['full_name'] if uploader else 'Unknown'
    
    return render_template('client/files.html', files=my_files)

@app.route('/client/download/encrypted/<file_id>')
def client_download_encrypted(file_id):
    if session.get('role') != 'client':
        flash('Access denied!', 'error')
        return redirect(url_for('login'))
    
    File = Query()
    file_record = files_table.get(File.id == file_id)
    
    if file_record and file_record.get('recipient_id') == session.get('user_id'):
        encrypted_path = os.path.join(UPLOAD_FOLDER, 'encrypted', file_record['encrypted_filename'])
        return send_file(encrypted_path, as_attachment=True)
    
    flash('File not found or access denied!', 'error')
    return redirect(url_for('client_files'))

@app.route('/client/download/decrypted/<file_id>')
def client_download_decrypted(file_id):
    if session.get('role') != 'client':
        flash('Access denied!', 'error')
        return redirect(url_for('login'))
    
    File = Query()
    file_record = files_table.get(File.id == file_id)
    
    if file_record and file_record.get('recipient_id') == session.get('user_id'):
        encrypted_path = os.path.join(UPLOAD_FOLDER, 'encrypted', file_record['encrypted_filename'])
        
        with open(encrypted_path, 'r') as f:
            encrypted_content = f.read()
        
        decrypted_content = decrypt_file_content(encrypted_content, file_record.get('rails', RAILS))
        
        return send_file(
            io.BytesIO(decrypted_content),
            as_attachment=True,
            download_name=file_record['original_filename']
        )
    
    flash('File not found or access denied!', 'error')
    return redirect(url_for('client_files'))

@app.route('/client/profile', methods=['GET', 'POST'])
def client_profile():
    if session.get('role') != 'client':
        flash('Access denied!', 'error')
        return redirect(url_for('login'))
    
    User = Query()
    user = users_table.get(User.id == session.get('user_id'))
    
    if request.method == 'POST':
        update_data = {
            'full_name': request.form['full_name'],
            'email': request.form['email'],
            'phone': request.form['phone'],
            'address': request.form['address']
        }
        
        if request.form.get('new_password'):
            if check_password_hash(user['password'], request.form.get('current_password', '')):
                update_data['password'] = generate_password_hash(request.form['new_password'])
            else:
                flash('Current password is incorrect!', 'error')
                return redirect(url_for('client_profile'))
        
        users_table.update(update_data, User.id == session.get('user_id'))
        session['full_name'] = update_data['full_name']
        flash('Profile updated successfully!', 'success')
    
    return render_template('client/profile.html', user=user)

@app.route('/message/decrypt/<message_id>')
def decrypt_message(message_id):
    if not session.get('user_id'):
        flash('Please login first!', 'error')
        return redirect(url_for('login'))
    
    Message = Query()
    message = messages_table.get(Message.id == message_id)
    
    if message and message.get('is_encrypted'):
        decrypted = rail_decrypt(message['message'], RAILS)
        return {'decrypted': decrypted}
    
    return {'decrypted': message.get('message', '')}

@app.route('/message/read/<message_id>')
def mark_message_read(message_id):
    if not session.get('user_id'):
        return {'success': False}
    
    Message = Query()
    messages_table.update({'read': True}, Message.id == message_id)
    return {'success': True}

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
