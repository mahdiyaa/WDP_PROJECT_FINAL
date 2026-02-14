from flask import Blueprint, render_template, request, redirect, url_for, session, flash, current_app
from flask_login import login_user, logout_user, current_user, login_required
from models import User
from datetime import datetime, timedelta
import re
import smtplib
from email.message import EmailMessage
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

auth_bp = Blueprint('auth', __name__)

GMAIL_EMAIL_PATTERN = r'^[a-zA-Z0-9._%+-]+@gmail\.com$'


def is_valid_gmail(email):
    normalized = (email or '').strip().lower()
    return bool(re.match(GMAIL_EMAIL_PATTERN, normalized))


def generate_reset_token(email):
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    return serializer.dumps(email, salt='password-reset-salt')


def verify_reset_token(token, max_age):
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    try:
        return serializer.loads(token, salt='password-reset-salt', max_age=max_age)
    except (SignatureExpired, BadSignature):
        return None


def send_password_reset_email(recipient_email, reset_link):
    mail_username = current_app.config.get('MAIL_USERNAME')
    mail_password = (current_app.config.get('MAIL_APP_PASSWORD') or '').replace(' ', '')
    mail_server = current_app.config.get('MAIL_SERVER')
    mail_port = current_app.config.get('MAIL_PORT')
    use_tls = current_app.config.get('MAIL_USE_TLS', True)

    if not mail_username or not mail_password:
        raise ValueError('MAIL_USERNAME and MAIL_APP_PASSWORD must be configured.')

    msg = EmailMessage()
    msg['Subject'] = 'Genlink Password Reset'
    msg['From'] = mail_username
    msg['To'] = recipient_email
    msg.set_content(
        f"""Hello,

We received a request to reset your Genlink password.

Click the link below to set a new password:
{reset_link}

This link expires in 30 minutes.

If you did not request this, you can ignore this email.
"""
    )

    with smtplib.SMTP(mail_server, mail_port, timeout=30) as server:
        server.ehlo()
        if use_tls:
            server.starttls()
            server.ehlo()
        server.login(mail_username, mail_password)
        server.send_message(msg)


@auth_bp.route('/feedback', methods=['GET', 'POST'])
@login_required
def feedback():
    from database import execute_query

    if request.method == 'POST':
        full_name = request.form.get('full_name', '').strip()
        email = request.form.get('email', '').strip().lower()
        feedback_type = request.form.get('feedback_type', '').strip()
        feedback_text = request.form.get('feedback_text', '').strip()

        if not full_name or not email or not feedback_type or not feedback_text:
            return render_template(
                'auth/feedbackform.html',
                error='Please fill in all fields.',
                form_data=request.form,
                editing=False,
                action_url=url_for('auth.feedback'),
            )

        if not is_valid_gmail(email):
            return render_template(
                'auth/feedbackform.html',
                error='Please enter a valid Gmail address ending with @gmail.com.',
                form_data=request.form,
                editing=False,
                action_url=url_for('auth.feedback'),
            )

        if feedback_type not in {'Positive', 'Negative'}:
            return render_template(
                'auth/feedbackform.html',
                error='Please select a valid feedback type.',
                form_data=request.form,
                editing=False,
                action_url=url_for('auth.feedback'),
            )

        execute_query(
            """
            INSERT INTO feedback (user_id, full_name, email, feedback_type, feedback_text)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (current_user.id, full_name, email, feedback_type, feedback_text),
            commit=True
        )

        flash('Thank you! Your feedback has been submitted.', 'success')
        return redirect(url_for('main.home'))

    return render_template(
        'auth/feedbackform.html',
        form_data={},
        editing=False,
        action_url=url_for('auth.feedback')
    )


@auth_bp.route('/feedback/history', methods=['GET'])
@login_required
def feedback_history():
    from database import execute_query

    feedback_entries = execute_query(
        """
        SELECT id, full_name, email, feedback_type, feedback_text
        FROM feedback
        WHERE user_id = %s
        ORDER BY id DESC
        """,
        (current_user.id,),
        fetch_all=True,
    ) or []

    return render_template('auth/feedback_history.html', feedback_entries=feedback_entries)


@auth_bp.route('/feedback/<int:feedback_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_feedback(feedback_id):
    from database import execute_query

    feedback_entry = execute_query(
        """
        SELECT id, full_name, email, feedback_type, feedback_text
        FROM feedback
        WHERE id = %s AND user_id = %s
        """,
        (feedback_id, current_user.id),
        fetch_one=True,
    )

    if not feedback_entry:
        flash('Feedback entry not found.', 'error')
        return redirect(url_for('auth.feedback_history'))

    if request.method == 'POST':
        full_name = request.form.get('full_name', '').strip()
        email = request.form.get('email', '').strip().lower()
        feedback_type = request.form.get('feedback_type', '').strip()
        feedback_text = request.form.get('feedback_text', '').strip()

        if not full_name or not email or not feedback_type or not feedback_text:
            return render_template(
                'auth/feedbackform.html',
                error='Please fill in all fields.',
                form_data=request.form,
                editing=True,
                action_url=url_for('auth.edit_feedback', feedback_id=feedback_id),
                feedback_id=feedback_id,
            )

        if not is_valid_gmail(email):
            return render_template(
                'auth/feedbackform.html',
                error='Please enter a valid Gmail address ending with @gmail.com.',
                form_data=request.form,
                editing=True,
                action_url=url_for('auth.edit_feedback', feedback_id=feedback_id),
                feedback_id=feedback_id,
            )

        if feedback_type not in {'Positive', 'Negative'}:
            return render_template(
                'auth/feedbackform.html',
                error='Please select a valid feedback type.',
                form_data=request.form,
                editing=True,
                action_url=url_for('auth.edit_feedback', feedback_id=feedback_id),
                feedback_id=feedback_id,
            )

        execute_query(
            """
            UPDATE feedback
            SET full_name = %s, email = %s, feedback_type = %s, feedback_text = %s
            WHERE id = %s AND user_id = %s
            """,
            (full_name, email, feedback_type, feedback_text, feedback_id, current_user.id),
            commit=True,
        )

        flash('Feedback updated successfully.', 'success')
        return redirect(url_for('auth.feedback_history'))

    return render_template(
        'auth/feedbackform.html',
        form_data=feedback_entry,
        editing=True,
        action_url=url_for('auth.edit_feedback', feedback_id=feedback_id),
        feedback_id=feedback_id,
    )


@auth_bp.route('/feedback/<int:feedback_id>/delete', methods=['POST'])
@login_required
def delete_feedback(feedback_id):
    from database import execute_query

    feedback_entry = execute_query(
        "SELECT id FROM feedback WHERE id = %s AND user_id = %s",
        (feedback_id, current_user.id),
        fetch_one=True,
    )

    if not feedback_entry:
        flash('Feedback entry not found.', 'error')
        return redirect(url_for('auth.feedback_history'))

    execute_query(
        "DELETE FROM feedback WHERE id = %s AND user_id = %s",
        (feedback_id, current_user.id),
        commit=True,
    )

    flash('Feedback deleted successfully.', 'success')
    return redirect(url_for('auth.feedback_history'))


@auth_bp.route('/feedback/retrieve-email', methods=['GET'])
@login_required
def retrieve_feedback_email():
    return {'email': current_user.email or ''}, 200


@auth_bp.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()

        if not email:
            return render_template('auth/forgotpassword.html', error='Please enter your email address.')

        if not is_valid_gmail(email):
            return render_template('auth/forgotpassword.html', error='Please use a valid Gmail address ending with @gmail.com.')

        user = User.get_by_email(email)
        if not user:
            return render_template('auth/forgotpassword.html', error='No account found with that email address.')

        token = generate_reset_token(user.email)
        reset_link = url_for('auth.reset_password', token=token, _external=True)
        try:
            send_password_reset_email(user.email, reset_link)
        except smtplib.SMTPAuthenticationError:
            return render_template(
                'auth/forgotpassword.html',
                error='Gmail login failed. Check MAIL_USERNAME and Gmail app password in config.py.'
            )
        except Exception as e:
            return render_template(
                'auth/forgotpassword.html',
                error=f'Could not send reset email: {str(e)[:180]}'
            )

        flash('A password reset link has been sent to your email.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('auth/forgotpassword.html')


@auth_bp.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    max_age = current_app.config.get('RESET_TOKEN_MAX_AGE_SECONDS', 1800)
    email = verify_reset_token(token, max_age)

    if not email:
        flash('This password reset link is invalid or has expired.', 'error')
        return redirect(url_for('auth.forgot_password'))

    if request.method == 'POST':
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        if not password or not confirm_password:
            return render_template('auth/resetpassword.html', token=token, error='Please fill in both password fields.')

        if password != confirm_password:
            return render_template('auth/resetpassword.html', token=token, error='Passwords do not match.')

        password_pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[^A-Za-z0-9]).{8,}$'
        if not re.match(password_pattern, password):
            return render_template(
                'auth/resetpassword.html',
                token=token,
                error='Password must be at least 8 characters and include 1 lowercase, 1 uppercase, 1 number, and 1 special character.'
            )

        from database import execute_query

        existing_user = execute_query(
            'SELECT password_hash FROM users WHERE email = %s',
            (email,),
            fetch_one=True
        )

        if existing_user and existing_user.get('password_hash') == password:
            return render_template(
                'auth/resetpassword.html',
                token=token,
                error='Please enter a new password different from your current one.'
            )

        execute_query(
            'UPDATE users SET password_hash = %s, password_reset_count = password_reset_count + 1 WHERE email = %s',
            (password, email),
            commit=True
        )

        flash('Your password has been reset successfully. Please log in.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('auth/resetpassword.html', token=token)

@auth_bp.route('/signup', methods=['GET', 'POST'])
def signup():
    """About You: main signup step (GET renders form, POST handles submission)."""
    if request.method == 'POST':
        from database import get_db

        # get birthday + calculate age
        birthday_str = request.form.get('birthday', '').strip()
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        first_name = request.form.get('first_name', '').strip()
        last_name = request.form.get('last_name', '').strip()
        display_name = request.form.get('display_name', '').strip()
        phone = request.form.get('phone', '').strip()
        password = request.form.get('password', '')
        location_enabled = request.form.get('location_enabled') == 'on'

        user_data = {
            'username': username,
            'email': email,
            'first_name': first_name,
            'last_name': last_name,
            'display_name': display_name,
            'phone': phone,
            'birthday': birthday_str
        }

        # Validate required fields
        if not all([first_name, last_name, username, email, password, phone, birthday_str]):
            return render_template('auth/signup.html',
                user=user_data,
                error="All required fields must be filled.",
                location_enabled=location_enabled
            )

        # Validate email format
        if not is_valid_gmail(email):
            return render_template('auth/signup.html',
                user=user_data,
                error="Please enter a valid Gmail address ending with @gmail.com.",
                location_enabled=location_enabled
            )

        # Calculate age from birthday
        age_category = None
        age = None
        if birthday_str:
            try:
                birthday = datetime.strptime(birthday_str, '%Y-%m-%d')
                today = datetime.now()
                age = today.year - birthday.year - ((today.month, today.day) < (birthday.month, birthday.day))

                if age < 13:
                    return render_template('auth/signup.html',
                        user=user_data,
                        error="You must be at least 13 years old to sign up.",
                        location_enabled=location_enabled
                    )

                if age < 60:
                    age_category = 'youth'
                else:
                    age_category = 'elderly'
            except ValueError:
                return render_template('auth/signup.html',
                    user=user_data,
                    error="Invalid date format. Please enter a valid birthday.",
                    location_enabled=location_enabled
                )

        # Try to check existing users and insert into database
        try:
            # Check if email already exists
            if User.get_by_email(email):
                return render_template('auth/signup.html',
                    user=user_data,
                    error="Email already registered. Please use a different one.",
                    location_enabled=location_enabled
                )

            # Check if username already exists
            if User.get_by_username(username):
                return render_template('auth/signup.html',
                    user=user_data,
                    error="Username already taken. Please use a different one.",
                    location_enabled=location_enabled
                )

            # Insert into database
            conn = get_db()
            cur = conn.cursor(dictionary=True)

            cur.execute("""
                INSERT INTO users 
                (email, username, password_hash, first_name, last_name, display_name, 
                 phone_number, date_of_birth, age_group, location_enabled)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                email,
                username,
                password,
                first_name,
                last_name,
                display_name,
                phone,
                birthday_str,
                age_category,
                1 if location_enabled else 0
            ))

            user_id = cur.lastrowid
            conn.commit()
            cur.close()
            conn.close()

            # Store user ID in session and log the user in
            session['user_id'] = user_id
            session['signup_email'] = email

            try:
                user = User.get_by_id(user_id)
                if user:
                    login_user(user)
            except Exception:
                pass

            # Redirect to homepage after completing About You
            return redirect(url_for('main.home'))

        except Exception as e:
            error_msg = str(e)
            print(f"Signup error: {error_msg}")
            # If host resolution fails, provide clearer guidance
            if 'Unknown MySQL server host' in error_msg or 'getaddrinfo failed' in error_msg:
                guidance = (
                    "Could not reach MySQL host.\n"
                    "Please verify the hostname in your Config (Config.MYSQL_HOST),\n"
                    "ensure DNS resolves it or try the database IP address, and confirm port/network access."
                )
                return render_template('auth/signup.html', user=user_data, error=guidance)

            return render_template('auth/signup.html',
                user=user_data,
                error=f"An error occurred while creating your account: {error_msg[:200]}",
                location_enabled=location_enabled
            )

    # GET: render the About You / signup form
    return render_template('auth/signup.html', user={})

@auth_bp.route('/signup2', methods=['GET', 'POST'])
def signup_step2():
    """Handle the second signup step - can be interests, connections, etc."""
    if 'user_id' not in session:
        return redirect(url_for('auth.signup'))
    
    # Placeholder for step 2 - redirect to home
    return redirect(url_for('main.home'))


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        if not username or not password:
            return render_template('auth/login.html', error="Username and password required.")

        # Session recording the number of failed attempts
        failed_attempts = session.get('failed_attempts', 0)
        lockout_time = session.get('lockout_time')

        if lockout_time:
            lockout_time = datetime.fromisoformat(lockout_time)  # string to datetime
            if datetime.now() < lockout_time:
                remaining_seconds = int((lockout_time - datetime.now()).total_seconds())
                return render_template('auth/login.html', 
                    error="Too many failed attempts.", 
                    lockout_seconds=remaining_seconds)
            else:
                session.pop('failed_attempts', None)
                session.pop('lockout_time', None)
                failed_attempts = 0

        # Check credentials
        user = User.get_by_username(username)

        if user and user.check_password(password):
            # Successful login - clear attempts
            session.pop('failed_attempts', None)
            session.pop('lockout_time', None)
            login_user(user)
            
            return redirect(url_for('main.home'))
        else:
            # Failed login - increment counter
            failed_attempts += 1
            session['failed_attempts'] = failed_attempts
            
            if failed_attempts >= 3:
                # Lock out for 10 seconds
                lockout_time = datetime.now() + timedelta(seconds=10)
                session['lockout_time'] = lockout_time.isoformat()  # datetime to string
                return render_template('auth/login.html', 
                    error="Too many failed attempts.", 
                    lockout_seconds=10)
            else:
                remaining_attempts = 3 - failed_attempts
                return render_template('auth/login.html', 
                    error=f"Invalid username or password. {remaining_attempts} attempt(s) remaining.")

    # GET request - check if already locked out
    lockout_time = session.get('lockout_time')
    
    if lockout_time:
        lockout_time = datetime.fromisoformat(lockout_time)
        if datetime.now() < lockout_time:
            remaining_seconds = int((lockout_time - datetime.now()).total_seconds())
            return render_template('auth/login.html',
                error="Too many failed attempts.",
                lockout_seconds=remaining_seconds)
        else:
            session.pop('failed_attempts', None)
            session.pop('lockout_time', None)
    
    return render_template('auth/login.html')


@auth_bp.route('/settings')
@login_required
def settings():
    return redirect(url_for('auth.appearance_settings'))


@auth_bp.route('/language', methods=['GET'])
@login_required
def language_settings():
    return render_template('auth/language.html')


@auth_bp.route('/language/update', methods=['POST'])
@login_required
def update_language():
    from database import execute_query

    data = request.get_json(silent=True) or request.form
    language = (data.get('language') or 'en').strip()
    if language not in {'en', 'zh-CN', 'ta', 'ms'}:
        language = 'en'

    execute_query(
        "UPDATE users SET language = %s WHERE id = %s",
        (language, current_user.id),
        commit=True,
    )

    return ('', 204)




@auth_bp.route('/appearance')
@login_required
def appearance_settings():
    return render_template('auth/appearance.html')


@auth_bp.route('/appearance/update', methods=['POST'])
@login_required
def update_appearance():
    from database import get_db

    try:
        data = request.get_json(silent=True) or request.form

        theme = (data.get('theme') or 'light').strip().lower()
        db_theme = 'darkmode' if theme == 'dark' else 'lightmode'

        try:
            text_size = int(data.get('text_size', 16))
        except (TypeError, ValueError):
            text_size = 16
        text_size = max(12, min(48, text_size))

        font_style_raw = (data.get('font_style') or 'arial').strip().lower()
        font_db_map = {
            'arial': 'Arial',
            'verdana': 'Verdana',
            'tahoma': 'Tahoma',
            'trebuchet': 'Trebuchet MS',
            'georgia': 'Georgia',
            'times': 'Times New Roman',
            'courier': 'Courier New'
        }
        font_style = font_db_map.get(font_style_raw, 'Arial')

        font_weight_raw = str(data.get('font_weight', '500')).strip()
        boldness_map = {
            '300': 'light',
            '500': 'medium',
            '700': 'dark'
        }
        boldness = boldness_map.get(font_weight_raw, 'medium')

        conn = get_db()
        cur = conn.cursor(dictionary=True)

        try:
            cur.execute(
                """
                SELECT id
                FROM appearance
                WHERE user_id = %s
                ORDER BY id DESC
                LIMIT 1
                """,
                (current_user.id,)
            )
            latest_row = cur.fetchone()

            if latest_row:
                keep_id = latest_row.get('id')
                cur.execute(
                    """
                    UPDATE appearance
                    SET theme = %s, text_size = %s, font_style = %s, boldness = %s
                    WHERE id = %s
                    """,
                    (db_theme, text_size, font_style, boldness, keep_id)
                )

                cur.execute(
                    """
                    DELETE FROM appearance
                    WHERE user_id = %s AND id <> %s
                    """,
                    (current_user.id, keep_id)
                )
            else:
                cur.execute(
                    """
                    INSERT INTO appearance (user_id, theme, text_size, font_style, boldness)
                    VALUES (%s, %s, %s, %s, %s)
                    """,
                    (current_user.id, db_theme, text_size, font_style, boldness)
                )

            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            cur.close()

        return {'success': True}, 200
    except Exception as e:
        return {'success': False, 'error': str(e)[:200]}, 500


@auth_bp.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    if request.method == 'POST':
        logout_user()
        session.clear()
        return redirect(url_for('auth.login'))

    return render_template('auth/logout.html')


@auth_bp.route('/logout-now', methods=['GET'])
@login_required
def logout_now():
    logout_user()
    session.clear()
    return redirect(url_for('auth.login'))


@auth_bp.route('/delete-account', methods=['POST'])
@login_required
def delete_account():
    from database import get_db

    user_id = current_user.id
    conn = get_db()
    cur = conn.cursor(dictionary=True)

    try:
        cur.execute("SELECT DATABASE() AS db_name")
        db_row = cur.fetchone() or {}
        db_name = db_row.get('db_name')

        cleanup_targets = []

        if db_name:
            cur.execute(
                """
                SELECT TABLE_NAME, COLUMN_NAME
                FROM information_schema.KEY_COLUMN_USAGE
                WHERE TABLE_SCHEMA = %s
                  AND REFERENCED_TABLE_NAME = 'users'
                  AND REFERENCED_COLUMN_NAME = 'id'
                """,
                (db_name,)
            )
            for row in cur.fetchall() or []:
                table_name = row.get('TABLE_NAME')
                column_name = row.get('COLUMN_NAME')
                if table_name and column_name:
                    cleanup_targets.append((table_name, column_name))

            cur.execute(
                """
                SELECT TABLE_NAME, COLUMN_NAME
                FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA = %s
                  AND COLUMN_NAME = 'user_id'
                """,
                (db_name,)
            )
            for row in cur.fetchall() or []:
                table_name = row.get('TABLE_NAME')
                column_name = row.get('COLUMN_NAME')
                if table_name and column_name:
                    cleanup_targets.append((table_name, column_name))

        unique_targets = set(cleanup_targets)

        for table_name, column_name in sorted(unique_targets):
            if table_name == 'users' and column_name == 'id':
                continue
            cur.execute(
                f"DELETE FROM `{table_name}` WHERE `{column_name}` = %s",
                (user_id,)
            )

        cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
        conn.commit()
    except Exception as exc:
        conn.rollback()
        flash(f'Could not delete account: {str(exc)[:200]}', 'error')
        return redirect(url_for('auth.logout'))
    finally:
        cur.close()

    logout_user()
    session.clear()
    return redirect(url_for('auth.login'))
