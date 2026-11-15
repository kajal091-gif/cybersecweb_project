from flask import Flask, render_template, request, redirect, url_for, session, send_file
import port_scanner
import encryptor
import vault_manager
import auth
import os
import ipaddress
import password_checker
import socket

import vulnerability_scanner
import ai_recommendations

app = Flask(__name__)
app.secret_key = "supersecretkey"

# ---------------- Welcome Page ----------------
@app.route('/')
def welcome():
    return render_template('welcome.html')

# ---------------- Index Page ----------------
@app.route('/index')
def index():
    return render_template('index.html')

# ---------------- Login ----------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if auth.check_login(username, password):
            session['user'] = username
            return redirect(url_for('vault_dashboard'))
        else:
            error = "❌ Invalid credentials. Try again."
    return render_template('login.html', error=error)

# ---------------- Register ----------------

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Run password strength check
        result = password_checker.check_strength(password)

        # Show password review page before finalizing
        return render_template('password_review.html',
                               username=username,
                               password=password,
                               result=result)

    return render_template('register.html')

@app.route('/finalize_register', methods=['POST'])
def finalize_register():
    username = request.form['username']
    password = request.form['password']

    if auth.register_user(username, password):
        return render_template('register_success.html')
    else:
        return "❌ Username already exists. Please try again."

# ---------------- Vault Dashboard ----------------
@app.route('/vault')
def vault_dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('vault_dashboard.html')

# ---------------- Store Files ----------------
@app.route('/vault/store', methods=['GET', 'POST'])
def vault_store():
    if 'user' not in session:
        return redirect(url_for('login'))

    message = None
    if request.method == 'POST':
        uploaded_file = request.files['file']
        if uploaded_file:
            data = uploaded_file.read()
            key = auth.get_user_key(session['user'])
            user_folder = os.path.join("vault_storage", session['user'])
            os.makedirs(user_folder, exist_ok=True)
            encrypted_data = encryptor.encrypt_file(data, key)
            file_path = os.path.join(user_folder, uploaded_file.filename + ".enc")
            vault_manager.save_to_vault(file_path, encrypted_data)
            message = f"✅ File '{uploaded_file.filename}' encrypted and stored."
    return render_template('vault_store.html', message=message)

# ---------------- View Files ----------------
@app.route('/vault/view')
def vault_view():
    if 'user' not in session:
        return redirect(url_for('login'))
    user_folder = os.path.join("vault_storage", session['user'])
    os.makedirs(user_folder, exist_ok=True)
    files = os.listdir(user_folder)
    return render_template('vault_view.html', files=files)

# ---------------- File Operations ----------------
@app.route('/download/<filename>')
def download(filename):
    if 'user' not in session:
        return redirect(url_for('login'))
    file_path = os.path.join("vault_storage", session['user'], filename)
    return send_file(file_path, as_attachment=True)

@app.route('/decrypt/<filename>')
def decrypt(filename):
    if 'user' not in session:
        return redirect(url_for('login'))
    file_path = os.path.join("vault_storage", session['user'], filename)
    with open(file_path, "rb") as f:
        encrypted_data = f.read()
    key = auth.get_user_key(session['user'])
    try:
        decrypted_data = encryptor.decrypt_file(encrypted_data, key)
    except Exception:
        return "❌ Unable to decrypt file (wrong key)."
    temp_path = os.path.join("vault_storage", session['user'], "decrypted_" + filename.replace(".enc", ""))
    with open(temp_path, "wb") as f:
        f.write(decrypted_data)
    return send_file(temp_path, as_attachment=True)

@app.route('/delete/<filename>')
def delete(filename):
    if 'user' not in session:
        return redirect(url_for('login'))
    file_path = os.path.join("vault_storage", session['user'], filename)
    if os.path.exists(file_path):
        os.remove(file_path)
    return redirect(url_for('vault_view'))

@app.route('/update/<filename>', methods=['POST'])
def update(filename):
    if 'user' not in session:
        return redirect(url_for('login'))
    uploaded_file = request.files['file']
    if uploaded_file:
        data = uploaded_file.read()
        key = auth.get_user_key(session['user'])
        encrypted_data = encryptor.encrypt_file(data, key)
        user_folder = os.path.join("vault_storage", session['user'])
        os.makedirs(user_folder, exist_ok=True)
        file_path = os.path.join(user_folder, filename)
        vault_manager.save_to_vault(file_path, encrypted_data)
    return redirect(url_for('vault_view'))

# ---------------- Scanner -----------------

def validate_target(target):

    target = target.strip()

    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass

    try:
        socket.gethostbyname(target)
        return True
    except socket.gaierror:
        return False
@app.route('/scanner', methods=['GET', 'POST'])
def scanner():

    if request.method == 'POST':

        target = request.form['ip'].strip()

        if not validate_target(target):
            return render_template(
                'unauthorized.html',
                ip=target
            )

        try:

            open_ports, closed_ports, port_names = (
                port_scanner.scan_ports_threaded(target)
            )

            summary = {
                "total_ports": len(open_ports) + len(closed_ports),
                "open_count": len(open_ports),
                "closed_count": len(closed_ports),
                "ip": target
            }

            vulnerabilities = vulnerability_scanner.analyze_ports(open_ports)
            

            recommendations = (
                ai_recommendations.generate_recommendations(
                    vulnerabilities
                )
            )

            risk_penalty = {
                "Critical": 25,
                "High": 15,
                "Medium": 10,
                "Low": 5
            }

            score = 100

            for vuln in vulnerabilities:
                score -= risk_penalty.get(
                    vuln["risk"],
                    5
                )

            score = max(0, score)

            return render_template(
                'scan_report.html',
                ip=target,
                open_ports=open_ports,
                closed_ports=closed_ports,
                port_names=port_names,
                summary=summary,
                vulnerabilities=vulnerabilities,
                recommendations=recommendations,
                score=score
            )
            return render_template(
                'scan_report.html',
                ip=target,
                open_ports=open_ports,
                closed_ports=closed_ports,
                port_names=port_names,
                summary=summary,
                vulnerabilities=vulnerabilities,
                recommendations=recommendations,
                score=score
            )

        except Exception as e:
            return f"Scanner Error: {str(e)}"

    return render_template(
        'scanner.html',
        summary=None
    )

@app.route('/report_preview/<ip>')
def report_preview(ip):
    if 'user' not in session:
        return redirect(url_for('login'))
    open_ports, closed_ports, port_names = port_scanner.scan_ports_threaded(ip)
    report_lines = [
        f"Scan Report for {ip}",
        f"Total Ports Scanned: {len(open_ports) + len(closed_ports)}",
        f"Open Ports: {len(open_ports)}",
        f"Closed Ports: {len(closed_ports)}",
        "",
        "Open Ports & Services:",
    ]
    if open_ports:
        for port in open_ports:
            service = port_names.get(port, "Unknown/Custom Service")
            report_lines.append(f"Port {port} is OPEN → {service}")
    else:
        report_lines.append("No open ports found.")
    report_lines.append("")
    report_lines.append("Closed Ports & Services:")
    if closed_ports:
        for port in closed_ports:
            service = port_names.get(port, "Unknown/Custom Service")
            report_lines.append(f"Port {port} is CLOSED → {service}")
    else:
        report_lines.append("No closed ports found.")
    report_text = "\n".join(report_lines)
    return render_template('report_preview.html', ip=ip, report_text=report_text)

@app.route('/download_report/<ip>')
def download_report(ip):
    if 'user' not in session:
        return redirect(url_for('login'))
    open_ports, closed_ports, port_names = port_scanner.scan_ports_threaded(ip)
    report_lines = [
        f"Scan Report for {ip}",
        f"Total Ports Scanned: {len(open_ports) + len(closed_ports)}",
        f"Open Ports: {len(open_ports)}",
        f"Closed Ports: {len(closed_ports)}",
        "",
        "Open Ports & Services:",
    ]
    if open_ports:
        for port in open_ports:
            service = port_names.get(port, "Unknown/Custom Service")
            report_lines.append(f"Port {port} is OPEN → {service}")
    else:
        report_lines.append("No open ports found.")
    report_lines.append("")
    report_lines.append("Closed Ports & Services:")
    if closed_ports:
        for port in closed_ports:
            service = port_names.get(port, "Unknown/Custom Service")
            report_lines.append(f"Port {port} is CLOSED → {service}")
    else:
        report_lines.append("No closed ports found.")
    report_text = "\n".join(report_lines)
    user_folder = os.path.join("vault_storage", session['user'])
    os.makedirs(user_folder, exist_ok=True)
    report_path = os.path.join(user_folder, f"scan_report_{ip}.txt")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report_text)
    return send_file(report_path, as_attachment=True)

@app.route('/save_report/<ip>')
def save_report(ip):
    if 'user' not in session:
        return redirect(url_for('login'))
    open_ports, closed_ports, port_names = port_scanner.scan_ports_threaded(ip)
    report_lines = [
        f"Scan Report for {ip}",
        f"Total Ports Scanned: {len(open_ports) + len(closed_ports)}",
        f"Open Ports: {len(open_ports)}",
        f"Closed Ports: {len(closed_ports)}",
        "",
        "Open Ports & Services:",
    ]
    if open_ports:
        for port in open_ports:
            service = port_names.get(port, "Unknown/Custom Service")
            report_lines.append(f"Port {port} is OPEN → {service}")
    else:
        report_lines.append("No open ports found.")

    report_lines.append("")
    report_lines.append("Closed Ports & Services:")

    if closed_ports:
        for port in closed_ports:
            service = port_names.get(port, "Unknown/Custom Service")
            report_lines.append(f"Port {port} is CLOSED → {service}")
    else:
        report_lines.append("No closed ports found.")

    report_text = "\n".join(report_lines)

    # Save report in user-specific folder
    user_folder = os.path.join("vault_storage", session['user'])
    os.makedirs(user_folder, exist_ok=True)
    report_path = os.path.join(user_folder, f"scan_report_{ip}.txt")

    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report_text)

    return f"✅ Report for {ip} has been saved to your vault."

# ---------------- Logout ----------------
@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('index'))

if __name__ == "__main__":
    app.run(debug=True)
