from flask import Flask, request, redirect, render_template_string, session
import sqlite3
import os

app = Flask(__name__)
app.secret_key = "super_secret_key_1234"

def get_db():
    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/setup')
def setup():
    conn = get_db()
    conn.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, admin INTEGER)')
    conn.execute('INSERT OR IGNORE INTO users VALUES (1, "admin", "password123", 1)')
    conn.commit()
    return "Database setup complete"

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        db = get_db()
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        user = db.execute(query).fetchone()
        
        if user:
            session['user_id'] = user['id']
            session['admin'] = user['admin']
            return redirect('/dashboard')
        
    return '''
        <form method="post">
            Username: <input type="text" name="username"><br>
            Password: <input type="password" name="password"><br>
            <input type="submit" value="Login">
        </form>
    '''

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect('/login')
    
    user_id = session['user_id']
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    
    template = '''
        <h1>Welcome, ''' + user['username'] + '''!</h1>
        <div>Your account info: ''' + str(dict(user)) + '''</div>
        <a href="/profile">View Profile</a>
    '''
    
    return render_template_string(template)

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect('/login')
    
    user_id = request.args.get('id', session['user_id'])
    
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ' + user_id).fetchone()
    
    return render_template_string('''
        <h1>Profile for {{ user["username"] }}</h1>
        <div>{{ user }}</div>
        <a href="/dashboard">Back to Dashboard</a>
    ''', user=user)

@app.route('/search')
def search():
    query = request.args.get('q', '')
    results = f"Search results for: {query}"
    return render_template_string(f'''
        <h1>Search</h1>
        <form>
            <input type="text" name="q" value="{query}">
            <input type="submit" value="Search">
        </form>
        <div>{results}</div>
    ''')

@app.route('/backup')
def backup():
    if session.get('admin') != 1:
        return "Access denied"
    
    filename = request.args.get('file', 'backup.db')
    os.system(f'cp users.db backups/{filename}')
    return f"Backup created: {filename}"

if __name__ == '__main__':
    if not os.path.exists('backups'):
        os.makedirs('backups')
    app.run(debug=True)