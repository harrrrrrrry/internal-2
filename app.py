from flask import Flask, render_template, request, redirect, session
import sqlite3
from sqlite3 import Error
from flask_bcrypt import Bcrypt
DATABASE = "tables_equipment_log"
inc_pass1 = False
app = Flask(__name__)
app.secret_key = 'balls'
pass_match = False
pass_len = False
Bcrypt = Bcrypt(app)



def connect_database(db_file):
    try:
        connection = sqlite3.connect(db_file)
        return connection
    except Error as e:
        print(e)
        return
@app.route('/')
def render_homepage():
    return render_template('home.html')


@app.route('/menu')
def render_menu_page():
    return render_template('menu.html')


@app.route('/contact')
def render_contact_page():
    return render_template('contact.html')



@app.route('/Login', methods=['POST', 'GET'])
def render_login_page():
    if request.method == 'POST':
        email = request.form.get('user_email').strip().lower()
        password = request.form.get('user_password')
        con = connect_database(DATABASE)
        cur = con.cursor()
        query = 'SELECT user_fname, user_lname, user_email, user_password FROM users WHERE user_email = ?'
        cur.execute(query, (email,))
        results = cur.fetchone()
        print(results)

        con.close()
        session['logged_in'] = True
        if session['logged_in'] == True:
            print("kaboom")
        session['user_email'] = results[2]
        session['user_fname'] = results[0]
        session['user_lname'] = results[1]
        return redirect('/')

    return render_template('Login.html')



@app.route('/bookings')
def render_bookings_page():
    return render_template('bookings.html')



@app.route('/sign_up', methods=['POST', 'GET'])
def render_sign_up_page():
    if request.method == "POST":
        user_fname = request.form.get("user_fname").title().strip()
        user_lname = request.form.get("user_lname").title().strip()
        user_email = request.form.get("user_email").lower().strip()
        user_password = request.form.get("user_password")
        user_password2 = request.form.get("user_password2")


        if user_password != user_password2:
            pass_match = True
            return render_template('sign_up.html', pass_match=pass_match)

        if len(user_password) < 8:
            pass_len = True
            return render_template('sign_up.html', pass_len=pass_len)

        if len(user_password) > 30:
            pass_len = True
            return render_template('sign_up.html', pass_len=pass_len)
        hashed_password = Bcrypt.generate_password_hash(user_password)
        con = connect_database(DATABASE)
        query_insert = "INSERT INTO users (user_fname,user_lname, user_email, user_password ) VALUES(?,?,?,?)"
        print('flagged thing kaboom')
        cur = con.cursor()
        cur.execute(query_insert,(user_fname, user_lname ,user_email ,hashed_password))
        con.commit()
        con.close()
    return render_template('sign_up.html')


app.run(host='0.0.0.0', debug=True)
