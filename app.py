from flask import Flask, render_template, request, redirect, session
import sqlite3
from sqlite3 import Error
from flask_bcrypt import Bcrypt
DATABASE = "tables_equipment_log"
inc_pass1 = False
app = Flask(__name__)
app.secret_key = 'balls'
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
            return redirect("\signup?error=password+do+not+match")

        if len(user_password) < 8:
            return redirect("\signup?error=passowrd+to+short+,+atleast+8+required")

        if len(user_password) > 30:
            return redirect("\signup?error=password+is+too+long+,+30+characters+max")
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
