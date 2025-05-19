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
results = ['user']
logged_in = False
wrong_id = False
inventory_size = 10


def connect_database(db_file):
    try:
        connection = sqlite3.connect(db_file)
        return connection
    except Error as e:
        print(e)
        return


@app.route('/')
def render_homepage():
    results[0] = results[0]
    return render_template('home.html')


@app.route('/adminpage', methods=['GET', 'POST'])
def render_adminpage_page():
    headers = ('equipment', 'description', 'equipment_id', 'delete')

    con = connect_database(DATABASE)

    query = "SELECT equipment_name, equipment_description, Equipment_id FROM equipment"
    cur = con.cursor()
    cur.execute(query)
    equipment = cur.fetchall()
    con.commit()


    if request.method == 'POST':
        con = connect_database(DATABASE)
        cur.concursor(con)
        query = 'DELETE FROM equipment WHERE equipment_id=?'
        cur.execute(query,)

    return render_template('adminpage.html',equipment_id=equipment_id, header=headers, equipment0=equipment, incorrect_id=wrong_id,)


@app.route('/remove_eqipment', methods=['GET', 'POST'])
def render_remove_equipment_page():
    equipment_id = request.form.get['equipment_id']
    if request.method == 'POST':
        con = connect_database(DATABASE)
        cur = con.cursor()
        query = "DELETE FROM equipment WHERE equipment_id=?"
        cur.execute(query,(equipment_id,))







@app.route('/menu')
def render_menu_page():
    headers = ('Who', 'When', 'What')
    con = connect_database(DATABASE)
    query = "SELECT user_id, date_0, equipment_id FROM booking_table"
    cur = con.cursor()
    cur.execute(query)
    timetable_info = cur.fetchall()
    con.commit()
    return render_template('menu.html', header=headers, timetable_info0=timetable_info)


@app.route('/equipment', methods=['POST', 'GET'])
def render_equipment_page():
    if request.method == "POST":
        equipment_name = request.form.get("equipment_name")
        equipment_description = request.form.get("equipment_description")
        equipment_category = request.form.get("equipment_category")
        con = connect_database(DATABASE)
        query_insert = "INSERT INTO equipment ( equipment_name, equipment_description, equipment_category ) VALUES(?,?,?)"
        cur = con.cursor()
        cur.execute(query_insert, (equipment_name, equipment_description, equipment_category))
        con.commit()
        con.close()
    return render_template('equipment.html')


@app.route('/inventory', methods=['POST', 'GET'])
def render_contact_page():
    headers = ('equipment', 'description', 'equipment_id')

    con = connect_database(DATABASE)

    query = "SELECT equipment_name, equipment_description, Equipment_id FROM equipment"
    cur = con.cursor()
    cur.execute(query)
    equipment = cur.fetchall()
    equipment_id = None
    con.commit()

    con = connect_database(DATABASE)
    query = "SELECT * FROM equipment "
    cur = con.cursor()
    cur.execute(query, )
    number0 = cur.fetchall()
    print(number0)
    number_awesome = len(number0)
    print(number_awesome)

    if request.method == "POST":
        equipment_id = request.form.get('equipment_id')
        date_0 = request.form.get("date_0")
        user_id = session['user_id']
        con = connect_database(DATABASE)
        query = 'SELECT equipment_id FROM equipment WHERE equipment_id = ?'
        print(equipment_id)
        cur.execute(query, (equipment_id))
        john = cur.fetchall()
        query_insert = "INSERT INTO booking_table ( date_0, user_id, equipment_id ) VALUES(?, ?, ?)"
        cur = con.cursor()
        cur.execute(query_insert, (date_0, user_id, equipment_id))
        con.commit()
        con.close()

    return render_template('contact.html', header=headers, equipment0=equipment, incorrect_id=wrong_id,
                           number_awesome=number_awesome)


@app.route('/Login', methods=['POST', 'GET'])
def render_login_page():
    if request.method == 'POST':
        email = request.form.get('user_email').strip().lower()
        password = request.form.get('user_password')
        con = connect_database(DATABASE)
        cur = con.cursor()
        query = 'SELECT user_id, user_fname, user_password, admin_check FROM users WHERE user_email = ?'
        cur.execute(query, (email,))
        results = cur.fetchone()
        print(results)

        con.close()
        session['logged_in'] = True
        if session['logged_in'] == True:
            print("kaboom")
        try:
            user_id = results[0]
            user_fname = results[1]
            user_password = results[2]
            user_admin_check = results[3]
        except IndexError:
            return redirect("/login?wrong+email+or+password")
        if not Bcrypt.check_password_hash(user_password, password):
            return redirect("/login?wrong+email+or+password")

        session['user_password'] = results[2]
        session['user_id'] = results[0]
        session['user_fname'] = results[1]
        session['user_admin_check'] = results[3]
        print(session)

        return redirect('/')

    return render_template('Login.html')


@app.route('/bookings', methods=['POST', 'GET'])
def render_bookings_page():
    if request.method == "POST":
        date_0 = request.form.get("date_0").title().strip()
        user_id = session['user_id']
        con = connect_database(DATABASE)
        # saev maybe for later - query = 'SELECT user_id, user_fname, user_lname FROM users INNER JOIN booking_table ON bookings_table.user_id = users.user_id'
        query_insert = "INSERT INTO booking_table ( date_0, user_id ) VALUES(?, ?)"
        cur = con.cursor()
        cur.execute(query_insert, (date_0, user_id))
        con.commit()
        con.close()
    return render_template('bookings.html')


@app.route('/logout')
def render_logout():
    session.clear()
    Logged_in = False
    return render_template('home.html')


@app.route('/sign_up', methods=['POST', 'GET'])
def render_sign_up_page():
    if request.method == "POST":
        user_fname = request.form.get("user_fname").title().strip()
        user_lname = request.form.get("user_lname").title().strip()
        user_email = request.form.get("user_email").lower().strip()
        user_password = request.form.get("user_password")
        user_password2 = request.form.get("user_password2")
        user_admin_check = request.form.get("admin_check")

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
        query_insert = "INSERT INTO users (user_fname,user_lname, user_email, user_password, admin_check) VALUES(?,?,?,?,?)"
        cur = con.cursor()
        cur.execute(query_insert, (user_fname, user_lname, user_email, hashed_password, user_admin_check))
        con.commit()
        con.close()
    return render_template('sign_up.html')


app.run(host='0.0.0.0', debug=True)
