from operator import index

from flask import Flask, render_template, request, redirect, session
import sqlite3
from sqlite3 import Error
from flask_bcrypt import Bcrypt

DATABASE = "tables_equipment_log"
app = Flask(__name__)
app.secret_key = 'balls'
pass_match = False
pass_len = False
Bcrypt = Bcrypt(app)
results = ['user']
logged_in = False
wrong_id = False



def connect_database(db_file):
    try:
        connection = sqlite3.connect(db_file)
        return connection
    except Error as e:
        print(e)
        return
    #this function is so that the database is linked to this python script and we can fiddle with at we please


@app.route('/')
def render_homepage():
    user_name = session.get('user_fname')
    return render_template('home.html', user_name=user_name)
# reders hompage, when teh user signs in it prints thier name and welcome text



@app.route('/adminpage', methods=['GET', 'POST'])
def render_adminpage_page():
    headers = ('equipment', 'description', 'equipment_id', 'delete')
    con = connect_database(DATABASE)
    query = "SELECT equipment_name, equipment_description, Equipment_id FROM equipment" # this block deletes a piece of euipment by querying and getting al the teh information from teh equipment row that is selected in the equipmentHTML
    cur = con.cursor()
    cur.execute(query)
    equipment = cur.fetchall()
    con.commit()

    con = connect_database(DATABASE)
    query = "SELECT user_id, date_0, booking_id, equipment_id FROM booking_table" # this block deletes all the bookings acociated with this piece of equipment, if the booking wanst deleted, it would cause many errors such as, the IDs would overlap causeing bookings to never be deletes and show up fro other piece of quipment of the other ID
    cur = con.cursor()
    cur.execute(query)
    booking = cur.fetchall()
    con.commit()

    return render_template('adminpage.html',equipment_id=equipment, header=headers, equipment0=equipment, incorrect_id=wrong_id,)
 # this function handles delteing and showing all the inventory that YSAR owns, we need to be abel to delte piece of equipment as often items like the reapeter or printers break. we want to display it so the admins know what we have in stock.

@app.route('/remove_eqipment', methods=['GET', 'POST'])
def render_remove_equipment_page():
    equipment_id = request.form.get('equipment_id') #gets the id of the row we want to delete
    if request.method == 'POST':
        con = connect_database(DATABASE)
        cur = con.cursor()
        query = "DELETE FROM equipment WHERE equipment_id=?" # gets the
        cur.execute(query,(equipment_id,))
        con.commit()
        con.close()

        con = connect_database(DATABASE)
        cur = con.cursor()
        query = "DELETE FROM booking_table WHERE equipment_id=?"
        cur.execute(query, (equipment_id,))
        con.commit()
        con.close()

    return render_template("adminpage.html")



@app.route('/userprofile', methods=['GET', 'POST'])
def render_userprofile_page():
    if request.method == 'POST':
        user_fname = request.form.get('user_fname').title().strip()
        user_lname = request.form.get('user_lname').title().strip()
        con = connect_database(DATABASE)
        user_id = session['user_id']
        query_update = "UPDATE users SET user_fname = ?, user_lname = ? WHERE user_id = ?"
        cur = con.cursor()
        cur.execute(query_update, (user_fname, user_lname, user_id))
        con.commit()
        con.close()
    return render_template("userprofile.html")


@app.route('/menu')
def render_menu_page():
    headers = ('Who', 'When', 'What')
    con = connect_database(DATABASE)
    query = "SELECT users.user_fname, booking_table.date_0, equipment.equipment_name, equipment.equipment_description FROM booking_table JOIN users ON users.user_id=booking_table.user_id JOIN equipment ON equipment.equipment_id=booking_table.equipment_id"
    cur = con.cursor()
    cur.execute(query,)
    timetable_info = cur.fetchall()
    con.commit()
    return render_template('menu.html', header=headers, timetable_info0=timetable_info)


@app.route('/equipment', methods=['POST', 'GET'])
def render_equipment_page():
    if request.method == "POST":
        equipment_name = request.form.get("equipment_name")
        equipment_description = request.form.get("equipment_description")
        con = connect_database(DATABASE)
        query_insert = "INSERT INTO equipment ( equipment_name, equipment_description ) VALUES(?,?)"
        cur = con.cursor()
        cur.execute(query_insert, (equipment_name, equipment_description))
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
    con.commit()

    con = connect_database(DATABASE)
    query = "SELECT equipment_name FROM equipment "
    cur = con.cursor()
    cur.execute(query, )
    number0 = cur.fetchall()

    if request.method == "POST":
        equipment_id = request.form.get('equipment').strip()
        date_0 = request.form.get("date_0")
        user_id = session['user_id']
        print(equipment_id)
        con = connect_database(DATABASE)
        cur = con.cursor()
        query = 'SELECT equipment_id FROM equipment WHERE equipment_name = ?'
        cur.execute(query, (equipment_id,))
        equipment_id0 = cur.fetchone()
        print(equipment_id0[0])



        query_insert = "INSERT INTO booking_table ( date_0, user_id, equipment_id ) VALUES(?, ?, ?)"
        cur = con.cursor()
        cur.execute(query_insert, (date_0, user_id, equipment_id0[0]))
        con.commit()
        con.close()

    return render_template('contact.html', header=headers, equipment0=equipment,
                           number_awesome=number0)


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
        con.close()
        if results == None:
            wrong_pass = True
            return render_template('Login.html', wrong_pass=wrong_pass)
            print("results are none")

        try:
            user_id = results[0]
            user_fname = results[1]
            user_password = results[2]
            user_admin_check = results[3]
            session['user_password'] = results[2]
            session['user_id'] = results[0]
            session['user_fname'] = results[1]
            session['user_admin_check'] = results[3]
            print(session)
            if not Bcrypt.check_password_hash(user_password, password):
                wrong_pass = True
                print("wrong password")
                session['logged_in'] = False
                session['user_admin_check'] = False
                return render_template('Login.html', wrong_pass=wrong_pass)
            print("here")
            session['logged_in'] = True
            return redirect('/')
        except TypeError:
            print("error putting in password")
            wrong_pass = True
            return render_template('Login.html', wrong_pass=wrong_pass)
        except IndexError:
            wrong_pass = True
            return render_template('Login.html', wrong_pass=wrong_pass)

    return render_template('Login.html')


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
