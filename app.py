from flask import Flask, render_template

app = Flask(__name__)


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

@app.route('/sign_up')
def render_sign_up_page():
    return render_template('sign_up.html')


app.run(host='0.0.0.0', debug=True)
