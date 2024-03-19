from flask import Blueprint, render_template
from flask_login import  login_required, current_user

views = Blueprint('views', __name__)

@views.route('/', methods=['GET', 'POST'])

def home():
 return render_template("home.html", user=current_user)

@views.route('/sponsorships', methods=[' GET,POST'])
def sponsorships():
 return render_template('sponsorships.html', user=current_user)

@views.route('/adminPage', methods=['GET, POST'])
def adminPage():
 return render_template('adminPage.html',  user=current_user)
