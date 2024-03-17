from Funding import app
from flask import render_template, redirect, request, url_for,flash,session,jsonify
from Funding.models import Item, User, ApplicationForm as ApplicationFormModel
from Funding.forms import RegisterForm,LoginForm,ApplicationF,ProfileForm,ContactForm 
from Funding import db
from flask_login import login_user,logout_user,current_user, login_required
from email.message import EmailMessage
from datetime import datetime
import ssl,smtplib

@app.route('/')
def main():
    return redirect(url_for('login_page'))
@app.route('/home')
def home_page():
    return render_template('home_page.html')
@app.route('/about')
def about_page():
    return render_template('about.html')

@app.route('/bursaries')
#@login_required
def bursary_page():
    form = ApplicationFormModel()
    items = []
    admin_items = []
    if current_user.is_authenticated:
        if current_user.username == "Admin":
            admin_items = ApplicationFormModel.query.all()  # Retrieve all items for admin
        else:
            items = ApplicationFormModel.query.filter_by(faculty=current_user.faculty).all()
            # Filter out expired items for regular users
            items = [item for item in items if item.enddate > datetime.now()]
    else:
        items = ApplicationFormModel.query.all()

    return render_template('bursarylist.html', items=items, admin_items=admin_items,form=form)

@app.route('/register', methods=['GET', 'POST'])
def register_page():
    form = RegisterForm()
    if form.validate_on_submit():
        user_to_create = User(username=form.username.data,
                              surname=form.surname.data,
                              dateofbirth=form.dateofbirth.data,
                              Idnumber=form.Idnumber.data,
                              email_address=form.email_address.data,
                              password=form.password1.data,
                              faculty = form.faculty.data)
        db.session.add(user_to_create)
        db.session.commit()
        login_user(user_to_create)
        flash(f'Account created successfully! You are now logged in as {user_to_create.username}', category='success')
        return redirect(url_for('home_page'))
    
    if form.errors != {}: #If there are not errors from the validations
        for err_msg in form.errors.values():
            flash(f'There was an error with creating a user: {err_msg}', category='danger')

    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login_page():
    form = LoginForm()
    if form.validate_on_submit():
        # Verify reCAPTCHA
        captcha_response = request.form['g-recaptcha-response']
        if verify_recaptcha(captcha_response):            
            attempted_user = User.query.filter_by(username=form.username.data).first()
            if attempted_user and attempted_user.check_password_correction(
                    attempted_password=form.password.data
            ):
                login_user(attempted_user)
                flash(f'Success! You are logged in as: {attempted_user.username}', category='success')                        
                current_bursary_count = len(ApplicationFormModel.query.filter_by(faculty=attempted_user.faculty).all())
                if current_user.username != "Admin":            
                    if 'previous_bursary_count' in session:
                        previous_bursary_count = session['previous_bursary_count']
                        
                        if current_bursary_count > previous_bursary_count:
                            flash(f'Good news! There are new available bursaries {current_bursary_count}', category='info')

                session['previous_bursary_count'] = current_bursary_count
                
                return redirect(url_for('profile'))            
            else:
                flash('Username and password are not match! Please try again', category='danger')
        else:            
            flash('reCAPTCHA verification failed. Please try again.', category='danger')

    return render_template('login.html', form=form)

def verify_recaptcha(response):
    secret_key = '6LfFb5spAAAAACBBbpLfHlf3umwfWQc8eBJzYsDX' 
    url = 'https://www.google.com/recaptcha/api/siteverify'
    data = {
        'secret': secret_key,
        'response': response
    }
    response = request.post(url, data=data)
    result = response.json()
    return result['success']

"""
@app.route('/login', methods=['GET', 'POST'])
def login_page():
    form = LoginForm()
    if form.validate_on_submit():
        attempted_user = User.query.filter_by(username=form.username.data).first()
        if attempted_user and attempted_user.check_password_correction(
                attempted_password=form.password.data
        ):
            login_user(attempted_user)
            flash(f'Success! You are logged in as: {attempted_user.username}', category='success')                        
            flash(f'To view your profile, click on your name above', category='success') 
            current_bursary_count = len(ApplicationFormModel.query.filter_by(faculty=attempted_user.faculty).all())
            if current_user.username != "Admin":            
             if 'previous_bursary_count' in session:
                previous_bursary_count = session['previous_bursary_count']
                                
                if current_bursary_count > previous_bursary_count:
                    flash(f'Good news! There are new available bursaries {current_bursary_count}', category='info')

            session['previous_bursary_count'] = current_bursary_count
            
            return redirect(url_for('profile'))            
        else:
            flash('Username and password are not match! Please try again', category='danger')

    return render_template('login.html', form=form)
"""
@app.route('/logout')
def logout_page():
    logout_user()
    flash('You have been logged out!', category='info')
    return redirect(url_for('home_page'))

@app.route('/ApplicationForm', methods=['GET', 'POST'])
def application_form_page():
    form = ApplicationF()
    
    if form.validate_on_submit():
        application_data = ApplicationFormModel(
            name=form.name.data,
            company=form.company.data,
            faculty = form.faculty.data,
            description=form.description.data,
            enddate=form.enddate.data,
            amount=form.amount.data,
            link=form.link.data
        )
        
        db.session.add(application_data)
        db.session.commit()

        flash('Application submitted successfully!', category='success')
        return redirect(url_for('home_page'))

    if form.errors != {}:
        for err_msg in form.errors.values():
            flash(f'Error occurred in Application Form: {err_msg}', category='danger')

    return render_template('applicationform.html', form=form)

def get_available_bursaries_count(user):
    if user.username == "Admin":
        return ApplicationFormModel.query.count()
    else:
        return ApplicationFormModel.query.filter_by(faculty=user.faculty).count()


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    available_bursaries_count = get_available_bursaries_count(current_user)
    form = ProfileForm()

    if form.validate_on_submit():
        current_user.username = form.username.data
        current_user.email_address = form.email_address.data
        current_user.Idnumber = form.idnumber.data
        current_user.password =  form.password1.data
        current_user.dateofbirth = form.dateofbirth.data
        current_user.facutly = form.faculty.data
        current_user.role = form.role.data

        if form.password1.data:
            current_user.password = form.password1.data

        db.session.commit()
        flash('Your profile has been updated!', 'success')
        return redirect(url_for('profile'))

    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email_address.data = current_user.email_address
        form.idnumber.data = current_user.Idnumber
        form.password1.data = ''
        form.dateofbirth.data = current_user.dateofbirth
        form.faculty.data = current_user.faculty
        form.role.data = current_user.role

    return render_template('profile.html', form=form,available_bursaries_count=available_bursaries_count)

@app.route('/available_bursaries_count', methods=['GET'])
@login_required
def available_bursaries_count():
    available_bursaries_count = get_available_bursaries_count(current_user)
    return jsonify({'count': available_bursaries_count})
@app.route('/contact', methods=['GET', 'POST'])
def contact():
    form = ContactForm()
    email_sender = 'silverknight1414@gmail.com'
    email_password = 'cpxn ympm wuvf fetq'
    recipient = ''    
    subject = 'Ting'
    body = """Hello there"""

    if form.validate_on_submit():

        subject = 'DUT ScholarHub feedback'
        body = f"Name: {form.name.data}\nEmail: {form.email.data}\n\n{form.message.data}"
        recipient = form.email.data

        em = EmailMessage()

        em['From'] = email_sender
        em['To'] = recipient
        em['Subject'] = subject
        em.set_content(body)

        context = ssl.create_default_context()

        with smtplib.SMTP_SSL('smtp.gmail.com',465,context=context) as smtp:
            try:            
                smtp.login(email_sender,email_password)
                smtp.sendmail(email_sender,recipient,em.as_string())
                flash('Your message has been sent!', 'success')
                return redirect(url_for('contact'))
            except Exception as e:
                flash(f"An error occurred: {str(e)}", 'danger')

    return render_template('contact.html', form=form)

@app.route('/bursaries/<int:bursary_id>')
def bursary_detail(bursary_id):
    # Retrieve bursary details from the database based on the bursary_id
    bursary = ApplicationFormModel.query.get(bursary_id)
    return render_template('bursary_detail.html', bursary=bursary)

@app.route('/delete_bursary/<int:id>', methods=['POST'])
@login_required
def delete_bursary(id):
    if current_user.username != "Admin":
        # Handle unauthorized access
        flash('You are not authorized to delete bursaries.', 'danger')
        return redirect(url_for('bursary_page'))

    bursary = ApplicationFormModel.query.get_or_404(id)
    db.session.delete(bursary)
    db.session.commit()
    
    flash('Bursary deleted successfully!', 'success')
    return redirect(url_for('bursary_page'))