from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, FileField, DateField, TextAreaField, SelectField,FloatField
from wtforms.validators import Length, EqualTo, Email, DataRequired, ValidationError, URL
from Funding.models import User


class RegisterForm(FlaskForm):
    def validate_username(self, username_to_check):
        user = User.query.filter_by(username=username_to_check.data).first()
        if user:
            raise ValidationError('Username already exists! Please try a different username')

    def validate_email_address(self, email_address_to_check):
        email_address = User.query.filter_by(email_address=email_address_to_check.data).first()
        if email_address:
            raise ValidationError('Email Address already exists! Please try a different email address')

    username = StringField(label='Name/Username:', validators=[Length(min=2, max=30), DataRequired()])
    surname = StringField(label='Surname:', validators=[Length(min=2, max=30), DataRequired()])
    dateofbirth = DateField('Date of Birth:', validators=[DataRequired()])
    Idnumber = StringField(label='ID number:',validators=[Length(max=13), DataRequired()])
    email_address = StringField(label='Email Address:', validators=[Email(), DataRequired()])
    faculty = SelectField('Faculty', choices=[
        ('ai', 'Accounting and informatics'),
        ('as', 'Applied science'),
        ('ad', 'Arts and design'),
        ('hs', 'Health sciences'),
        ('ms', 'Management sciences'),
        ('eng', 'Engineering and the Built Enviroment')
        # Add more choices as needed
    ], validators=[DataRequired()])
    password1 = PasswordField(label='Password:', validators=[Length(min=6), DataRequired()])
    password2 = PasswordField(label='Confirm Password:', validators=[EqualTo('password1'), DataRequired()])
    submit = SubmitField(label='Create Account')


class LoginForm(FlaskForm):
    username = StringField(label='User Name:', validators=[DataRequired()])
    password = PasswordField(label='Password:', validators=[DataRequired()])
    submit = SubmitField(label='Sign in')

class ApplicationF(FlaskForm):
    #def validate_url(self, url_to_check): 
    name = StringField('Bursary Name', validators=[DataRequired(), Length(max=200)])
    company = StringField('Company', validators=[DataRequired(), Length(max=200)])
    faculty = SelectField('Faculty', choices=[
        ('ai', 'Accounting and informatics'),
        ('as', 'Applied science'),
        ('ad', 'Arts and design'),
        ('hs', 'Health sciences'),
        ('ms', 'Management sciences'),
        ('eng', 'Engineering and the Built Enviroment')
        ], validators=[DataRequired()])
    description = StringField('Description', validators=[DataRequired(), Length(max=255)])
    enddate = DateField('Expiry', validators=[DataRequired()])
    amount = FloatField(label='Offered Amount',validators=[DataRequired()])
    link = StringField('Link', validators=[DataRequired(), URL(),Length(max=200)])    
    csrf_token = StringField('CSRF Token')
    #documents = FileField('Upload Documents')
    submit = SubmitField('Submit Entry')

class ProfileForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=30)])
    email_address = StringField('Email Address', validators=[DataRequired(), Length(max=50)])
    idnumber = StringField(label='ID number',validators=[Length(max=13), DataRequired()])
    password1 = PasswordField(label='Password', validators=[Length(min=6), DataRequired()])
    dateofbirth = DateField('Date of Birth', validators=[DataRequired()])
    faculty = SelectField('Faculty', choices=[
        ('ai', 'Accounting and informatics'),
        ('as', 'Applied science'),
        ('ad', 'Arts and design'),
        ('hs', 'Health sciences'),
        ('ms', 'Management sciences'),
        ('eng', 'Engineering and the Built Enviroment')
        ], validators=[DataRequired()])
    role = StringField('Role', validators=[Length(max=30)])
    submit = SubmitField('Update Profile')    

class ContactForm(FlaskForm):
    name = StringField('Your Name', validators=[DataRequired()])
    email = StringField('Your Email', validators=[DataRequired(), Email()])
    message = TextAreaField('Your Message', validators=[DataRequired()])
    submit = SubmitField('Send Message')