from Funding import db,login_manager
from Funding import bcrypt
from flask_login import UserMixin
from Funding import app

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model,UserMixin):
    id = db.Column(db.Integer(), primary_key=True)
    username = db.Column(db.String(length=30), nullable=False, unique=True)
    surname = db.Column(db.String(length=30), nullable=False, unique=True)
    dateofbirth = db.Column(db.Date(),nullable=False)
    Idnumber = db.Column(db.String(length=13),nullable=False)
    email_address = db.Column(db.String(length=50), nullable=False, unique=True)
    faculty = db.Column(db.String(length=60), nullable=False)    
    password_hash = db.Column(db.String(length=60), nullable=False)
    items = db.relationship('Item', backref='owned_user', lazy=True)
    role = db.Column(db.String(length=30), nullable=True, unique=True)

    @property
    def password(self):
        return self.password

    @password.setter
    def password(self, plain_text_password):
        self.password_hash = bcrypt.generate_password_hash(plain_text_password).decode('utf-8')

    def check_password_correction(self,attempted_password):
        return bcrypt.check_password_hash(self.password_hash, attempted_password)

    
class Item(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(length=30), nullable=False, unique=True)
    description = db.Column(db.String(length=1024), nullable=False, unique=True)
    owner = db.Column(db.Integer(), db.ForeignKey('user.id'))
    def __repr__(self):
        return f'Item {self.name}'

class ApplicationForm(db.Model):
    id = db.Column(db.Integer(), primary_key=True)    
    name = db.Column(db.String(length=200), nullable=False)
    company = db.Column(db.String(length=200), nullable=False)
    faculty = db.Column(db.String(length=60), nullable=True)
    description = db.Column(db.String(length=255), nullable=False)
    enddate = db.Column(db.Date(),nullable=False)
    amount = db.Column(db.Float(),nullable=False)    
    #upload_documents = db.Column(db.String(length=255))
    link =db.Column(db.String(length=200), nullable=False)    


with app.app_context():
    db.create_all()
    


