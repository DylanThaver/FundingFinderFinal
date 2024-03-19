from . import db
from flask_login import UserMixin

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    Email = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(150))
    firstName = db.Column(db.String(150))
    lastName = db.Column(db.String(150))
    department = db.Column(db.String(150))
    position=db.Column(db.String(150))

    def __init__(self,Email,password,firstName,lastName,department, position):
        self.Email=Email
        self.password=password
        self.firstName=firstName
        self.lastName=lastName
        self.department=department
        self.position=position

class Sponsorship(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    AcompanyName = db.Column(db.String(150), unique=True)
    BOpeningDate = db.Column(db.String(150))
    CclosingDate = db.Column(db.String(150))
    Ddepartment = db.Column(db.String(150))
    companyEmail = db.Column(db.String(150))
    add_req = db.Column(db.String(150))


    def __init__(self,AcompanyName,BOpeningDate,CclosingDate,Ddepartment,companyEmail, add_req):
        self.AcompanyName=AcompanyName
        self.BOpeningDate=BOpeningDate
        self.CclosingDate=CclosingDate
        self.Ddepartment=Ddepartment
        self.companyEmail=companyEmail
        self.add_req=add_req


class Grant(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    GAcompanyName = db.Column(db.String(150), unique=True)
    GBOpeningDate = db.Column(db.String(150))
    GCclosingDate = db.Column(db.String(150))
    GDdepartment = db.Column(db.String(150))
    companyEmail = db.Column(db.String(150))
    add_req = db.Column(db.String(150))



    def __init__(self,GAcompanyName,GBOpeningDate,GCclosingDate,GDdepartment,companyEmail,add_req):
        self.GAcompanyName=GAcompanyName
        self.GBOpeningDate=GBOpeningDate
        self.GCclosingDate=GCclosingDate
        self.GDdepartment=GDdepartment
        self.companyEmail=companyEmail
        self.add_req = add_req

    
class Bursary(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    BAcompanyName = db.Column(db.String(150), unique=True)
    BBOpeningDate = db.Column(db.String(150))
    BCclosingDate = db.Column(db.String(150))
    BDdepartment = db.Column(db.String(150))
    companyEmail = db.Column(db.String(150))
    add_req = db.Column(db.String(150))


    def __init__(self,BAcompanyName,BBOpeningDate,BCclosingDate,BDdepartment,companyEmail,add_req):
        self.BAcompanyName=BAcompanyName
        self.BBOpeningDate=BBOpeningDate
        self.BCclosingDate=BCclosingDate
        self.BDdepartment=BDdepartment
        self.companyEmail=companyEmail
        self.add_req = add_req

class StudentApplication(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    companyEmail = db.Column(db.String(150))
    companyName = db.Column(db.String(150))
    applicationDate = db.Column(db.DateTime)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    sponsorship_id = db.Column(db.Integer, db.ForeignKey('sponsorship.id'))
    grant_id = db.Column(db.Integer, db.ForeignKey('grant.id'))
    bursary_id = db.Column(db.Integer, db.ForeignKey('bursary.id'))
    supp_doc_name = db.Column(db.String(150))
    supp_doc = db.Column(db.LargeBinary)