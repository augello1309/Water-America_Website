from flask import render_template, flash, redirect, request, url_for, Flask, session
from flask_pymongo import PyMongo
from models import userSchema, Address1, MoveAddress1
from usps import USPSApi, Address
from datetime import datetime
from flask_bcrypt import Bcrypt
from flask_login import login_user, login_required, logout_user, current_user, LoginManager
from User import User
from apscheduler.schedulers.background import BackgroundScheduler
import random
import string
from flask_mail import Message, Mail
from flask_session import Session
from bson import ObjectId
from dotenv import load_dotenv
import os
load_dotenv()
#print(os.getenv("SECRET_KEY"))

app = Flask(__name__)

app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")
app.config["MONGO_URI"] = os.getenv("MONGO_URI")

app.config["MAIL_SERVER"]=os.getenv("MAIL_SERVER")
app.config["MAIL_PORT"] = int(os.getenv("MAIL_PORT"))
app.config["MAIL_USE_TLS"] = bool(os.getenv("MAIL_USE_TLS"))
app.config["MAIL_USERNAME"] = os.getenv("MAIL_USERNAME")
app.config["MAIL_PASSWORD"] = os.getenv("MAIL_PASSWORD")
app.config['SESSION_TYPE'] = os.getenv("SESSION_TYPE")

mongodb_client = PyMongo(app)
bcrypt = Bcrypt(app)
db = mongodb_client.db
mail = Mail(app)



Session(app)

@app.route('/store_url/<url>')
def store_url(url):
    session['last_url'] = url
    print(session)
    return 'URL stored successfully.'

@app.route('/redirect_to_last_url')
def redirect_to_last_url():
    last_url = session.get('last_url')
    print(last_url)
    if last_url:
        return redirect(last_url)
    return 'No stored URL found.'

@app.route('/updateScheduler')
def updateScheduler():
    data = []
    for i in db.Users.find({}):
        if i['moveaddress'] != None and i['moveaddress']["verified"] == True:
            i = str(i['_id'])
            data.append(i)
    day = datetime.today()
   
    for j in data:
        mongodate = db.Users.find_one({"_id": ObjectId(j)})["moveaddress"]["date"]
        mongonewaddress = db.Users.find_one({"_id": ObjectId(j)})["moveaddress"]
        mongodate = mongodate.split('-')
        if int(mongodate[0]) <= day.year and int(mongodate[1]) <= day.month and int(mongodate[2]) <= day.day:
            db.Users.update_one({"_id": ObjectId(j)}, {"$set": {"address": mongonewaddress}})
            db.Users.update_one({"_id": ObjectId(j)}, {"$set": {"moveaddress": None}})


    return 0
try:
    scheduler = BackgroundScheduler()
    scheduler.add_job(updateScheduler, 'interval', seconds=2)
    scheduler.start()
except RuntimeError:
    print("Scheduler Stopped")

login_manager = LoginManager()
login_manager.login_view = 'Login'
login_manager.login_message_category = 'error'
login_manager.init_app(app)

@login_manager.user_loader
def load_user(id): 
    user = db.Users.find_one({"_id": ObjectId(id)})
    if user != None:
        return User(user)
    else:
        pass
    

@app.route('/')
def index():
    return render_template('Landing.html')

@app.route('/Login', methods=["GET", "POST"])
def Login():
    store_url(request.url)
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = db.Users.find_one({"email": email})
        if user:
            if user["verified"] == True:
                if bcrypt.check_password_hash(user["password"], password):
                    flash('Logged in successfully', category="success")
                    loginuser = User(user)
                    login_user(loginuser, remember=True)
                    return redirect('/home')
                else:
                    flash('Incorrect password. Try again.', category="error")
            else:
                flash("Please verify your email to login")
        else:
            flash("Email does not exist.", category='error')

    return render_template('LoginPage.html')

def generate_verification_code():
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(50))

@app.route('/verify_email/<code>', methods=["GET"])
def verify_email(code):
    
    user = db.Users.find_one({'verification_code': code})
    if user:
        if user['verified'] == False:
            db.Users.update_one({"_id": user['_id']}, {'$set': {'verified': True}})
            flash('Your email address has been successfully verified')
            loginuser = User(user)
            login_user(loginuser, remember=True)
            return redirect('/home')
        else:
            flash("You are already verified. Please login")
            return redirect('/')
    else:
        flash('Invalid verification code. Please check you email and use the correct link')
        return redirect('/')

@app.route('/SignUp', methods=["GET", "POST"])
def SignUpPage():
    store_url(request.url)
    if request.method =="POST":
        email1 = request.form.get('email')
        username1 = request.form.get("username")
        password1 = request.form.get("password")
        CPassword = request.form.get("CPassword")
        firstname = request.form.get("firstname")
        lastname = request.form.get("lastname")
        if len(email1) < 4:
            flash('Email must be greater than 3 characters.', category='error')
            pass
        elif db.Users.find_one({"email": email1}) != None:
            flash('Email in use', category='error')
            pass
        elif len(username1) < 2:
            flash('Username must be greater than 1 characters.', category='error')
            pass
        elif db.Users.find_one({"username": username1}) != None:
            flash('Username in use', category='error')
            pass
        elif password1 != CPassword:
            flash('Passwords do not match', category='error')
            pass
        elif len(password1) < 7:
            flash('Password must be greater than 6 characters.', category='error')
            pass
        else:
            password1 = bcrypt.generate_password_hash(password1).decode('utf-8')
            verification_code = generate_verification_code()
            newuserdate = datetime.utcnow()
            address = None
            moveaddress1 = None
            movehistory = []
            role="Default"
            user = userSchema(username1, password1, email1, newuserdate, address, firstname, lastname, moveaddress1, role, movehistory, verification_code)
            db.Users.insert_one(user.__dict__)

            msg = Message('Verify Your Email', sender=app.config['MAIL_USERNAME'], recipients = [user.email])
            verification_link = url_for('verify_email', code=verification_code, _external=True)
            msg.html = render_template('verification_email.html', verification_link=verification_link)
            mail.send(msg)
            flash('A verification email has been sent. Please check your inbox')
            return redirect('/')

    return render_template('SignUpPage.html')

@app.route('/home', methods=["GET"])
@login_required
def home():
    store_url(request.url)

    id = current_user.user_json["_id"]
    user = db.Users.find_one({"_id": ObjectId(id)})
    address = user["address"]

    return render_template('home.html', address=address, role=user["role"])


@app.route('/about', methods=["GET"])
def aboutus():
    store_url(request.url)

    return render_template('About.html')

@app.route('/newaddress', methods=["GET", "POST"])
@login_required
def newaddress():
    store_url(request.url)
    if request.method =="POST":
        firstname = current_user.user_json["firstname"]
        lastname = current_user.user_json["lastname"]
        address = request.form.get('address')
        city = request.form.get('city')
        state = request.form.get('state')
        zip = request.form.get('zip5')

        validaddress = Address(
            name= firstname + " " + lastname,
            address_1=address,
            city=city,
            state=state,
            zipcode=zip
        )
        usps = USPSApi('37RUTGE6O0597', test=True)
        validation = usps.validate_address(validaddress)
    
        try:
            keyerror = validation.result['AddressValidateResponse']['Address']['Error']
            flash("Not a valid address")
        except KeyError:
            print(validation.result)
            address = validation.result['AddressValidateResponse']['Address']['Address2']
            city = validation.result['AddressValidateResponse']['Address']['City']
            state = validation.result['AddressValidateResponse']['Address']['State']
            zip = validation.result['AddressValidateResponse']['Address']['Zip5']

            enteraddress = Address1(address, city, state, zip)
            jsonaddress = enteraddress.__dict__
            current = current_user.user_json["_id"]
            db.Users.update_one({"_id": ObjectId(current)}, {"$set": {"address": jsonaddress}})
            
            flash("accepted address")
            return redirect('/home')
            
    return render_template('newaddress.html', role=current_user.user_json["role"])

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/Login')


flag = 0
flag2 = 0
flag3 = 0
urlcount = 0
@app.route('/Adminpage', methods=["GET", "POST"])
@login_required
def adminpage():
    global flag
    global flag2
    global flag3
    global userinadmin
    buttonpress = request.form.get("adminfix")
    print(buttonpress)
    print("hello")
    if session["last_url"] != "http://localhost:5000/Adminpage":
        flag = 0
        flag2 = 0
        flag3 = 0

    store_url(request.url)
    while(True):
        data = []
        count = 0
        count2 = 0
 
        
        for i in db.Users.find({}):
            if i['moveaddress'] != None and i['moveaddress']["verified"] == True:
                count += 1
            data.append(i)
            
        count2 += 1
        if buttonpress == "1":
            print("done")
            flag = 0
            flag2 = 0
            flag3 = 0
            return render_template('Adminpage.html', role=current_user.user_json["role"], count=count, data=data)
        
        if request.method == "POST" and flag3 == 0:
            flag = 1
            
            for i in data:
               # print(request.form.get('editinfo'))
               # print(str(i))
                if request.form.get('editinfo') == str(i):
                    userinadmin = i
                    break
                
        if flag == 0:
            flag3 = 0
            return render_template('Adminpage.html', role=current_user.user_json["role"], count=count, data=data)
        else:
            if request.method == "POST" and flag2 == 1:
                address = request.form.get('address')
                city = request.form.get('city')
                state = request.form.get('state')
                zip = request.form.get('zip5')
                newaddress = request.form.get('newaddress')
                newcity = request.form.get('newcity')
                newstate = request.form.get('newstate')
                newzip = request.form.get('newzip5')
                
                date = request.form.get('date')
                reason = request.form.get('radiobox')

                if address == "" or city == "" or state == "" or zip == "" or newaddress == "" or newcity == "" or newstate == "" or newzip == "" or date == "" or reason == "":
                    flash("Please fill out all fields")
                else:

                    validaddress = Address(
                    name=userinadmin["firstname"] + " " + userinadmin["lastname"],
                    address_1=address,
                    city=city,
                    state=state,
                    zipcode=zip
                )
                    usps = USPSApi('37RUTGE6O0597', test=True)
                    validation = usps.validate_address(validaddress)
                    try:
                        keyerror = validation.result['AddressValidateResponse']['Address']['Error']
                        flash("Address is not a valid address")
                    except KeyError:
                       # print(validation.result)
                        address = validation.result['AddressValidateResponse']['Address']['Address2']
                        city = validation.result['AddressValidateResponse']['Address']['City']
                        state = validation.result['AddressValidateResponse']['Address']['State']
                        zip = validation.result['AddressValidateResponse']['Address']['Zip5']

                        enteraddress = Address1(address, city, state, zip)
                        jsonaddress = enteraddress.__dict__
                        current = userinadmin["_id"]
                        db.Users.update_one({"_id": ObjectId(current)}, {"$set": {"address": jsonaddress}})

                        newvalidaddress = Address(
                        name=userinadmin["firstname"] + " " + userinadmin["lastname"],
                        address_1=newaddress,
                        city=newcity,
                        state=newstate,
                        zipcode=newzip
                        )
                        usps = USPSApi('37RUTGE6O0597', test=True)
                        validation = usps.validate_address(newvalidaddress)
                        try:
                            keyerror = validation.result['AddressValidateResponse']['Address']['Error']
                            flash("New Address is not a valid address")
                        except KeyError:
                            newaddress = validation.result['AddressValidateResponse']['Address']['Address2']
                            newcity = validation.result['AddressValidateResponse']['Address']['City']
                            newstate = validation.result['AddressValidateResponse']['Address']['State']
                            newzip = validation.result['AddressValidateResponse']['Address']['Zip5']
                            enteraddress = MoveAddress1(newaddress, newcity, newstate, newzip, date, reason)
                            jsonaddress = enteraddress.__dict__
                            current = userinadmin["_id"]
                            db.Users.update_one({"_id": ObjectId(current)}, {"$set": {"moveaddress": jsonaddress}})
                            db.Users.update_one({"_id": ObjectId(current)}, {"$push": {"movehistory": jsonaddress}})
                            flag = 0
                            flag3 = 1
                            flag2 = 0
                            verified = request.form.get("verifiedbox")
                            if verified == None:
                                verified = False
                            else:
                                verified = True
                            #print(verified)
                            db.Users.update_one({"_id": ObjectId(current)}, {"$set": {"moveaddress.verified": verified}})

                            return redirect(url_for('adminpage'))   
                                   
            flag2=1
            
            return render_template("adminedit.html", user=userinadmin, role=current_user.user_json["role"])


@app.route('/moveaddress', methods=["GET", "POST"])
@login_required
def moveaddress():
    store_url(request.url)
    user_id = current_user.user_json["_id"]
    user = db.Users.find_one({'_id': ObjectId(user_id)})
    current_address = user.get("address", {})

    if request.method == "POST":
        address_form = request.form.get('address')
        city = request.form.get('city')
        state = request.form.get('state')
        zip_code = request.form.get('zip5')

        new_address = request.form.get('newaddress')
        new_city = request.form.get('newcity')
        new_state = request.form.get('newstate')
        new_zip = request.form.get('newzip5')

        date = request.form.get('date')
        reason = request.form.get('radiobox')

        valid_address = Address(
            name=current_user.user_json["firstname"] + " " + current_user.user_json["lastname"],
            address_1=address_form,
            city=city,
            state=state,
            zipcode=zip_code
        )
        usps = USPSApi('37RUTGE6O0597', test=True)
        validation = usps.validate_address(valid_address)

        try:
            keyerror = validation.result['AddressValidateResponse']['Address']['Error']
        except KeyError:
            address_form = validation.result['AddressValidateResponse']['Address']['Address2']
            city = validation.result['AddressValidateResponse']['Address']['City']
            state = validation.result['AddressValidateResponse']['Address']['State']
            zip_code = validation.result['AddressValidateResponse']['Address']['Zip5']

            if address_form != current_address["address"] or city != current_address["city"] or \
               state != current_address["state"] or zip_code != current_address["zip"]:
                flash("Incorrect Address")
            elif date == "":
                flash("Enter in a date")
            elif reason is None:
                flash("Enter in a reason")
            else:
                new_valid_address = Address(
                    name=current_user.user_json["firstname"] + " " + current_user.user_json["lastname"],
                    address_1=new_address,
                    city=new_city,
                    state=new_state,
                    zipcode=new_zip
                )
                usps = USPSApi('37RUTGE6O0597', test=True)
                validation = usps.validate_address(new_valid_address)

                try:
                    keyerror = validation.result['AddressValidateResponse']['Address']['Error']
                    flash("New Address is not a valid address")
                except KeyError:
                    new_address = validation.result['AddressValidateResponse']['Address']['Address2']
                    new_city = validation.result['AddressValidateResponse']['Address']['City']
                    new_state = validation.result['AddressValidateResponse']['Address']['State']
                    new_zip = validation.result['AddressValidateResponse']['Address']['Zip5']

                    enter_address = MoveAddress1(new_address, new_city, new_state, new_zip, date, reason)
                    json_address = enter_address.__dict__
                    current = current_user.user_json["_id"]
                    db.Users.update_one({"_id": ObjectId(current)}, {"$set": {"moveaddress": json_address}})
                    db.Users.update_one({"_id": ObjectId(current)}, {"$push": {"movehistory": json_address}})

                    return redirect('/summary')

    if session['last_url'] == 'http://localhost:5000/summary' or session['last_url'] == 'http://localhost:5000/moveinfo':
        store_url(request.url)
        try:
            return render_template('editmoveaddress.html', 
                               address=current_user.user_json["address"]["address"],
                               city = current_user.user_json["address"]["city"],
                               state = current_user.user_json["address"]["state"],
                               zip = current_user.user_json["address"]["zip"],
                               newaddress = current_user.user_json["moveaddress"]["address"],
                               newcity = current_user.user_json["moveaddress"]["city"],
                               newstate = current_user.user_json["moveaddress"]["state"],
                               newzip = current_user.user_json["moveaddress"]["zip"],
                               date = current_user.user_json["moveaddress"]["date"],
                               reason = current_user.user_json["moveaddress"]["reason"],
                               role = current_user.user_json["role"]
                               )
        except TypeError:
            return render_template('moveaddress.html', role = current_user.user_json["role"], address=current_address, newaddress=user.get("moveaddress", {}))
    else:
        store_url(request.url)
        return render_template('moveaddress.html', role = current_user.user_json["role"], address=current_address, newaddress=user.get("moveaddress", {}))


@app.route('/verify_emailforaddress/<code>', methods=["GET"])
@login_required
def verify_emailforaddress(code): 
    usercode = current_user.user_json["moveaddress"]["verification_code"]
    print(code)
    print(usercode)
    if current_user.user_json["moveaddress"]['verified'] == False:
        db.Users.update_one({"_id": current_user.user_json['_id']}, {'$set': {"moveaddress.verified": True}})
        flash('Your email address has been successfully verified. Move address added.')
        return redirect('/home')
    else:
        flash("You already verified your email. Move address not changed.")
        return redirect('/home')

@app.route('/summary', methods=["GET", "POST"])
@login_required
def summary():
    store_url(request.url)
    user = db.Users.find_one(current_user.user_json['_id'])
    button = request.form.get("checkbox")
    editbutton = request.form.get("editinfo")
    
    print(user)
    if request.method == "POST":
        if button == "agree":
            verification_code = generate_verification_code()
            print(verification_code)
            db.Users.update_one({"_id": current_user.user_json['_id']}, {'$set': {"moveaddress.verification_code": verification_code}})
            db.Users.update_one({"_id": current_user.user_json['_id']}, {'$set': {"moveaddress.verified": False}})

            msg = Message('Verify Your Address', sender=app.config['MAIL_USERNAME'], recipients = [current_user.user_json["email"]])
            verification_link = url_for('verify_emailforaddress', code=verification_code, _external=True)
            msg.html = render_template('verification_email.html', verification_link=verification_link)
            mail.send(msg)
            flash('A verification email has been sent. Please check your inbox')
            return redirect('/home')
        elif editbutton == "editinfo":
            return redirect('/moveaddress')
        else:
            flash("Please click the \'I agree\' checkbox to continue.")

    return render_template('summary.html', user=user, role = current_user.user_json["role"])

@app.route('/viewhistory', methods=["GET", "POST"])
@login_required
def viewhistory():
    user = current_user.user_json["_id"]
    user = db.Users.find_one({'_id': user})
    history = current_user.user_json["movehistory"]
    if request.method == "POST":
        for i in history:
            if request.form.get("deletebutton") == str(i):
                db.Users.update_one({"_id": ObjectId(current_user.user_json["_id"])}, {"$pull": {"movehistory": i}})
                return redirect(url_for('viewhistory'))

    return render_template('viewhistory.html', user=user)

@app.route('/moveinfo', methods=["GET", "POST"])
@login_required
def moveinfo():
    store_url(request.url)
    user = current_user.user_json["_id"]
    user = db.Users.find_one({'_id': user})
    if request.form.get("movebutton") == "2":
        return redirect("/viewhistory")
    elif request.form.get("movebutton") == "1":
        return redirect('/moveaddress')
    elif request.form.get("movebutton") == "3":
        db.Users.update_one({"_id": ObjectId(current_user.user_json["_id"])}, {"$set": {"moveaddress": None}})
        return redirect(url_for('moveinfo'))
        
    return render_template('moveinfo.html', user=user, role=current_user.user_json["role"])

@app.route('/ContactUs')
def ContactUs():
    return render_template('About.html', role=current_user.user_json["role"])

if __name__ == "__main__":
    app.run(debug=True)
