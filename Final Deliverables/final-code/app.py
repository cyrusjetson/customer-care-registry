
from flask import Flask, render_template, request, redirect, session, url_for, request
import ibm_db
from base64 import b64encode
import re
import random
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
import os
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge
import pathlib
from datetime import date
import requests
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
import google.auth.transport.requests as e

# funtions
# to send mail


def sendmail(tomail, title, content):
    message = Mail(
        from_email='check@mail.com',
        to_emails=tomail,
        subject=title,
        html_content=content)
    sg = SendGridAPIClient(apikey)
    sg.send(message)


# check whether user authenticated


def checkauth():
    key_list = list(session.keys())
    if key_list:
        return True
    else:
        return False

# removes session


def clean():
    key_list = list(session.keys())
    for key in key_list:
        session.pop(key)


###         for session           ####
##         userid, name, email    ##

# Initial Steps
# for sendgrid
apikey = 'apikeyy'
global msg
# app
app = Flask(__name__)

# app secret key

app.secret_key = ""
app.config['MAX_CONTENT_LENGTH'] = 17 * 1024 * 1024  # 18MB
app.config['ALLOWED_EXTENSIONS'] = ['.jpg', 'jpeg', '.png', '.gif']

# Ensure responses aren't cached


@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    return response


# DB2 connection
print("Trying to connect...")
global conn
conn = ibm_db.connect("DATABASE=;HOSTNAME=;PORT=;SECURITY=SSL;SSLServerCertificate=DigiCertGlobalRootCA.crt;UID=;PWD=;", '', '')
print("connected..")

# OAuth for Google
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

GOOGLE_CLIENT_ID = "apps.googleusercontent.com"

client_secrets_file = os.path.join(
    pathlib.Path(__file__).parent, "client_secret.json")


# for navigating
@app.route('/nav/<x>')
def nav(x):
    if checkauth() == False:
        return redirect(url_for('err'))
    return render_template('revert.html', s=x)


@app.route('/', methods=['GET'])
def base():
    return redirect(url_for('login'))


# Login
@app.route('/login', methods=["GET", "POST"])
def login():
    msg = ''
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['pass']
        if len(username) == 0 or len(password) == 0:
            msg = 'Details are not filled completely!'
            return render_template('login.html', msg=msg)
        if username == 'admin' and password == 'admin':
            session['userid'] = 'admin'
            session['name'] = 'admin'
            session['email'] = 'imadmin@gmail.com'
            return redirect('/nav/2')
        else:
            sql = "select * from agents where username = ? and password = ?"
            stmt = ibm_db.prepare(conn, sql)
            ibm_db.bind_param(stmt, 1, username)
            ibm_db.bind_param(stmt, 2, password)
            ibm_db.execute(stmt)
            account = ibm_db.fetch_assoc(stmt)
            if account:
                session['userid'] = account['USERNAME']
                session['name'] = account['NAME']
                session['email'] = account['EMAIL']
                return redirect('/nav/3')

        sql = "select * from users where username = ? and password = ?"
        stmt = ibm_db.prepare(conn, sql)
        ibm_db.bind_param(stmt, 1, username)
        ibm_db.bind_param(stmt, 2, password)
        ibm_db.execute(stmt)
        account = ibm_db.fetch_assoc(stmt)
        if account:
            session['userid'] = account['USERNAME']
            session['name'] = account['NAME']
            session['email'] = account['EMAIL']
            return redirect('nav/1')
        else:
            msg = 'Incorrect user credentials'
            return render_template('login.html', msg=msg)
    else:
        
        print(request.host_url)
        complete_addr = request.host_url + "callback"
        print(complete_addr)
        global flow
        flow = Flow.from_client_secrets_file(
            client_secrets_file=client_secrets_file,
            scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email",
                    "openid"],
            redirect_uri=complete_addr
        )
        msg = ''
        return render_template('login.html', msg=msg)

# login using google


@app.route('/google')
def google():
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)

# verify for google login


@app.route('/callback')
def callback():
    try:
        flow.fetch_token(authorization_response=request.url)
        credentials = flow.credentials
        request_session = requests.session()
        cached_session = cachecontrol.CacheControl(request_session)
        token_request = e.Request(session=cached_session)

        id_info = id_token.verify_oauth2_token(
            id_token=credentials._id_token,
            request=token_request,
            audience=GOOGLE_CLIENT_ID
        )

        tempemail = id_info.get("email")
        tempname = id_info.get("name")
        sql = "select username from users where email = ?"
        stmt = ibm_db.prepare(conn, sql)
        ibm_db.bind_param(stmt, 1, tempemail)
        ibm_db.execute(stmt)
        account = ibm_db.fetch_assoc(stmt)
        if account:
            session["userid"] = account['USERNAME']
            session["email"] = tempemail
            session["name"] = tempname
            return redirect('/nav/1')
        else:
            clean()
            return render_template('signup.html', msg='Account not available kindly sign up!')
    except:
        return redirect(url_for('err'))


# signup
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    msg = ''
    if request.method == 'POST':
        username = request.form['username']
        if username == 'admin':
            msg = "Account already exists"
            return render_template('signup.html', msg=msg)
        name = request.form['name']
        email = request.form['email']
        phn = request.form['phn']
        password = request.form['pass']
        repass = request.form['repass']
        if len(username) == 0 or len(name) == 0 or len(email) == 0 or len(phn) == 0 or len(password) == 0 or len(repass) == 0:
            msg = "Form is not filled completely!!"

            return render_template('signup.html', msg=msg)

        elif password != repass:
            msg = "Password is not matched"

            return render_template('signup.html', msg=msg)
        elif not re.match(r'[a-z]+', username):
            msg = 'Username can contain only small letters and numbers'

            return render_template('signup.html', msg=msg)
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            msg = 'Invalid email'

            return render_template('signup.html', msg=msg)
        elif not re.match(r'[A-Za-z]+', name):
            msg = "Enter valid name"

            return render_template('signup.html', msg=msg)
        elif not re.match(r'[0-9]+', phn):
            msg = "Enter valid phone number"

            return render_template('signup.html', msg=msg)

        sql = "select * from users where username = ? or email = ? or phn = ?"
        stmt = ibm_db.prepare(conn, sql)
        ibm_db.bind_param(stmt, 1, username)
        ibm_db.bind_param(stmt, 2, email)
        ibm_db.bind_param(stmt, 3, phn)
        ibm_db.execute(stmt)
        account = ibm_db.fetch_assoc(stmt)
        if account:
            msg = 'Acccount already exists'
            return render_template('signup.html', msg=msg)
        else:
            sql = "select * from agents where username = ? or email = ? or phn = ?"
            stmt = ibm_db.prepare(conn, sql)
            ibm_db.bind_param(stmt, 1, username)
            ibm_db.bind_param(stmt, 2, email)
            ibm_db.bind_param(stmt, 3, phn)
            ibm_db.execute(stmt)
            account = ibm_db.fetch_assoc(stmt)
            if account:
                msg = 'Acccount already exists'
                return render_template('signup.html', msg=msg)
            else:
                global temp
                temp = {}
                temp['userid'] = username
                temp['name'] = name
                temp['email'] = email
                temp['phn'] = phn
                temp['password'] = password
                global code
                code = random.randint(10000, 99999)
                codee = str(code)
                try:
                    title = 'Verification code for customer care registry'
                    content = '<br><div style="background-color:rgb(102, 150, 184);color: white;padding:12px;border-radius:1rem;"><br><h1 style="color:black;"><center>Verification Code</center></h1><hr><h2>&nbsp;&nbsp;&nbsp;Your verification code: <strong><i>'+codee+'</i></strong> </h2>'
                    sendmail(email, title, content)
                except Exception:
                    msg = 'Not a valid email ID'
                    return render_template('signup.html', msg=msg)
                return render_template('verification.html', msg='', status=1)
    else:
        return render_template('signup.html')


@app.route('/verify', methods=['POST'])
def verify():
    try:
        if len(request.form['CODE']) < 5:
            msg = 'Enter valid code'
            return render_template('signup.html', msg=msg)
        if request.form['CODE'] == str(code):
            insert_sql = "insert into users values(?,?,?,?,?)"
            prep_stmt = ibm_db.prepare(conn, insert_sql)
            ibm_db.bind_param(prep_stmt, 1, temp['userid'])
            ibm_db.bind_param(prep_stmt, 2, temp['name'])
            ibm_db.bind_param(prep_stmt, 3, temp['email'])
            ibm_db.bind_param(prep_stmt, 4, temp['phn'])
            ibm_db.bind_param(prep_stmt, 5, temp['password'])
            ibm_db.execute(prep_stmt)
            tomail = temp['email']
            title = 'Hello from Team Nitro'
            content = '<br><div style="background-color:rgb(102, 150, 184);color: white;padding:12px;border-radius:1rem;"><br><h1 style="color:black;"><center>Welcome to customer care registry 😄❤️</center></h1><hr><h2>&nbsp;&nbsp;&nbsp;Your account has been created successfully! We happy to have you as our customer 😊 <strong><i></i></strong> </h2>'
            try:
                sendmail(tomail, title, content)
            except:
                print('error')
            msg = ''
            session['userid'] = temp['userid']
            session['name'] = temp['name']
            session['email'] = temp['email']
            return redirect('/nav/1')
        else:
            msg = "Wrong verification code"
            return render_template('signup.html', msg=msg)
    except:
        return redirect(url_for('err'))

# navigating to user dashboard


@app.route('/user')
def userafterlogin():
    msg = ''
    if checkauth() == False:
        return redirect(url_for('err'))
    sql = "select * from complaints where username = ?"
    complaints = []
    stmt = ibm_db.prepare(conn, sql)
    ibm_db.bind_param(stmt, 1, session['userid'])
    ibm_db.execute(stmt)
    dictionary = ibm_db.fetch_assoc(stmt)

    while dictionary != False:
        dictionary['NEWIMG'] = b64encode(dictionary['PIC']).decode("utf-8")
        complaints.append(dictionary)
        dictionary = ibm_db.fetch_assoc(stmt)
    return render_template('dashboard.html', name=session["name"], complaints=complaints, msg=msg)


# navigating to agent dashboard
@app.route('/agent')
def agentafterlogin():
    if checkauth() == False:
        return redirect(url_for('err'))
    msg = ''
    sql = "select * from complaints where assigned_agent = ?"
    complaints = []
    stmt = ibm_db.prepare(conn, sql)
    ibm_db.bind_param(stmt, 1, session['userid'])
    ibm_db.execute(stmt)
    dictionary = ibm_db.fetch_assoc(stmt)

    while dictionary != False:
        dictionary['NEWIMG'] = b64encode(dictionary['PIC']).decode("utf-8")
        complaints.append(dictionary)
        dictionary = ibm_db.fetch_assoc(stmt)
    return render_template('agentdash.html', name=session['name'], complaints=complaints, msg=msg)

# User
# new complaint by user


@app.route('/addnew', methods=["GET", "POST"])
def add():
    msg = ''
    if checkauth() == False:
        return redirect(url_for('err'))
    if request.method == 'POST':
        today = date.today()
        d1 = today.strftime("%d/%m/%Y")
        d2 = d1 + ''
        try:
            flag = 0
            title = request.form['title']
            des = request.form['des']

            if len(title) > 0 and len(des) > 0:
                file = request.files['file']
                if file:
                    extention = os.path.splitext(file.filename)[1].lower()
                    if extention not in app.config['ALLOWED_EXTENSIONS']:
                        newmsg = 'Allowed files are jpeg, gif, jpg, png'

                        sql = "select * from complaints where username = ?"
                        complaints = []
                        stmt = ibm_db.prepare(conn, sql)
                        ibm_db.bind_param(stmt, 1, session['userid'])
                        ibm_db.execute(stmt)
                        dictionary = ibm_db.fetch_assoc(stmt)

                        while dictionary != False:
                            dictionary['NEWIMG'] = b64encode(
                                dictionary['PIC']).decode("utf-8")
                            complaints.append(dictionary)
                            dictionary = ibm_db.fetch_assoc(stmt)
                        return render_template('dashboard.html', name=session["name"], complaints=complaints, msg=newmsg)
                    newtemp = os.path.join(
                        'static/assets/uploads/', secure_filename(file.filename))

                    file.save(newtemp)
                    try:
                        sql = "insert into complaints(username,title,complaint,pic,date_of_complaint) values(?,?,?,?,?)"

                        stmt = ibm_db.prepare(conn, sql)
                        ibm_db.bind_param(stmt, 1, session["userid"])
                        ibm_db.bind_param(stmt, 2, title)
                        ibm_db.bind_param(stmt, 3, des)
                        ibm_db.bind_param(stmt, 4, newtemp,
                                          ibm_db.PARAM_FILE, ibm_db.SQL_BLOB)
                        ibm_db.bind_param(stmt, 5, d2)
                        ibm_db.execute(stmt)
                        msg = 'Complaint added successfully'
                        flag = 1
                        if os.path.exists(newtemp):
                            os.remove(newtemp)
                        else:
                            print("The file does not exist")
                    except:
                        flag = 0
                        print('error in file upload')
                else:
                    try:
                        sql = "insert into complaints(username,title,complaint,date_of_complaint) values(?,?,?,?)"
                        stmt = ibm_db.prepare(conn, sql)
                        ibm_db.bind_param(stmt, 1, session["userid"])
                        ibm_db.bind_param(stmt, 2, title)
                        ibm_db.bind_param(stmt, 3, des)
                        ibm_db.bind_param(stmt, 4, d2)
                        ibm_db.execute(stmt)
                        msg = 'Complaint added successfully'
                        flag = 1
                    except:
                        flag = 0
                        print('error in add')
                if flag == 1:
                    try:
                        # auto-assign
                        sql = "select * from auto_assign"
                        stmt = ibm_db.prepare(conn, sql)
                        ibm_db.execute(stmt)
                        stat = ibm_db.fetch_assoc(stmt)
                        if stat['STATUS'] == 1:
                            sql = "select username from agents order by complaints_count asc limit 1"
                            stmt = ibm_db.prepare(conn, sql)
                            ibm_db.execute(stmt)
                            temp = ibm_db.fetch_assoc(stmt)
                            needed_agent = temp['USERNAME']
                            if needed_agent != None:
                                sql = "select c_id from complaints where username = ? and title = ? and complaint = ?"
                                stmt = ibm_db.prepare(conn, sql)
                                ibm_db.bind_param(stmt, 1, session["userid"])
                                ibm_db.bind_param(stmt, 2, title)
                                ibm_db.bind_param(stmt, 3, des)
                                ibm_db.execute(stmt)
                                temp = ibm_db.fetch_assoc(stmt)
                                ccid = temp['C_ID']
                                sql = "update complaints set assigned_agent =? where c_id = ?"
                                stmt = ibm_db.prepare(conn, sql)
                                ibm_db.bind_param(stmt, 1, needed_agent)
                                ibm_db.bind_param(stmt, 2, ccid)
                                ibm_db.execute(stmt)
                                sql = "update agents set complaints_count = complaints_count+1 where username=?"
                                stmt = ibm_db.prepare(conn, sql)
                                ibm_db.bind_param(stmt, 1, needed_agent)
                                ibm_db.execute(stmt)

                                sql = "update agents set status =1 where username = ?"
                                stmt = ibm_db.prepare(conn, sql)
                                ibm_db.bind_param(stmt, 1, needed_agent)
                                ibm_db.execute(stmt)

                                sql = "update complaints set date_assigned =? where c_id = ?"
                                stmt = ibm_db.prepare(conn, sql)
                                ibm_db.bind_param(stmt, 1, d2)
                                ibm_db.bind_param(stmt, 2, ccid)
                                ibm_db.execute(stmt)
                                msg = 'Agent assigned'

                                sql = "select email from users where username =?"
                                stmt = ibm_db.prepare(conn, sql)
                                ibm_db.bind_param(stmt, 1, session["userid"])
                                ibm_db.execute(stmt)
                                stat = ibm_db.fetch_assoc(stmt)
                                title = 'Agent assigned'
                                content = '<br><div style="background-color:rgb(102, 150, 184);color: white;padding:12px;border-radius:1rem;"><br><h1 style="color:black;"><center>Agent assigned!</center></h1><hr><h2>&nbsp;&nbsp;&nbsp;Agent <i>' + \
                                    needed_agent+'</i> is assigned for your query and now your query is in progress..</h2>'
                                try:
                                    sendmail(stat['EMAIL'], title, content)
                                except:
                                    print('error in mail')
                    except:
                        print('error in auto assign')
            else:
                msg = 'Kindly fill the blanks'
            sql = "select * from complaints where username = ?"
            complaints = []
            stmt = ibm_db.prepare(conn, sql)
            ibm_db.bind_param(stmt, 1, session['userid'])
            ibm_db.execute(stmt)
            dictionary = ibm_db.fetch_assoc(stmt)

            while dictionary != False:
                dictionary['NEWIMG'] = b64encode(
                    dictionary['PIC']).decode("utf-8")
                complaints.append(dictionary)
                dictionary = ibm_db.fetch_assoc(stmt)
            return render_template('dashboard.html', name=session["name"], complaints=complaints, msg=msg)
        except RequestEntityTooLarge:
            msg = 'Too large than limit'
            sql = "select * from complaints where username = ?"
            complaints = []
            stmt = ibm_db.prepare(conn, sql)
            ibm_db.bind_param(stmt, 1, session['userid'])
            ibm_db.execute(stmt)
            dictionary = ibm_db.fetch_assoc(stmt)

            while dictionary != False:
                dictionary['NEWIMG'] = b64encode(
                    dictionary['PIC']).decode("utf-8")
                complaints.append(dictionary)
                dictionary = ibm_db.fetch_assoc(stmt)
            return render_template('dashboard.html', name=session["name"], complaints=complaints, msg=msg)
    else:
        return redirect(url_for('err'))
# Agent
# set stat


@app.route('/setstat/<x>')
def set(x):
    if checkauth() == False:
        return redirect(url_for('err'))
    if session['userid'] != 'admin':
        return redirect(url_for('err'))

    sql = "update auto_assign set status = ?"
    stmt = ibm_db.prepare(conn, sql)
    ibm_db.bind_param(stmt, 1, x)
    ibm_db.execute(stmt)
    return redirect(url_for('ad'))
# update complaint by Agent


@app.route('/updatecomplaint', methods=["GET", "POST"])
def updatecomplaint():
    if checkauth() == False:
        return redirect(url_for('err'))
    msg = ''
    if request.method == 'POST':
        cid = request.form['cid']
        solution = request.form['solution']
        if len(solution) > 0 and len(cid) > 0:
            try:
                today = date.today()
                d1 = today.strftime("%d/%m/%Y")
                d2 = '' + d1
                sql = "update complaints set solution =?,status=1,date_completed=? where c_id = ? and assigned_agent=?"
                stmt = ibm_db.prepare(conn, sql)
                ibm_db.bind_param(stmt, 1, solution)
                ibm_db.bind_param(stmt, 2, d2)
                ibm_db.bind_param(stmt, 3, cid)
                ibm_db.bind_param(stmt, 4, session["userid"])
                ibm_db.execute(stmt)
                sql = "update agents set solved_count = solved_count+1 where username=?"
                stmt = ibm_db.prepare(conn, sql)
                ibm_db.bind_param(stmt, 1, session["userid"])
                ibm_db.execute(stmt)
                sql = "select solved_count from agents where username = ?"
                stmt = ibm_db.prepare(conn, sql)
                ibm_db.bind_param(stmt, 1, session["userid"])
                ibm_db.execute(stmt)
                solved = ibm_db.fetch_assoc(stmt)

                sql = "select complaints_count from agents where username = ?"
                stmt = ibm_db.prepare(conn, sql)
                ibm_db.bind_param(stmt, 1, session["userid"])
                ibm_db.execute(stmt)
                complaints_count = ibm_db.fetch_assoc(stmt)
                if solved['SOLVED_COUNT'] == complaints_count['COMPLAINTS_COUNT']:
                    sql = "update agents set status =3 where username=?"
                    stmt = ibm_db.prepare(conn, sql)
                    ibm_db.bind_param(stmt, 1, session["userid"])
                    ibm_db.execute(stmt)
            except:
                print("cant insert")
        else:
            msg = 'Kindly fill the details'
        sql = "select * from complaints where assigned_agent = ?"
        complaints = []
        stmt = ibm_db.prepare(conn, sql)
        ibm_db.bind_param(stmt, 1, session["userid"])
        ibm_db.execute(stmt)
        dictionary = ibm_db.fetch_assoc(stmt)

        while dictionary != False:
            dictionary['NEWIMG'] = b64encode(dictionary['PIC']).decode("utf-8")
            complaints.append(dictionary)
            dictionary = ibm_db.fetch_assoc(stmt)
        return render_template('agentdash.html', name=session["name"], complaints=complaints, msg=msg)
    else:
        return redirect(url_for('signout'))


# agents page for Admin
@app.route('/agents')
def agents():
    if checkauth() == False:
        return redirect(url_for('err'))
    if session['userid'] != 'admin':
        return redirect(url_for('err'))
    sql = "select * from agents"
    agents = []
    stmt = ibm_db.prepare(conn, sql)
    ibm_db.execute(stmt)
    dictionary = ibm_db.fetch_assoc(stmt)
    while dictionary != False:
        agents.append(dictionary)
        dictionary = ibm_db.fetch_assoc(stmt)
    return render_template('agents.html', agents=agents)

# Admin page navigation


@app.route('/admin')
def ad():
    if checkauth() == False:
        return redirect(url_for('err'))
    if session['userid'] != 'admin':
        return redirect(url_for('err'))

    sql = "select * from auto_assign"
    stmt = ibm_db.prepare(conn, sql)
    ibm_db.execute(stmt)
    stat = ibm_db.fetch_assoc(stmt)

    global auto_stat
    auto_stat = stat['STATUS']
    sql = "select count(c_id) as temp from complaints"
    stmt = ibm_db.prepare(conn, sql)
    ibm_db.execute(stmt)
    temp = ibm_db.fetch_assoc(stmt)
    total = temp['TEMP']
    sql = "select count(c_id) as temp from complaints where length(assigned_agent) > 2"
    stmt = ibm_db.prepare(conn, sql)
    ibm_db.execute(stmt)
    temp = ibm_db.fetch_assoc(stmt)
    assigned = temp['TEMP']
    global count
    count = total - assigned
    return render_template('admin.html', auto_assign=auto_stat, count=count)


# adding new agent by Admin
@app.route('/addnewagent', methods=["GET", "POST"])
def addagent():
    if checkauth() == False:
        return redirect(url_for('err'))
    if session['userid'] != 'admin':
        return redirect(url_for('err'))

    if request.method == 'POST':
        username = request.form['username']
        name = request.form['name']
        email = request.form['email']
        phone = request.form['phone']
        password = request.form['password']
        if len(username) > 2 and len(name) > 1 and len(email) > 0 and len(phone) > 0 and len(password) > 2:
            try:
                sql = "insert into agents values(?,?,?,?,?,?,3,0,0)"
                stmt = ibm_db.prepare(conn, sql)
                ibm_db.bind_param(stmt, 1, username)
                ibm_db.bind_param(stmt, 2, name)
                ibm_db.bind_param(stmt, 3, email)
                ibm_db.bind_param(stmt, 4, phone)
                ibm_db.bind_param(stmt, 5, password)
                ibm_db.bind_param(stmt, 6, 'General support')
                ibm_db.execute(stmt)
            except:
                print("cant insert")

        return redirect(url_for('agents'))

    else:
        return redirect(url_for('signout'))


# Tickets page for admin
@app.route('/tickets')
def tickets():
    if checkauth() == False:
        return redirect(url_for('err'))
    if session['userid'] != 'admin':
        return redirect(url_for('err'))
    sql = "select * from complaints"
    complaints = []
    stmt = ibm_db.prepare(conn, sql)
    ibm_db.execute(stmt)
    dictionary = ibm_db.fetch_assoc(stmt)

    while dictionary != False:
        dictionary['NEWIMG'] = b64encode(dictionary['PIC']).decode("utf-8")
        complaints.append(dictionary)
        dictionary = ibm_db.fetch_assoc(stmt)

    sql = "select username from agents"
    freeagents = []
    stmt = ibm_db.prepare(conn, sql)
    ibm_db.execute(stmt)
    dictionary = ibm_db.fetch_assoc(stmt)
    while dictionary != False:
        freeagents.append(dictionary)
        dictionary = ibm_db.fetch_assoc(stmt)

    return render_template('tickets.html', complaints=complaints, freeagents=freeagents)

# Assign agent for admin


@app.route('/assignagent', methods=["GET", "POST"])
def assignagent():
    if checkauth() == False:
        return redirect(url_for('err'))
    if session['userid'] != 'admin':
        return redirect(url_for('err'))
    if request.method == "POST":
        ccid = request.form['ccid']
        agent = request.form['agent']
        if len(ccid) == 0:
            msg = 'Enter valid complaint ID'
        else:
            try:
                today = date.today()
                d1 = today.strftime("%d/%m/%Y")
                d2 = d1 + ''
                sql = "update complaints set assigned_agent =?,date_assigned= ? where c_id = ?"
                stmt = ibm_db.prepare(conn, sql)
                ibm_db.bind_param(stmt, 1, agent)
                ibm_db.bind_param(stmt, 2, d2)
                ibm_db.bind_param(stmt, 3, ccid)
                ibm_db.execute(stmt)
                sql = "update agents set complaints_count = complaints_count+1 where username=?"
                stmt = ibm_db.prepare(conn, sql)
                ibm_db.bind_param(stmt, 1, agent)
                ibm_db.execute(stmt)

                sql = "update agents set status =1 where username = ?"
                stmt = ibm_db.prepare(conn, sql)
                ibm_db.bind_param(stmt, 1, agent)  # updated
                ibm_db.execute(stmt)

                sql = "select username from complaints where c_id = ?"
                stmt = ibm_db.prepare(conn, sql)
                ibm_db.bind_param(stmt, 1, ccid)  # updated
                ibm_db.execute(stmt)
                dictionary = ibm_db.fetch_assoc(stmt)
                user = dictionary['USERNAME']

                sql = "select email from users where username = ?"
                stmt = ibm_db.prepare(conn, sql)
                ibm_db.bind_param(stmt, 1, user)  # updated
                ibm_db.execute(stmt)
                dictionary = ibm_db.fetch_assoc(stmt)
                tomail = dictionary['EMAIL']
                title = 'Agent assigned'
                content = '<br><div style="background-color:rgb(102, 150, 184);color: white;padding:12px;border-radius:1rem;"><br><h1 style="color:black;"><center>Agent assigned!</center></h1><hr><h2>&nbsp;&nbsp;&nbsp;Agent <i>' + \
                    agent+'</i> is assigned for your query and now your query is in progress..</h2>'
                try:
                    sendmail(tomail, title, content)
                except:
                    print('error')
            except:
                print("cant update")
        return redirect(url_for('tickets'))
    else:
        return redirect(url_for('signout'))


# password reset
@app.route('/forgot', methods=["GET", "POST"])
def forget():
    msg = ''
    if request.method == "GET":
        return render_template('forgot.html', msg=msg)
    else:
        global email
        global code
        email = request.form['email']
        if len(email) == 0:
            msg = 'Kindly fill the details'
            return render_template('forgot.html', msg=msg)
        sql = "select username from users where email = ?"
        stmt = ibm_db.prepare(conn, sql)
        ibm_db.bind_param(stmt, 1, email)
        ibm_db.execute(stmt)
        account = ibm_db.fetch_assoc(stmt)

        if account:
            username = account['USERNAME']
            userid = username
            code = random.randint(10000, 99999)
            codee = str(code)
            title = 'Verification code for reset password'
            content = '<br><div style="background-color:rgb(102, 150, 184);color: white;padding:12px;border-radius:1rem;"><br><h1 style="color:black;"><center>Verification Code</center></h1><hr><h2>&nbsp;&nbsp;&nbsp;Hello ' + \
                userid+', Your verification code for reset password: <strong><i>' + \
                codee+'</i></strong> </h2>'
            try:
                sendmail(email, title, content)
            except Exception:
                msg = 'Not a valid email ID'
                return render_template('forgot.html', msg=msg)

            return render_template('verification.html', msg='', status=2)
        else:
            msg = 'Not a valid email ID'
            return render_template('forgot.html', msg=msg)

# password reset verification


@app.route('/resetverify', methods=["GET", "POST"])
def resetverify():
    password = request.form['password']
    repass = request.form['repass']
    if password == repass and len(password) > 0:
        if request.form['CODE'] == str(code):
            try:
                sql = "update users set password = ? where email = ?"
                stmt = ibm_db.prepare(conn, sql)
                ibm_db.bind_param(stmt, 1, password)
                ibm_db.bind_param(stmt, 2, email)
                ibm_db.execute(stmt)
                msg = 'Password updated successfully'
                title = 'Password Reset'
                content = '<br><div style="background-color:rgb(102, 150, 184);color: white;padding:12px;border-radius:1rem;"><br><h1 style="color:black;"><center>Update</center></h1><hr><h2>&nbsp;&nbsp;&nbsp;Password updated successfully!  <strong><i></i></strong> </h2>'

                try:
                    sendmail(email, title, content)
                except Exception:
                    msg = 'Not a valid email ID'
                    return render_template('forgot.html', msg=msg)
            except Exception:
                print('error')

            return render_template('login.html', msg=msg)
        else:
            msg = "Wrong verification code"
            return render_template('forgot.html', msg=msg)
    else:
        msg = 'Password mismatch or fields are empty!'
        return render_template('verification.html', status=2)


@app.route('/err')
def err():
    return render_template('error.html')


@app.route('/signout')
def signout():
    key_list = list(session.keys())
    for key in key_list:
        session.pop(key)
    return render_template('revert.html', s=6)


if __name__ == "__main__":
    app.run(debug=False, host='0.0.0.0')
