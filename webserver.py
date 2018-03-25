from flask import Flask, render_template, request, redirect, url_for, flash, session, escape, make_response
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Brand, Seller, SubBrand

import re
import random
import hashlib
import hmac
from string import letters

app = Flask(__name__)

engine = create_engine('sqlite:///BrandSeller.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

secret='gduiwdhe28ey3812983uio12rhe3900-`--'

def make_secure_val(val):
	return '%s|%s'%(val,hmac.new(secret,val).hexdigest())

def check_secure_val(secure_val):
	val=secure_val.split('|')[0]
	if secure_val==make_secure_val(val):
		return val

def set_secure_cookie(name,val):
	resp=make_response(redirect(url_for('profile')))
	resp.set_cookie(name,val)

def read_secure_cookie(name):
	uid=request.cookies.get(name)
	return uid

def login(user):
	set_secure_cookie('user_id',user)

def logout():
	response.headers.add_header('Set-Cookie','user_id=; Path=/')

def initialize(*a,**kw):
	initialize(*a,**kw)
	uid=read_secure_cookie('user_id')
	q=session.query(Brand).filter_by(id=uid).one()
	user=uid
	if user and q:
		return user

def make_salt(length=5):
	return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name,pw,salt=None):
	if not salt:
		salt=make_salt()
	h=hashlib.sha256(name+pw+salt).hexdigest()
	return '%s,%s'%(salt,h)

def valid_pw(name,password,h):
	salt=h.split(',')[0]
	return h==make_pw_hash(name,password,salt)

USER_RE=re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
	return username and USER_RE.match(username)

PASS_RE=re.compile(r"^.{3,20}$")
def valid_password(password):
	return password and PASS_RE.match(password)

EMAIL_RE=re.compile(r"^[\S]+@[\S]+\.[\S]+$")
def valid_email(email):
	return not email or EMAIL_RE.match(email)

@app.route('/',methods=['POST','GET'])
def signin():
	if request.method=='POST':
		username=request.form['username']
		password=request.form['password']
		pw=make_pw_hash(username,password)
		u=session.query(Brand).filter_by(username=username, password=pw).all()
		if u:
			resp=make_session(redirect('profile'))
			resp.set_cookie('user_id',str(u[0].id))
			return resp
		msg="Invalid Login!!"
		return render_template('welcome.html',msg=msg)
	return render_template('welcome.html')

@app.route('/signup',methods=['POST','GET'])
def signup():
	if request.method=='POST':
		have_error=False
		username=request.form['username']
		name=request.form['brand']
		password=request.form['password']
		verify=request.form['verify']
		email=request.form['email']

		params=dict(username=username, email=email)

		if not valid_username(username):
			params['error_username']="This is not a valid username"
			have_error=True

		if not valid_password(password):
			params['error_password']="That wasn't a valid password"
			have_error=True
		elif password!=verify:
			params['error_verify']="Your passwords didn't match"
			have_error=True

		if not valid_email(email):
			params['error_email']="Thats's not a valid email-id"
			have_error=True

		u=session.query(Brand).filter_by(name=name).all()
		if u:
			params['brand_error']="This brand name already exists"
			have_error=True

		if have_error:
			return render_template('signup.html',**params)
		else:
			pw=make_pw_hash(username,password)
			newbrand=Brand(name=name,username=username,password=pw,enail=email)
			session.add(newbrand)
			session.commit()

			id=session.query(Brand).filter_by(name=name, username=username, password=pw).one()

			resp=make_response(redirect('profile'))
			resp.set_cookie('user_id',str(id.id))
			return resp

	return render_template('signup.html')

@app.route('/profile')
def profile():
	if request.cookies.get('user_id'):
		return "Welcome"+request.cookies.get('user_id')
	else:
		return redirect(url_for('signup'))


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)