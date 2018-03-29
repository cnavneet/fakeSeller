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

@app.route('/logout')
def logout():
	resp=make_response(redirect('/'))
	resp.set_cookie('user_id',"")
	return resp

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
	if request.cookies.get('user_id'):
		return redirect(url_for('profile'))
	if request.method=='POST':
		username=request.form['username']
		password=request.form['password']
		brand=request.form['brand']
		
		u=session.query(Brand).filter_by(name=brand,username=username).one()
		if u and valid_pw(username,password,u.password):
			resp=make_response(redirect('profile'))
			resp.set_cookie('user_id',str(u.id))
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
		user_id=int(request.cookies.get('user_id'))
		brand=session.query(Brand).filter_by(id=user_id).one()
		sub=session.query(SubBrand).filter_by(parent_id=user_id).all()
		seller=session.query(Seller).filter_by(parent_id=user_id).all()
		return render_template('profile.html',brand=brand,sub=sub,seller=seller)
	else:
		return redirect(url_for('signin'))

@app.route('/profile/<int:user_id>/<int:seller_id>/sdelete',methods=['GET','POST'])
def sdelete(user_id,seller_id):
	if not request.cookies.get('user_id'):
		return redirect(url_for('signin'))
	brand=session.query(Brand).filter_by(id=user_id).one()
	seller=session.query(Seller).filter_by(parent_id=user_id,id=seller_id).one()
	if request.method=='POST':
		session.delete(seller)
		session.commit()
		flash("Successfully deleted "+seller.name+" registered for "+seller.product+" !!")

		return redirect(url_for('profile'))

	return render_template('sdelete.html',brand=brand,seller=seller)

@app.route('/profile/<int:user_id>/<int:product_id>/delete',methods=['GET','POST'])
def pdelete(user_id,product_id):
	if not request.cookies.get('user_id'):
		return redirect(url_for('signin'))
	brands=session.query(Brand).filter_by(id=user_id).one()
	brandItem=session.query(SubBrand).filter_by(id=product_id,parent_id=user_id).one()
	if request.method=='POST':
		Pdel=session.query(SubBrand).filter_by(id=product_id,parent_id=user_id).one()
		session.delete(Pdel)
		session.commit()
		flash("Sub-brand/Product deleted!!")

		return redirect(url_for('profile'))

	return render_template('pdelete.html',brand=brands,sbrand=brandItem)

@app.route('/profile/<int:user_id>/<int:product_id>/edit',methods=['POST','GET'])
def pedit(user_id,product_id):
	if not request.cookies.get('user_id'):
		return redirect(url_for('signin'))
	brands=session.query(Brand).filter_by(id=user_id).one()
	brandItem=session.query(SubBrand).filter_by(id=product_id,parent_id=user_id).one()
	if request.method=='POST':
		brandItem.name=request.form['name']
		u=request.form['name']
		session.add(brandItem)
		session.commit()
		flash("Sub-brand/Product name editted successfully!!")

		return redirect(url_for('profile'))

	return render_template('bedit.html',brand=brands,sbrand=brandItem)

@app.route('/profile/<int:user_id>/<int:seller_id>/sedit',methods=['GET','POST'])
def sedit(user_id,seller_id):
	if not request.cookies.get('user_id'):
		return redirect(url_for('signin'))
	brand=session.query(Brand).filter_by(id=user_id).one()
	sub=session.query(SubBrand).filter_by(parent_id=user_id).all()
	seller=session.query(Seller).filter_by(parent_id=user_id,id=seller_id).one()

	if request.method=='POST':
		name=request.form['name']
		product=request.form['product']
		price=request.form['price']

		sb=session.query(SubBrand).filter_by(parent_id=user_id,name=product).all()
		if not sb:
			msg="The sub-brand/product is'nt in the current list of "+brand.name
			return render_template('selledit.html',msg=msg,brand=brand,sub=sub,seller=seller)

		seller.name=name
		seller.product=product
		seller.price=price
		session.add(seller)
		session.commit()

		flash("Successfully editted "+seller.name)
		return redirect(url_for('profile'))

	return render_template('selledit.html',brand=brand,sub=sub,seller=seller)

@app.route('/digitaladmin',methods=['POST','GET'])
def admin():
	if request.method=='POST':
		admin_username=request.form['username']
		admin_password=request.form['password']

		if admin_username=='digitalibiadmin' and admin_password=='adminadmin':
			return redirect(url_for('adminpage'))
		msg="Inavlid admin credentials!!"
		return render_template('admin.html',msg=msg)
	return render_template('admin.html')

@app.route('/adminpage/<int:brand_id>/addelete')
def addel(brand_id):
	brand=session.query(Brand).filter_by(id=brand_id).one()
	session.delete(brand)
	session.commit()

	flash(brand.name+" successfully deleted!!")
	return redirect(url_for('adminpage'))

@app.route('/branddetail/<int:brand_id>/')
def branddetail(brand_id):
	brand=session.query(Brand).filter_by(id=brand_id).one()
	sub=session.query(SubBrand).filter_by(parent_id=brand_id).all()
	seller=session.query(Seller).filter_by(parent_id=brand_id).all()
	return render_template('brandDetail.html',sub=sub,seller=seller,brand=brand)

@app.route('/adminpage')
def adminpage():
	brandData=session.query(Brand).all()
	return render_template('brandpage.html',data=brandData)

@app.route('/profile/<int:user_id>/newbrand',methods=['GET','POST'])
def newbrand(user_id):
	brand=session.query(Brand).filter_by(id=user_id).one()
	sub=session.query(SubBrand).filter_by(parent_id=user_id).all()
	if request.method=='POST':
		name=request.form['name']
		u=session.query(SubBrand).filter_by(name=name,parent_id=user_id).all()
		if u:
			msg='Sub-brand/product with this name already exists!!'
			return render_template('newbrand.html',brand=brand,sub=sub,msg=msg)
		subb=SubBrand(name=name,parent_id=user_id)
		session.add(subb)
		session.commit()

		flash("Sub-brand/product has been added and displayed in the corresponding section!")

		return redirect(url_for('profile'))
	return render_template('newbrand.html',brand=brand,sub=sub)

@app.route('/profile/<int:user_id>/newseller',methods=['GET','POST'])
def newseller(user_id):
	brand=session.query(Brand).filter_by(id=user_id).one()
	seller=session.query(Seller).filter_by(parent_id=user_id).all()
	sub=session.query(SubBrand).filter_by(parent_id=user_id).all()
	if request.method=='POST':
		name=request.form['name']
		product=request.form['product']
		price=request.form['price']
		u=session.query(Seller).filter_by(name=name,product=product,parent_id=user_id).all()
		if u:
			msg='Seller name with particular product already exists is already registered with the particular product!!'
			return render_template('newseller.html',brand=brand,msg=msg,sub=sub)
		subs=Seller(name=name,product=product,price=price,parent_id=user_id)
		session.add(subs)
		session.commit()

		flash("Seller has be successfully registered and displayed in the corresponding section!!")

		return redirect(url_for('profile'))
	return render_template('newseller.html',brand=brand,sub=sub)

if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)