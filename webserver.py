from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
import cgi

from database_setup import Base, Brand, SubBrand, Seller
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import os
import re
import random
import hashlib
import hmac
from string import letters

engine=create_engine('sqlite:///restaurantMenu.db')
Base.metadata.bind=engine
DBSession=sessionmaker(bind=engine)
session=DBSession()

secret='fguqq7ye782ewiuqhdd	eo92`-112o`2=-=`ii'

def make_secure_val(val):
	return '%s|%s'%(val,hmac.new(secret,val).hexdigest())

def check_secure_val(secure_val):
	val=secure_val.split('|')[0]
	if secure_val==make_secure_val(val):
		return val
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



class webserverHandler(BaseHTTPRequestHandler):

	def set_secure_cookie(self, name, val):
		cookie_val=make_secure_val(val)
		self.send_header('Set-Cookie','%s=%s;Path=/'%(name,cookie_val))
		self.end_headers()

	def read_secure_cookie(self,name):
		cookie_val=cgi.parse_cookie(name)
		return cookie_val and check_secure_val(cookie_val)

	def initialize(self, *a, **kw):
		uid=self.read_secure_cookie('user_id')
		self.user=uid and User.by_id(int(uid))

	def do_GET(self):
		if self.path.endswith("/"):
			self.send_response(200)
			self.send_header('Content-type','text/html')
			self.end_headers()

			output=""
			output+="<html><body>"
			output+="<h2>Sign In</h2>"
			output+="<form method='POST' enctype='multipart/form-data' action=''>"
			output+="<input type='text' name='username' required placeholder='Username'></br>"
			output+="<input type='password' name=password' required' placeholder='Password'></br>"
			output+="<input type='submit' name='Log In'>"
			output+="</form><a href='/signup'>Signup</a></body></html>"
			self.wfile.write(output)
			return

	def do_POST(self):
		if self.path.endswith("/"):
			ctype, pdict=cgi.parse_header(
				self.headers.getheader('content-type'))
			if ctype=='multipart/form-data':
				fields=cgi.parse_multipart(self.rfile,pdict)
				username=fields.get('username')
				pw_hash=fields.get('password')
				pw_hash=make_pw_hash(username,pw_hash)
				u=session.query(Brand).filter_by(username=username,password=pw_hash).one()
				self.login(u.id)

				self.send_response(301)
				self.send_header('Content-type','text/html')
				self.login(u.id)
				self.send_header('Location','/profile')
				self.end_headers()

		if self.path.endswith("/signup"):
			ctype, pdict=cgi.parse_header(
				self.headers.getheader('content-type'))
			if ctype=='multipart/form-data':
				fields=cgi.parse_multipart(self.rfile.pdict)
				name=fields.get('brandName')
				username=fields.get('username')
				pw_hash=fields.get('password')
				pw_hash=make_pw_hash(username,pw_hash)
				email=fields.get('email')
				newBrand=Brand(name=name[0],username=username[0],password=pw_hash[0],email=email[0])
				session.add(newBrand)
				session.commit()

				u=session.query(Brand).filter_by(username=username,password=pw_hash).one()

				self.send_response(301)
				self.send_header('Content-type','text/html')
				self.login(u.id)
				self.send_header('Location','/profile')
				self.end_headers()


def main():
	try:
		port=8080
		server=HTTPServer(('',port), webserverHandler)
		print "Server running on port %s"%port
		server.serve_forever()

	except:
		print "^C entered, stopping web server...!!"
		server.socket.close()

if __name__ == '__main__':
	main()