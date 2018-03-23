from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
import cgi

from database_setup import Base, Restaurant, MenuItem
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

engine=create_engine('sqlite:///restaurantMenu.db')
Base.metadata.bind=engine
DBSession=sessionmaker(bind=engine)
session=DBSession()



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