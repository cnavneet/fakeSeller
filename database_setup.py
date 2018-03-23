import os
import sys
from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
 
Base = declarative_base()
 
class Brand(Base):
    __tablename__ = 'brand'
   
    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    username=Column(String(250),nullable=False)
    password=Column(String(250),nullable=False)
    enail=Column(String(250),nullable=False)

class SubBrand(Base):
	__tablename__='subbrand'

	id=Column(Integer, primary_key=True)
	name=Column(String(250),nullable=False)
	parent_id=Column(Integer,ForeignKey('brand.id'))
	brand=relationship(Brand)

class Seller(Base):
	__tablename__='seller'

	id=Column(Integer, primary_key=True)
	name=Column(String(250), nullable=False)
	product=Column(String(250),nullable=False)
	price=Column(String(20))
	parent_id=Column(Integer,ForeignKey('brand.id'))
	brand=relationship(Brand)


engine = create_engine('sqlite:///BrandSeller.db')
Base.metadata.create_all(engine)