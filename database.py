from sqlalchemy import Column, Integer, String, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import scoped_session, sessionmaker

Base = declarative_base()
engine = create_engine('sqlite:///database.db')
db_session = scoped_session(sessionmaker(autocommit=False, autoflush=False, bind=engine))

class File(Base):
    __tablename__ = 'files'
    id = Column(Integer, primary_key=True)
    filename = Column(String)

def init_db():
    Base.metadata.create_all(bind=engine)
