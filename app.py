from ast import Delete
from flask import Flask, url_for, render_template, request, Response, flash, redirect
import pyodbc
import passlib
import base64
from werkzeug.utils import secure_filename
from forms import RegistrationForm, LoginForm, MemeForm, EditMeme
from helpers import login_required
from tempfile import mkdtemp
from sqlalchemy import Column, Integer, String, ForeignKey, LargeBinary
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import exc
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy_utils import PasswordType, force_auto_coercion
import sqlalchemy
from threading import get_ident
from flask_login import (
    UserMixin,
    login_user,
    LoginManager,
    current_user,
    logout_user,
    login_required,
)


app = Flask(__name__)


wsgi_app = app.wsgi_app

app.config['DEBUG'] = True

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True

app.config["TEMPLATES_AUTO_RELOAD"] = True
app.config['SECRET_KEY'] = '5791628bb0b13ce0c436dfde280ba245'


app.config["SESSION_TYPE"] = "sqlalchemy"



def b64encode(data):
    return base64.b64encode(data).decode()

app.jinja_env.filters['b64encode'] = b64encode

Base = declarative_base()



server = 'KAMIL-KOMPUTER\SQLEXPRESS'
username = 'tester'
password = '1234'
database = 'MemDB'
driver = 'ODBC+DRIVER+17+for+SQL+Server'
engine_stmt = 'mssql+pyodbc://{}:{}@{}/{}?driver={}'.format(username,
                                                            password,
                                                            server,
                                                            database,
                                                            driver)



engine = sqlalchemy.create_engine(engine_stmt)




# https://stackoverflow.com/questions/43459182/proper-sqlalchemy-use-in-flask
db_session = scoped_session(sessionmaker(autocommit=False,
                                         autoflush=False,
                                         bind=engine))



class BaseModel(object):
    query = db_session.query_property()

Base = declarative_base(cls=BaseModel)


class User (Base, UserMixin):

    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    username = Column(String(256), unique=True, nullable=False)   
    password = Column(PasswordType(
        schemes=[
            'pbkdf2_sha512',
            'md5_crypt'
        ],
        deprecated=['md5_crypt']
    ), nullable=False)
    memes = relationship("Meme", backref='users')

    def __repr__(self):
        return '<User %r>' % self.username

    def get_name(self):
            return str(self.username)


class Meme (Base):

    __tablename__ = 'memes'

    id = Column(Integer, primary_key=True)
    img = Column(LargeBinary, nullable=False)
    title = Column(String(256), nullable=False)
    filename = Column(String(256), nullable=False)
    mimetype = Column(String(256), nullable=False)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)





login_manager = LoginManager()
login_manager.session_protection = "strong"
login_manager.login_view = "login"
login_manager.login_message = "Zaloguj się aby uzyskać dostęp."
login_manager.login_message_category = "info"


login_manager.init_app(app, add_context_processor=True)

Base.metadata.create_all(engine)



@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))



@app.route('/')
@app.route("/index")
@login_required
def index():
    username = current_user.username
    return render_template('index.html', username=username)




@app.route("/register", methods=['GET', 'POST'])
def register():
    form = RegistrationForm()

    if form.validate_on_submit():
        print(form.username.data)

        # check if username is taken
        if  (db_session.query(User).filter(User.username==form.username.data).first() is not None):
            flash('Ta nazwa użytkownika jest zajęta', 'danger')
            return render_template('register.html', title='Register', form=form)
        else:
            user = User(username=form.username.data, password=form.password.data)
            db_session.add(user)
            try:
                db_session.commit()
                flash('Poprawnie zarejstrowano, możesz się zalogować', 'info')
                return redirect(url_for('login'))
            except exc.SQLAlchemyError as e:
                print(type(e))
                flash('Wystąpił błąd podczas rejestracji konta', 'danger')
                return redirect(url_for('register'))

    return render_template('register.html', title='Register', form=form)

@app.route("/login", methods=['GET', 'POST'])
def login():

     form = LoginForm()

     if form.validate_on_submit():
        # Forget any user_id
        # session.clear()
        user = db_session.query(User).filter(User.username==form.username.data).first()
        # Ensure username exists and password is correct
        if user is None or user.password != form.password.data:
            flash('Niepoprawny login lub hasło!', 'error')
            return render_template('login.html', title='Login', form=form)
        else:
            login_user(user)
            print(current_user.username)
            flash('Jesteś zalogowany', 'success')
            return redirect(url_for('index'))

     return render_template('login.html', title='Login', form=form)



@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))



@app.route('/memes', methods=['GET', 'POST'])
@login_required
def memes():
    memes = db_session.query(Meme).all()


    return render_template('memes.html', title='Memes', memes=memes)



@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    form = MemeForm()
    if form.validate_on_submit():

        pic = form.file.data
        if not pic:
            return 'Nie załączono pliku!', 400
        filename = secure_filename(pic.filename)
        title = form.title.data
        mimetype = pic.mimetype
        if not title or not mimetype:
            return 'Błąd odczytu pliku!', 400

        print(current_user.get_id())

        # create
        img = Meme(img=pic.read(), title=title, filename=filename, mimetype=mimetype, user_id=current_user.get_id())
        db_session.add(img)

        try:
            db_session.commit()
            flash('Mem dodany', 'success')
            return redirect(url_for('index'))
        except exc.SQLAlchemyError as e:
            print(type(e))
            flash('Mem nie został dodany z powodu błędu', 'danger')
            return redirect(url_for('index'))

    return render_template('upload.html', title='Upload', form=form)



@app.route('/edit-meme/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_meme(id):
    form = EditMeme()
    meme = db_session.query(Meme).filter(Meme.id==id).first()
    print(form.title.data)
    id = meme.id

    if (meme and meme.user_id==int(current_user.get_id())): 
        if request.method == 'POST' and form.validate_on_submit():
            # update
            if form.title.data != None:
                title = form.title.data
                db_session.query(Meme).filter_by(id=id).update({"title":title})
            if form.file.data != None:
                filename = secure_filename(form.file.data.filename)
                db_session.query(Meme).filter_by(id=id).update({"filename":filename})
                img = form.file.data.read()
                db_session.query(Meme).filter_by(id=id).update({"img":img})
                mimetype = form.file.data.mimetype
                db_session.query(Meme).filter_by(id=id).update({"mimetype":mimetype})
            
            try:
                db_session.commit()
                flash('Mem edytowany pomyślnie!', 'success')
                return redirect(url_for('user_memes'))
            except exc.SQLAlchemyError as e:
                print(type(e))
                flash('Wystąpił błąd podczas dodawania mema', 'danger')
                return redirect(url_for('user_memes'))
        
        form.title.data = meme.title
        return render_template('edit-meme.html', form=form, id=id)
    else:
        return 'Błąd wczytywania #{id}'.format(id=id)


# https://www.blog.pythonlibrary.org/2017/12/14/flask-101-adding-editing-and-displaying-data/


@app.route('/meme/<int:id>')
@login_required
def meme(id):
    meme = db_session.query(Meme).filter(Meme.id==id).first()
    user_id = int(current_user.get_id())

    return render_template('meme.html', title='Meme', meme=meme, user_id=user_id)



@app.route('/user-memes', methods=['GET', 'POST'])
@login_required
def user_memes():
    memes = db_session.query(Meme).filter(Meme.user_id==current_user.get_id()).all()
    return render_template('user-memes.html', title='Twoje-memy', memes=memes)



@app.route("/delete-meme/<int:id>", methods=['POST'])
@login_required
def delete_meme(id):

    meme = db_session.query(Meme).filter(Meme.id==id).first()

    if (meme and meme.user_id==int(current_user.get_id())):
        try:
            db_session.query(Meme).filter(Meme.id==id).delete()
            db_session.commit()
            flash('Mem usunięty', 'succes')
            return redirect(url_for('user_memes'))
        except exc.SQLAlchemyError as e:
            print(type(e))
            flash('Wystąpił błąd podczas usuwania mema', 'danger')
            return redirect(url_for('user_memes'))


if __name__ == '__main__':
    import os
    HOST = os.environ.get('SERVER_HOST', 'localhost')
    try:
        PORT = int(os.environ.get('SERVER_PORT', '5555'))
    except ValueError:
        PORT = 5555
    app.run(HOST, PORT)
    