from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired
from wtforms.validators import DataRequired, Length, EqualTo, Optional
from wtforms import StringField, PasswordField, SubmitField



class RegistrationForm(FlaskForm):
        username = StringField('Nazwa użytkownika',
                           validators=[DataRequired(), Length(min=2, max=50)])

        password = PasswordField('Hasło', validators=[DataRequired()])

        confirm_password = PasswordField('Potwierdź hasło',
                                     validators=[DataRequired(), EqualTo('password')])

        submit = SubmitField('Zarejstruj się')


class LoginForm(FlaskForm):


    username = StringField('Nazwa użytkownika',
                        validators=[DataRequired()], render_kw={'autofocus': True})
    password = PasswordField('Hasło', validators=[DataRequired()])
    submit = SubmitField('Zaloguj się')


class MemeForm(FlaskForm):
    title = StringField('Tytuł mema',
                        validators=[DataRequired()])
    file = FileField('Obrazek', validators=[FileRequired()])

    submit = SubmitField('Dodaj mem')


class EditMeme(FlaskForm):
    title = StringField('Tytuł mema',
                        validators=[Optional()])
    file = FileField('Obrazek', validators=[Optional()])

    submit = SubmitField('Potwierdź edycję')
